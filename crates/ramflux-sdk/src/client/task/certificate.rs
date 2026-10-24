// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Redacted executor certificates: private grant records and form values never enter group traffic.
use super::{carrier::Carrier, decision::same_decision, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{Task, TaskResolve};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Reserved,
    Committed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub conversation_id: String,
    pub resolution: TaskResolve,
    pub assignee: String,
    pub issuer_device: String,
    pub issued_at: i64,
    pub phase: Phase,
    pub committed_version: Option<u64>,
    pub carrier_hash: Option<String>,
    pub decision_key: String,
    pub evidence_hash: String,
    pub signature: String,
}
impl Certificate {
    pub(super) fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("signature");
        }
        Ok(ramflux_protocol::canonical_json_bytes(&(
            "ramflux.task.decision_certificate.v1",
            value,
        ))?)
    }
    pub(crate) fn encoded(&self) -> Result<String, SdkError> {
        Ok(ramflux_protocol::encode_base64url(serde_json::to_vec(self)?))
    }
    pub(crate) fn decode(encoded: &str) -> Result<Self, SdkError> {
        if encoded.len() > 16 * 1024 {
            return Err(invalid("task certificate byte budget exceeded"));
        }
        let bytes = ramflux_protocol::decode_base64url(encoded)
            .map_err(|_| invalid("invalid task certificate encoding"))?;
        Ok(ramflux_protocol::parse_i_json(&bytes)?)
    }
}
pub(crate) fn carrier_hash(c: &Carrier) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url("ramflux.task.committed_intent.v1", &c.bytes()?))
}
pub(super) fn committed_key(c: &Carrier, assignee: &str, issuer: &str) -> Result<String, SdkError> {
    Ok(key("committed_decision", &serde_json::to_string(&(assignee, issuer, carrier_hash(c)?))?))
}
impl RamfluxClient {
    pub(super) fn sign_task_certificate(
        &self,
        mut certificate: Certificate,
    ) -> Result<Certificate, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if device.device_id != certificate.issuer_device
            || device.principal_id != certificate.assignee
        {
            return Err(invalid("task certificate must be signed by its executor"));
        }
        certificate.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &certificate.signing_bytes()?,
            device,
        );
        Ok(certificate)
    }
    pub(super) fn check_task_certificate_signature(
        &self,
        certificate: &Certificate,
    ) -> Result<(), SdkError> {
        let public = self.task_signer_key(&certificate.assignee, &certificate.issuer_device)?;
        ramflux_crypto::verify_canonical_signature(
            &certificate.signing_bytes()?,
            &certificate.signature,
            &public,
        )?;
        Ok(())
    }
    pub(super) fn check_committed_task_certificate(
        &self,
        c: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
        certificate: &Certificate,
    ) -> Result<(), SdkError> {
        self.check_task_certificate_at(c, task, resolution, certificate, false)
    }
    pub(super) fn check_historical_task_certificate(
        &self,
        c: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
        certificate: &Certificate,
    ) -> Result<(), SdkError> {
        self.check_task_certificate_at(c, task, resolution, certificate, true)
    }
    fn check_task_certificate_at(
        &self,
        c: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
        certificate: &Certificate,
        historical: bool,
    ) -> Result<(), SdkError> {
        let (executor, opened) = self
            .task_history(&task.conversation_id, &task.task_id)?
            .intervention_source(&resolution.step_id, &resolution.target)?;
        if certificate.phase != Phase::Committed
            || certificate.assignee != task.assignee
            || certificate.issuer_device != executor
            || certificate.conversation_id != task.conversation_id
            || !same_decision(&certificate.resolution, resolution)
            || certificate.resolution.base_revision < opened
            || resolution.base_revision < opened
            || certificate.committed_version != task.version.checked_add(1)
            || certificate.carrier_hash.as_deref() != Some(carrier_hash(c)?.as_str())
        {
            return Err(invalid(
                "task commit certificate does not match the current intervention and revision",
            ));
        }
        let expected = match &resolution.target {
            ramflux_protocol::NeedsMe::Approval { grant_id } => {
                super::decision::key_for_decision("grant", &(&task.assignee, grant_id))?
            }
            ramflux_protocol::NeedsMe::Choice { surface_id }
            | ramflux_protocol::NeedsMe::Input { surface_id } => super::decision::key_for_decision(
                "surface",
                &(&task.conversation_id, &task.assignee, surface_id, &resolution.decision_id),
            )?,
        };
        if certificate.decision_key != expected {
            return Err(invalid("task certificate external decision identity mismatch"));
        }
        if !historical {
            self.require_task_member(&task.conversation_id, &task.assignee, Some(&executor))?;
        }
        self.check_task_certificate_signature(certificate)
    }
    pub(super) fn save_task_commit_certificate(
        &self,
        c: &Carrier,
        certificate: &Certificate,
    ) -> Result<(), SdkError> {
        self.check_task_certificate_signature(certificate)?;
        if certificate.phase != Phase::Committed
            || certificate.carrier_hash.as_deref() != Some(carrier_hash(c)?.as_str())
            || certificate.conversation_id != c.conversation_id
        {
            return Err(invalid("task commit certificate carrier mismatch"));
        }
        self.account_db()?.prune_task_certificates(crate::time::now_unix_timestamp())?;
        let key = committed_key(c, &certificate.assignee, &certificate.issuer_device)?;
        if let Some(old) = self.account_db()?.load_actor_state::<Certificate>(&key)? {
            if old.encoded()? != certificate.encoded()? {
                return Err(invalid("task commit certificate collision"));
            }
        } else {
            let history = self.task_history(&c.conversation_id, c.event()?.event().task_id())?;
            if history
                .events
                .iter()
                .filter_map(|e| e.decision_certificate.as_ref())
                .any(|old| old.encoded().ok() == certificate.encoded().ok())
            {
                return Ok(());
            }
            let state = history.state()?;
            let task =
                state.task().ok_or_else(|| invalid("task certificate has no current task"))?;
            self.check_committed_task_certificate(c, task, &certificate.resolution, certificate)?;
            let now = crate::time::now_unix_timestamp();
            if certificate.issued_at > now.saturating_add(300)
                || certificate.issued_at < now.saturating_sub(7 * 24 * 60 * 60)
            {
                return Err(invalid("task certificate is outside the live retention window"));
            }
            self.account_db()?.persist_actor_state(&key, certificate)?;
            self.account_db()?.prune_task_certificates(crate::time::now_unix_timestamp())?;
        }
        Ok(())
    }
}
