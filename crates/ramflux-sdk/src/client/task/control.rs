// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Requester intents and executor acknowledgements inside authenticated pair controls.
use super::{Delivery, carrier::Carrier, certificate::Certificate, invalid, key};
use crate::prekey::SdkDeviceManifestResponse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub(crate) const PREFIX: &[u8] = b"ramflux.task.control.v1\n";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ack {
    pub carrier_base64: String,
    pub certificate: Certificate,
    pub manifests: Vec<SdkDeviceManifestResponse>,
    pub signer_principal: String,
    pub signer_device: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Control {
    Intent { carrier_base64: String },
    Ack(Box<Ack>),
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AckJob {
    pub ack: Ack,
    pub attempts: u32,
    pub next_at: i64,
    pub created_at: i64,
}
impl Control {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(invalid("task control byte budget exceeded"));
        }
        Ok(bytes)
    }
}
impl Ack {
    fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            "ramflux.task.decision_ack.v1",
            &self.carrier_base64,
            &self.certificate,
            &self.manifests,
            &self.signer_principal,
            &self.signer_device,
        ))?)
    }
    pub(crate) fn original(&self) -> Result<Carrier, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&self.carrier_base64)
            .map_err(|_| invalid("invalid task acknowledgement carrier"))?;
        Carrier::decode(&bytes)?.ok_or_else(|| invalid("task acknowledgement carrier missing"))
    }
}
impl RamfluxClient {
    pub(super) fn queue_task_decision_ack(
        &self,
        c: &Carrier,
        certificate: &Certificate,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if local.principal_id != certificate.assignee
            || local.device_id != certificate.issuer_device
        {
            return Ok(());
        }
        let fingerprint = super::certificate::carrier_hash(c)?;
        let id = key("ack", &fingerprint);
        if self
            .account_db()?
            .load_actor_state::<serde_json::Value>(&key("ack_sent", &fingerprint))?
            .is_some_and(|v| {
                v["start"]
                    .as_i64()
                    .is_some_and(|last| crate::time::now_unix_timestamp().saturating_sub(last) < 60)
            })
        {
            return Ok(());
        }
        if self.account_db()?.load_actor_state::<AckJob>(&id)?.is_some() {
            return Ok(());
        }
        let mut manifests = Vec::new();
        if c.principal_id != local.principal_id
            && let Some(manifest) =
                self.account_db()?.load_actor_state::<SdkDeviceManifestResponse>(&format!(
                    "identity/manifest/{}",
                    c.principal_id
                ))?
        {
            manifests.push(manifest);
        }
        let mut ack = Ack {
            carrier_base64: ramflux_protocol::encode_base64url(c.bytes()?),
            certificate: certificate.clone(),
            manifests,
            signer_principal: local.principal_id.clone(),
            signer_device: local.device_id.clone(),
            signature: String::new(),
        };
        ack.signature =
            ramflux_crypto::sign_canonical_bytes_with_device_branch(&ack.signing_bytes()?, local);
        let (count, bytes) = self.account_db()?.task_state_usage("task/ack/")?;
        if count >= 64
            || bytes
                .saturating_add(u64::try_from(serde_json::to_vec(&ack)?.len()).unwrap_or(u64::MAX))
                > 8 * 1024 * 1024
        {
            return Err(SdkError::InboundPending("task acknowledgement queue is full".into()));
        }
        self.account_db()?.persist_actor_state(
            &id,
            &AckJob { ack, attempts: 0, next_at: 0, created_at: crate::time::now_unix_timestamp() },
        )?;
        Ok(())
    }
    pub(crate) fn receive_task_control(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else { return Ok(false) };
        if body.len() > 2 * 1024 * 1024 {
            return Err(invalid("task control byte budget exceeded"));
        }
        self.require_task_member(
            conversation,
            &entry.envelope.source_principal_id,
            Some(&entry.envelope.source_device_id),
        )?;
        let thread = self
            .account_db()?
            .client_record("conversation", conversation)?
            .ok_or_else(|| invalid("task control conversation missing"))?;
        if thread["group_id"].as_str() != group {
            return Err(invalid("task control group context mismatch"));
        }
        let control: Control = ramflux_protocol::parse_i_json(raw)?;
        self.account_db()?.write_transaction(|| {
            match control {
                Control::Intent { carrier_base64 } => {
                    let bytes = ramflux_protocol::decode_base64url(&carrier_base64)
                        .map_err(|_| invalid("invalid task intent encoding"))?;
                    let c = Carrier::decode(&bytes)?
                        .ok_or_else(|| invalid("task intent carrier missing"))?;
                    if c.conversation_id != conversation
                        || c.principal_id != entry.envelope.source_principal_id
                        || c.device_id != entry.envelope.source_device_id
                        || !matches!(
                            c.event()?.event(),
                            ramflux_protocol::TaskEventBody::Resolve(_)
                        )
                    {
                        return Err(invalid("task intent source or context mismatch"));
                    }
                    self.project_task_control_carrier(&c)?;
                }
                Control::Ack(ack) => {
                    if ack.signer_principal != entry.envelope.source_principal_id
                        || ack.signer_device != entry.envelope.source_device_id
                        || ack.certificate.assignee != ack.signer_principal
                        || ack.certificate.issuer_device != ack.signer_device
                    {
                        return Err(invalid("task acknowledgement source mismatch"));
                    }
                    let public = self.task_signer_key(&ack.signer_principal, &ack.signer_device)?;
                    ramflux_crypto::verify_canonical_signature(
                        &ack.signing_bytes()?,
                        &ack.signature,
                        &public,
                    )?;
                    let c = ack.original()?;
                    if c.conversation_id != conversation {
                        return Err(invalid("task acknowledgement conversation mismatch"));
                    }
                    self.import_task_ack_manifests(&c, &ack.manifests)?;
                    let original_public = self.task_signer_key(&c.principal_id, &c.device_id)?;
                    c.verify(&original_public)?;
                    self.save_task_commit_certificate(&c, &ack.certificate)?;
                    self.project_task_control_carrier(&c)?;
                }
            }
            Ok::<_, SdkError>(true)
        })
    }
    fn import_task_ack_manifests(
        &self,
        c: &Carrier,
        manifests: &[SdkDeviceManifestResponse],
    ) -> Result<(), SdkError> {
        if manifests.len() > 1 {
            return Err(invalid("task acknowledgement manifest count exceeded"));
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        for manifest in manifests {
            if manifest.principal_id != c.principal_id {
                return Err(invalid("task acknowledgement manifest principal mismatch"));
            }
            let commitment = if manifest.principal_id == local.principal_id {
                self.surface_local_root_commitment()?
            } else {
                self.account_db()?
                    .client_record("identity", &manifest.principal_id)?
                    .and_then(|v| v["contact_identity_commitment"].as_str().map(str::to_owned))
                    .ok_or_else(|| {
                        invalid("task acknowledgement has no trusted principal commitment")
                    })?
            };
            crate::client::contact::verify_device_manifest(manifest, &commitment)?;
            self.persist_identity_directory(manifest)?;
        }
        Ok(())
    }
    pub(super) fn project_task_control_carrier(&self, c: &Carrier) -> Result<(), SdkError> {
        let pending = self
            .account_db()?
            .load_actor_state::<super::pending::Pending>(&super::pending::pending_key(c)?)?;
        let timeline =
            pending.as_ref().map_or_else(|| super::timeline_id(c), |p| Ok(p.message.clone()))?;
        let at = pending.as_ref().map_or_else(crate::time::now_unix_timestamp, |p| p.at);
        let outcome = self
            .project_task_message(
                &Delivery {
                    conversation: &c.conversation_id,
                    message: &timeline,
                    principal: &c.principal_id,
                    device: &c.device_id,
                    at,
                },
                &c.bytes()?,
            )?
            .ok_or_else(|| invalid("task control projection missing"))?;
        if self.direct_message_by_id(&timeline)?.is_none() {
            self.send_direct_message(&c.conversation_id, &timeline, &c.device_id, &[])?;
        }
        self.account_db()?.replace_surface_message_content(
            &c.conversation_id,
            &timeline,
            outcome.fallback_text.as_bytes(),
        )?;
        if !outcome.accepted && !outcome.pending {
            self.account_db()?.append_journal(&format!("task-decision-rejected:{}",super::certificate::carrier_hash(c)?),"task.changed",&json!({"conversation_id":c.conversation_id,"task_id":c.event()?.event().task_id(),"decision_rejected":true,"actor_kind_verified":false}),crate::time::now_unix_timestamp(),None)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ForwardJob {
    pub conversation_id: String,
    pub task_id: String,
    pub attempts: u32,
    pub next_at: i64,
    pub created_at: i64,
}
impl RamfluxClient {
    pub(super) fn queue_task_owned_forward(
        &self,
        conversation: &str,
        task: &str,
        principal: &str,
        device: &str,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if local.principal_id == principal && local.device_id == device {
            return Ok(());
        }
        let id = super::scoped("forward", conversation, task)?;
        if self.account_db()?.load_actor_state::<ForwardJob>(&id)?.is_none() {
            let (count, _) = self.account_db()?.task_state_usage("task/forward/")?;
            if count >= 64 {
                return Err(SdkError::InboundPending(
                    "task own-device forward queue is full".into(),
                ));
            }
            self.account_db()?.persist_actor_state(
                &id,
                &ForwardJob {
                    conversation_id: conversation.into(),
                    task_id: task.into(),
                    attempts: 0,
                    next_at: 0,
                    created_at: crate::time::now_unix_timestamp(),
                },
            )?;
        }
        Ok(())
    }
}
