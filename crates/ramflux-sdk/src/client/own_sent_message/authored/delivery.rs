// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-incarnation Sent attestations; a prepared plan is rechecked inside the writer.
use super::super::authored::{CAPTURE, Captured};
use crate::client::generated_control::control_from_payload;
use crate::client::identity_authority::NativeOperation;
use crate::client::routed::{Route, SendMaterial, SendMaterialRequest};
use crate::{GatewayDirectMessage, GatewaySessionConfig, RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};

const PENDING: &str = "own-history/pending/";

#[derive(Deserialize, Serialize)]
struct Work {
    source: g::QualifiedDevice,
    target: g::QualifiedDevice,
    target_certificate: String,
    owner: String,
    capture_hash: String,
    staging_id: String,
    envelope: Option<ramflux_protocol::Envelope>,
    next_at: i64,
    attempts: u32,
}

pub(crate) struct Plan {
    key: String,
    fingerprint: String,
    pub(crate) request: SendMaterialRequest,
    pub(crate) envelope: Option<ramflux_protocol::Envelope>,
}

fn fingerprint<T: Serialize>(value: &T) -> Result<String, SdkError> {
    let bytes = zeroize::Zeroizing::new(ramflux_protocol::canonical_json_bytes(value)?);
    Ok(ramflux_protocol::encode_base64url(blake3::hash(&bytes).as_bytes()))
}

impl RamfluxClient {
    fn authored_incarnation(
        &self,
        device: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(g::QualifiedDevice, String), SdkError> {
        self.require_native_operation(device, NativeOperation::Sync)?;
        let now = crate::custody::network_now()?;
        let authority = self
            .current_custody_authority(device.root_commitment(), now)?
            .ok_or(SdkError::NetworkingPending)?;
        let entry = authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == device.device_id())
            .ok_or_else(|| SdkError::InboundPending("own history target absent".into()))?;
        let reference = ramflux_protocol::custody::DeviceRef {
            account_anchor: device.root_commitment().into(),
            device_id: device.device_id().into(),
            device_epoch: entry.device_epoch,
        };
        authority.authorize(&reference, "sync", now)?;
        Ok((
            g::QualifiedDevice {
                account_anchor: reference.account_anchor,
                device_id: reference.device_id,
                device_epoch: reference.device_epoch,
            },
            fingerprint(&entry.branch_certificate)?,
        ))
    }

    pub(crate) fn stage_authored_history(&self) -> Result<(), SdkError> {
        let local = self.owned_device_identity()?;
        let Some(authority) = self
            .current_custody_authority(local.root_commitment(), crate::custody::network_now()?)?
        else {
            return Ok(());
        };
        let (source, _) = self.authored_incarnation(&local)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            for entry in &authority.envelope().body.devices {
                if entry.device_id == local.device_id() {
                    continue;
                }
                let target = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(
                    &authority,
                    &entry.device_id,
                )?;
                let Ok((target, target_certificate)) = self.authored_incarnation(&target) else {
                    continue;
                };
                for key in db.actor_state_keys(CAPTURE)? {
                    let Some(capture) = db.load_actor_state::<Captured>(&key)? else { continue };
                    let owner = ramflux_protocol::encode_base64url(&capture.target);
                    if db.message_is_deleted(&owner)? {
                        continue;
                    }
                    let tuple =
                        (&source, &target, &target_certificate, &capture.target, &capture.current);
                    let binding = format!("own-history/staged/{}", fingerprint(&tuple)?);
                    if db.actor_state_exists(&binding)? {
                        continue;
                    }
                    let staging_id =
                        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
                    let work = Work {
                        source: source.clone(),
                        target: target.clone(),
                        target_certificate: target_certificate.clone(),
                        owner: owner.clone(),
                        capture_hash: fingerprint(&capture)?,
                        staging_id: staging_id.clone(),
                        envelope: None,
                        next_at: 0,
                        attempts: 0,
                    };
                    let pending = format!("{PENDING}{staging_id}");
                    let (count, bytes) = db.actor_state_usage(PENDING)?;
                    if count >= 256
                        || bytes.saturating_add(
                            ramflux_protocol::canonical_json_bytes(&work)?.len() as u64,
                        ) > 8 * 1024 * 1024
                    {
                        return Err(SdkError::InboundPending(
                            "own history staging capacity".into(),
                        ));
                    }
                    db.persist_message_actor_state(&owner, &binding, &staging_id)?;
                    db.persist_message_actor_state(&owner, &pending, &work)?;
                }
            }
            Ok(())
        })
    }

    pub(super) fn retire_authored_history_for_owner(&self, owner: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        for key in db.actor_state_keys(PENDING)? {
            if db.load_actor_state::<Work>(&key)?.is_some_and(|work| work.owner == owner) {
                db.remove_actor_state(&key)?;
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_authored_history(
        &self,
        config: &GatewaySessionConfig,
    ) -> Result<Option<Plan>, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(None);
        }
        self.require_backup_outbound_ready()?;
        self.stage_authored_history()?;
        let db = self.account_db()?;
        for key in db.actor_state_keys(PENDING)? {
            let Some(mut work) = db.load_actor_state::<Work>(&key)? else { continue };
            if !self.authored_work_current(&work)? {
                db.remove_actor_state(&key)?;
                continue;
            }
            let now = crate::time::now_unix_timestamp();
            if work.next_at > now {
                continue;
            }
            let message = self.authored_history_message(config, &work)?;
            let request = if work.envelope.is_some() {
                SendMaterialRequest { root: None, prekey: None }
            } else {
                self.routed_send_material_request(config, &message)?
            };
            work.attempts = work.attempts.saturating_add(1);
            work.next_at = now.saturating_add((1_i64 << work.attempts.min(6)).min(60));
            db.persist_message_actor_state(&work.owner, &key, &work)?;
            return Ok(Some(Plan {
                fingerprint: fingerprint(&work)?,
                envelope: work.envelope.clone(),
                key,
                request,
            }));
        }
        Ok(None)
    }

    fn authored_work_current(&self, work: &Work) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        if db.message_is_deleted(&work.owner)? {
            return Ok(false);
        }
        let Some(capture) = db.load_actor_state::<Captured>(&format!("{CAPTURE}{}", work.owner))?
        else {
            return Ok(false);
        };
        if fingerprint(&capture)? != work.capture_hash {
            return Ok(false);
        }
        let local = self.owned_device_identity()?;
        if self.authored_incarnation(&local)?.0 != work.source {
            return Ok(false);
        }
        let Ok(target) =
            self.device_identity_for_root(&work.target.account_anchor, &work.target.device_id)
        else {
            return Ok(false);
        };
        let Ok((current, certificate)) = self.authored_incarnation(&target) else {
            return Ok(false);
        };
        Ok(current == work.target && certificate == work.target_certificate)
    }

    fn authored_history_message(
        &self,
        config: &GatewaySessionConfig,
        work: &Work,
    ) -> Result<GatewayDirectMessage, SdkError> {
        let capture = self
            .account_db()?
            .load_actor_state::<Captured>(&format!("{CAPTURE}{}", work.owner))?
            .ok_or_else(|| SdkError::InboundPending("own history capture erased".into()))?;
        let target =
            self.device_identity_for_root(&work.target.account_anchor, &work.target.device_id)?;
        let record = self.account_db()?.client_device_record(&target)?.ok_or_else(|| {
            SdkError::InboundPending("own history target directory missing".into())
        })?;
        Ok(GatewayDirectMessage {
            conversation_id: capture
                .sent
                .context
                .ok_or_else(|| SdkError::InboundRejected("own history context missing".into()))?
                .conversation_id,
            message_id: work.staging_id.clone(),
            envelope_id: work.staging_id.clone(),
            source_principal_id: config.principal_id.clone(),
            sender_id: config.device_id.clone(),
            recipient_device_id: Some(target.storage_key().into()),
            recipient_principal_commitment: Some(work.target.account_anchor.clone()),
            target_delivery_id: record["target_delivery_id"]
                .as_str()
                .ok_or(SdkError::NetworkingPending)?
                .into(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: self.content_ttl()?,
        })
    }

    pub(crate) fn seal_authored_history(
        &self,
        config: &GatewaySessionConfig,
        mut plan: Plan,
        material: SendMaterial,
    ) -> Result<Option<(Plan, ramflux_protocol::Envelope)>, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let Some(mut work) = db.load_actor_state::<Work>(&plan.key)? else { return Ok(None) };
            if fingerprint(&work)? != plan.fingerprint || !self.authored_work_current(&work)? {
                return Ok(None);
            }
            if let Some(envelope) = work.envelope {
                return Ok(Some((plan, envelope)));
            }
            let capture = db
                .load_actor_state::<Captured>(&format!("{CAPTURE}{}", work.owner))?
                .ok_or_else(|| SdkError::InboundPending("own history capture erased".into()))?;
            let mut message = self.authored_history_message(config, &work)?;
            let identity = self.allocate_generated_identity(
                &message.conversation_id,
                crate::client::generated_identity::now_ms(),
                true,
            )?;
            let control =
                control_from_payload(g::control::Payload::OwnMessageCopy(g::OwnMessageCopy {
                    source: Some(work.source.clone()),
                    target: Some(work.target.clone()),
                    created_at: message.created_at,
                    expires_at: message.created_at.saturating_add(i64::from(message.ttl)),
                    payload: Some(g::own_message_copy::Payload::Sent(capture.sent)),
                }))?;
            let exact = zeroize::Zeroizing::new(Self::encode_generated_inner(
                identity,
                &g::Content { value: Some(g::content::Value::Control(control)) },
            )?);
            let sealed =
                self.seal_routed_prepared(config, &message, &exact, Route::control(), material)?;
            let envelope =
                crate::dm::gateway_envelope_from_sealed(config, &mut message, sealed, None)?;
            work.envelope = Some(envelope.clone());
            let (_, used) = db.actor_state_usage(PENDING)?;
            let old = db
                .load_actor_state::<serde_json::Value>(&plan.key)?
                .ok_or(SdkError::ReplayMismatch)?;
            let required = ramflux_protocol::canonical_json_bytes(&work)?.len() as u64;
            if used
                .saturating_sub(ramflux_protocol::canonical_json_bytes(&old)?.len() as u64)
                .saturating_add(required)
                > 8 * 1024 * 1024
            {
                return Err(SdkError::InboundPending("own history sealed staging capacity".into()));
            }
            db.persist_message_actor_state(&work.owner, &plan.key, &work)?;
            plan.fingerprint = fingerprint(&work)?;
            plan.envelope = Some(envelope.clone());
            Ok(Some((plan, envelope)))
        })
    }

    pub(crate) fn complete_authored_history(&self, plan: &Plan) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            if let Some(work) = db.load_actor_state::<Work>(&plan.key)?
                && fingerprint(&work)? == plan.fingerprint
                && self.authored_work_current(&work)?
            {
                db.remove_actor_state(&plan.key)?;
            }
            Ok(())
        })
    }
}
