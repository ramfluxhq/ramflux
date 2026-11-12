// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conditional private-register courier plans; the writer owns every ratchet/store change.
use super::{RamfluxClient, Reference, SdkError, State, g, refresh::Generation, refused};
use crate::client::{
    identity_authority::NativeOperation,
    routed::{Route, SendMaterial, SendMaterialRequest},
};
use crate::{GatewayDirectMessage, GatewaySessionConfig};
use prost::Message as _;
use ramflux_crypto::RootQualifiedDeviceRef;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Repair {
    conversation_id: String,
    scope: String,
    target: String,
    target_epoch: u64,
    target_certificate: Option<String>,
    exact_body: Zeroizing<Vec<u8>>,
    read_marker_body: Option<Zeroizing<Vec<u8>>>,
    references: Vec<Reference>,
}
#[derive(Deserialize, Serialize)]
struct Pending {
    conversation_id: String,
    scope: String,
    source_epoch: u64,
    envelope: Option<ramflux_protocol::Envelope>,
    submitted: bool,
    references: Vec<Reference>,
    // Roster generation the envelope was sealed under; never reused across a refresh.
    #[serde(default)]
    refresh: Option<Generation>,
}

pub(crate) struct Plan {
    key: String,
    fingerprint: [u8; 32],
    pending: String,
    target: RootQualifiedDeviceRef,
    target_epoch: u64,
    target_certificate: Option<String>,
    generation: Option<Generation>,
    value: Zeroizing<Vec<u8>>,
    pub(crate) message: GatewayDirectMessage,
    pub(crate) request: SendMaterialRequest,
    pub(crate) envelope: Option<ramflux_protocol::Envelope>,
}

impl RamfluxClient {
    pub(crate) fn prepare_self_sync_repair(
        &self,
        config: &GatewaySessionConfig,
    ) -> Result<Option<Plan>, SdkError> {
        if !crate::client::target_selection::schema_v1_selected() {
            return Ok(None);
        }
        // A restored archive never sends before its fresh activation completes.
        if self.require_backup_outbound_ready().is_err() {
            return Ok(None);
        }
        // Cross the refresh barrier first: a new roster or local incarnation retires
        // what was sealed or queued for the previous one before anything is staged.
        let generation = match self.enter_self_sync_refresh() {
            Ok(generation) => generation,
            Err(SdkError::InboundPending(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.stage_native_self_sync_publications()?;
        let db = self.account_db()?;
        for key in db.actor_state_keys("self-sync/repair/")? {
            let encoded = db
                .load_actor_state::<serde_json::Value>(&key)?
                .ok_or_else(|| refused("repair disappeared"))?;
            let repair: Repair = serde_json::from_value(encoded.clone())?;
            // Restore merges replace registers below the SDK. A queued body that is no
            // longer the committed register, or that names a target failing reference
            // authentication, is retired instead of being sent or blocking the courier.
            if !self.self_sync_repair_matches_register(&repair)?
                || !self.self_sync_repair_references_authentic(&repair)?
            {
                self.retire_self_sync_repair(&key)?;
                continue;
            }
            let target = match self.device_identity(&repair.target) {
                Ok(target) => target,
                // A device removed from the verified roster is a retired target.
                Err(SdkError::Crypto(_)) => {
                    self.retire_self_sync_repair(&key)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !self.self_sync_target_admitted(&target, repair.target_epoch)?
                || self.self_sync_target_certificate(&target)? != repair.target_certificate
            {
                self.retire_self_sync_repair(&key)?;
                continue;
            }
            self.authorize_self_sync(&target, &repair.conversation_id)?;
            if self.self_sync_target_epoch(&target)? != repair.target_epoch {
                self.retire_self_sync_repair(&key)?;
                continue;
            }
            for (slot, body) in
                [("register", Some(&repair.exact_body)), ("read", repair.read_marker_body.as_ref())]
            {
                let Some(body) = body else { continue };
                if slot == "read" && body.as_slice() == repair.exact_body.as_slice() {
                    continue;
                }
                let pending = format!(
                    "{}/{slot}",
                    key.replacen("self-sync/repair/", "self-sync/pending/", 1)
                );
                let cached = db.load_actor_state::<Pending>(&pending)?;
                let epoch =
                    self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch;
                let cached = cached
                    .filter(|cached| cached.source_epoch == epoch && cached.refresh == generation);
                if cached.as_ref().is_some_and(|cached| cached.submitted) {
                    continue;
                }
                let envelope = cached.and_then(|cached| cached.envelope);
                let message = GatewayDirectMessage {
                    conversation_id: repair.conversation_id.clone(),
                    message_id: String::new(),
                    envelope_id: crate::new_surface_message_id()?,
                    source_principal_id: config.principal_id.clone(),
                    sender_id: config.device_id.clone(),
                    recipient_device_id: Some(target.device_id().into()),
                    recipient_principal_commitment: Some(target.root_commitment().into()),
                    target_delivery_id: target.storage_key().into(),
                    encrypted_body: Vec::new(),
                    created_at: crate::time::now_unix_timestamp(),
                    ttl: self.content_ttl()?,
                };
                let request = self.routed_send_material_request(config, &message)?;
                return Ok(Some(Plan {
                    key,
                    fingerprint: *blake3::hash(&ramflux_protocol::canonical_json_bytes(&encoded)?)
                        .as_bytes(),
                    pending,
                    target,
                    target_epoch: repair.target_epoch,
                    target_certificate: repair.target_certificate.clone(),
                    generation,
                    value: body.clone(),
                    message,
                    request,
                    envelope,
                }));
            }
            self.retire_self_sync_repair(&key)?;
        }
        Ok(None)
    }

    fn self_sync_repair_matches_register(&self, repair: &Repair) -> Result<bool, SdkError> {
        let Some(state) = self.account_db()?.load_actor_state::<State>(&repair.scope)? else {
            return Ok(false);
        };
        Ok(state.conversation_id == repair.conversation_id
            && state.exact_body.as_slice() == repair.exact_body.as_slice()
            && state.read_marker_body.as_ref().map(|body| body.exact_body.as_slice())
                == repair.read_marker_body.as_ref().map(|body| body.as_slice()))
    }

    // The receiver verifies references again; the sender never forwards a register whose
    // reference is known locally to name another conversation, author root or identity.
    fn self_sync_repair_references_authentic(&self, repair: &Repair) -> Result<bool, SdkError> {
        for body in
            [Some(&repair.exact_body), repair.read_marker_body.as_ref()].into_iter().flatten()
        {
            let value = g::self_sync::decode_stored_body(body)
                .map_err(|_| refused("repair value malformed"))?;
            match self.self_sync_references(&repair.conversation_id, &value, true) {
                Ok(_) => {}
                Err(SdkError::InboundRejected(_)) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }

    fn retire_self_sync_repair(&self, key: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let prefix = format!("{}/", key.replacen("self-sync/repair/", "self-sync/pending/", 1));
            for pending in db.actor_state_keys(&prefix)? {
                db.retire_self_sync_actor(&pending)?;
            }
            db.retire_self_sync_actor(key)?;
            Ok(())
        })
    }

    pub(super) fn self_sync_target_epoch(
        &self,
        target: &RootQualifiedDeviceRef,
    ) -> Result<u64, SdkError> {
        if let Some(authority) = self
            .current_custody_authority(target.root_commitment(), crate::custody::network_now()?)?
        {
            return authority
                .envelope()
                .body
                .devices
                .iter()
                .find(|entry| entry.device_id == target.device_id())
                .map(|entry| entry.device_epoch)
                .ok_or_else(|| refused("repair target epoch missing"));
        }
        if target == &self.owned_device_identity()? {
            return self
                .device_branch
                .as_ref()
                .map(|branch| branch.device_epoch)
                .ok_or(SdkError::IdentityRootMissing);
        }
        self.account_db()?
            .client_device_record(target)?
            .and_then(|record| record["device_epoch"].as_u64())
            .ok_or_else(|| refused("repair target epoch missing"))
    }

    pub(super) fn self_sync_target_certificate(
        &self,
        target: &RootQualifiedDeviceRef,
    ) -> Result<Option<String>, SdkError> {
        let Some(authority) = self
            .current_custody_authority(target.root_commitment(), crate::custody::network_now()?)?
        else {
            return Ok(None);
        };
        authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == target.device_id())
            .and_then(|entry| entry.branch_certificate.as_ref())
            .map(ramflux_protocol::custody::object_hash)
            .transpose()
            .map_err(SdkError::from)
    }

    fn self_sync_target_admitted(
        &self,
        target: &RootQualifiedDeviceRef,
        epoch: u64,
    ) -> Result<bool, SdkError> {
        let now = crate::custody::network_now()?;
        let Some(authority) = self.current_custody_authority(target.root_commitment(), now)? else {
            return Ok(true);
        };
        Ok(authority
            .authorize(
                &ramflux_protocol::custody::DeviceRef {
                    account_anchor: target.root_commitment().into(),
                    device_id: target.device_id().into(),
                    device_epoch: epoch,
                },
                "sync",
                now,
            )
            .is_ok())
    }

    fn self_sync_repair_current(&self, plan: &Plan) -> Result<bool, SdkError> {
        let Some(row) = self.account_db()?.load_actor_state::<serde_json::Value>(&plan.key)? else {
            return Ok(false);
        };
        if *blake3::hash(&ramflux_protocol::canonical_json_bytes(&row)?).as_bytes()
            != plan.fingerprint
        {
            return Ok(false);
        }
        // The plan was prepared under one roster generation and commits only under it.
        if self.self_sync_refresh_generation()? != plan.generation {
            return Ok(false);
        }
        let repair: Repair = serde_json::from_value(row)?;
        if !self.self_sync_repair_matches_register(&repair)?
            || !self.self_sync_repair_references_authentic(&repair)?
        {
            return Ok(false);
        }
        if !self.self_sync_target_admitted(&plan.target, plan.target_epoch)?
            || self.self_sync_target_certificate(&plan.target)? != plan.target_certificate
        {
            return Ok(false);
        }
        self.authorize_self_sync(&plan.target, &plan.message.conversation_id)?;
        Ok(self.self_sync_target_epoch(&plan.target)? == plan.target_epoch)
    }

    pub(crate) fn seal_self_sync_repair(
        &self,
        config: &GatewaySessionConfig,
        mut plan: Plan,
        material: SendMaterial,
    ) -> Result<Option<(Plan, ramflux_protocol::Envelope)>, SdkError> {
        Self::require_self_sync_floor_bootstrap()?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            if !self.self_sync_repair_current(&plan)? {
                return Ok(None);
            }
            if let Some(envelope) = plan.envelope.take() {
                return Ok(Some((plan, envelope)));
            }
            let value = g::self_sync::decode_stored_body(&plan.value)
                .map_err(|_| refused("repair value malformed"))?;
            let inner = Zeroizing::new(
                self.self_sync_publication_inner(&plan.message.conversation_id, &value)?,
            );
            let identity = g::Inner::decode(inner.as_slice())
                .map_err(|_| refused("repair identity missing"))?
                .identity
                .ok_or_else(|| refused("repair identity missing"))?;
            plan.message.message_id = ramflux_protocol::encode_base64url(&identity.id);
            self.require_native_operation(&plan.target, NativeOperation::Sync)?;
            let sealed = self.seal_routed_prepared(
                config,
                &plan.message,
                &inner,
                Route::control(),
                material,
            )?;
            let envelope =
                crate::dm::gateway_envelope_from_sealed(config, &mut plan.message, sealed, None)?;
            let repair: Repair =
                db.load_actor_state(&plan.key)?.ok_or_else(|| refused("repair disappeared"))?;
            let pending = Pending {
                conversation_id: repair.conversation_id,
                scope: repair.scope,
                source_epoch: self
                    .device_branch
                    .as_ref()
                    .ok_or(SdkError::IdentityRootMissing)?
                    .device_epoch,
                envelope: Some(envelope.clone()),
                submitted: false,
                references: repair.references,
                refresh: plan.generation.clone(),
            };
            if db.actor_state_exists(&plan.pending)? {
                db.retire_self_sync_actor(&plan.pending)?;
            }
            self.persist_self_sync_owned_state(
                &plan.pending,
                &serde_json::to_value(&pending)?,
                &pending.references,
            )?;
            Ok(Some((plan, envelope)))
        })
    }

    pub(crate) fn complete_self_sync_repair(&self, plan: &Plan) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            if !self.self_sync_repair_current(plan)? {
                return Ok(());
            }
            let Some(mut pending) = db.load_actor_state::<Pending>(&plan.pending)? else {
                return Ok(());
            };
            pending.envelope = None;
            pending.submitted = true;
            db.retire_self_sync_actor(&plan.pending)?;
            self.persist_self_sync_owned_state(
                &plan.pending,
                &serde_json::to_value(&pending)?,
                &pending.references,
            )
        })
    }
}
