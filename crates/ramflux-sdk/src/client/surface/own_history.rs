// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded surface proofs in the existing authenticated own-device history snapshot.
use super::{Carrier, ControlKind, SurfaceControl, invalid, key};
use crate::own_device_sync::SdkOwnDeviceSyncEnvelope;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde_json::Value;
impl RamfluxClient {
    pub(crate) fn surface_message_group_epoch(
        &self,
        message: &str,
    ) -> Result<Option<(String, u64)>, SdkError> {
        let Some(binding) =
            self.account_db()?.load_actor_state::<Value>(&key("message", message))?
        else {
            return Ok(None);
        };
        if let Some(group) = binding["group_id"].as_str() {
            let epoch = binding["group_epoch"]
                .as_u64()
                .ok_or_else(|| invalid("surface group message epoch missing"))?;
            Ok(Some((group.into(), epoch)))
        } else {
            Ok(None)
        }
    }
    pub(crate) fn own_surface_history_controls(&self) -> Result<Vec<SurfaceControl>, SdkError> {
        let db = self.account_db()?;
        let ids = db.client_directory_ids("surface", "", 65)?;
        if ids.len() > 64 {
            return Err(invalid("own surface history count budget exceeded"));
        }
        let mut controls = Vec::new();
        for reference in ids {
            let Some((record, state)) = self.surface_state_ref(&reference)? else { continue };
            let prefix = key("history", &reference) + "/";
            let history: Value = db
                .load_actor_state(&format!("{prefix}{:020}", state.version()))?
                .ok_or_else(|| invalid("surface history proof missing"))?;
            let latest: Carrier = serde_json::from_value(history["carrier"].clone())?;
            if latest.snapshot.is_none() {
                return Err(invalid("surface history requires an author snapshot"));
            }
            let thread = db
                .client_record("conversation", &record.conversation_id)?
                .ok_or_else(|| invalid("surface conversation missing"))?;
            let group_epoch = db.load_actor_state::<u64>(&key("group_epoch", &reference))?;
            if thread["group_id"].is_string() && group_epoch.is_none() {
                return Err(invalid("surface group history epoch missing"));
            }
            let mut floor = None;
            if let Some(group) = thread["group_id"].as_str() {
                let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                if !self.group_state(group)?.roles.contains_key(&local.device_id) {
                    continue;
                }
                floor = db.group_member_joined_epoch(group, &local.device_id)?;
                if floor.is_none_or(|f| group_epoch.is_none_or(|epoch| epoch < f)) {
                    continue;
                }
            }
            controls.push(self.surface_control_packet(&latest, ControlKind::Own, group_epoch)?);
            let prefix = key("actions", &reference) + "/";
            let actions: Vec<Value> = db.surface_history_page(&prefix, &prefix, 101)?;
            if actions.len() > 100 {
                return Err(invalid("own surface action history count budget exceeded"));
            }
            for action in actions {
                if floor.is_some_and(|floor| {
                    action["group_epoch"].as_u64().is_none_or(|epoch| epoch < floor)
                }) {
                    continue;
                }
                if action["attestation"].is_object() {
                    let receipt: Carrier = serde_json::from_value(action["attestation"].clone())?;
                    controls.push(self.surface_control_packet(
                        &receipt,
                        ControlKind::Own,
                        action["group_epoch"].as_u64(),
                    )?);
                }
            }
            if serde_json::to_vec(&controls)?.len() > 8 * 1024 * 1024 {
                return Err(invalid("own surface history byte budget exceeded"));
            }
        }
        Ok(controls)
    }
    pub(crate) fn import_own_surface_history(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        controls: &[SurfaceControl],
    ) -> Result<(), SdkError> {
        if controls.len() > 6464 || serde_json::to_vec(controls)?.len() > 8 * 1024 * 1024 {
            return Err(invalid("own surface history budget exceeded"));
        }
        self.account_db()?.surface_transaction(|| {
            for (index, control) in controls.iter().enumerate() {
                if control.kind != ControlKind::Own {
                    return Err(invalid("own history contains peer control"));
                }
                let context = control
                    .context
                    .as_ref()
                    .ok_or_else(|| invalid("own history context missing"))?;
                let source = self
                    .account_db()?
                    .client_record("device", &envelope.source_device_id)?
                    .ok_or_else(|| invalid("own history source missing"))?;
                let principal = source["principal_id"]
                    .as_str()
                    .ok_or_else(|| invalid("own history principal missing"))?;
                // This adapter runs only after verify_own_device_sync_envelope authenticated the
                // same-root source, target and encrypted snapshot. It forwards that authenticated
                // provenance into the normal surface control guard; it grants no peer authority.
                let entry = GatewayInboxEntry {
                    inbox_seq: 0,
                    target_delivery_id: envelope.target_device_id.clone(),
                    envelope: ramflux_protocol::Envelope {
                        schema: "ramflux.envelope.v1".into(),
                        version: 1,
                        domain: ramflux_protocol::domain::SURFACE_CARRIER.into(),
                        ext: ramflux_protocol::Ext::default(),
                        signed: envelope.signed.clone(),
                        envelope_id: format!("{}:{index}", envelope.snapshot_id),
                        source_principal_id: principal.into(),
                        source_device_id: envelope.source_device_id.clone(),
                        target_delivery_id: envelope.target_device_id.clone(),
                        routing_set_id: None,
                        delivery_class: ramflux_protocol::DeliveryClass::SelfDeviceControl,
                        priority: ramflux_protocol::Priority::Normal,
                        ttl: 600,
                        created_at: envelope.expires_at.saturating_sub(600),
                        encrypted_payload: String::new(),
                        payload_hash: String::new(),
                    },
                };
                self.receive_surface_control(
                    &entry,
                    &context.conversation_id,
                    context.group.as_ref().map(|g| g.group_id.as_str()),
                    &control.bytes()?,
                )?;
            }
            Ok(())
        })
    }
}
