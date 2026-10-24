// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded surface proofs in the existing authenticated own-device history snapshot.
use super::{Carrier, ControlKind, OwnedSurfaceCheckpoint, SurfaceControl, invalid, key};
use crate::own_device_sync::SdkOwnDeviceSyncEnvelope;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct SurfaceExportMetadata {
    pub truncated: bool,
    pub next_before: Option<i64>,
    pub skipped: std::collections::BTreeMap<String, u32>,
}
pub(crate) struct SurfaceHistoryExport {
    pub controls: Vec<SurfaceControl>,
    pub checkpoints: Vec<OwnedSurfaceCheckpoint>,
    pub metadata: SurfaceExportMetadata,
}
impl SurfaceExportMetadata {
    fn skip(&mut self, reason: &str) {
        *self.skipped.entry(reason.into()).or_default() += 1;
    }
}
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
    #[cfg(test)]
    pub(crate) fn own_surface_history_controls(&self) -> Result<Vec<SurfaceControl>, SdkError> {
        Ok(self.own_surface_history_export(None)?.controls)
    }
    pub(crate) fn own_surface_history_export(
        &self,
        before: Option<i64>,
    ) -> Result<SurfaceHistoryExport, SdkError> {
        let db = self.account_db()?;
        let mut rows = db.surface_recent_records::<Value>("directory/surface/", before, 65)?;
        let mut result = SurfaceHistoryExport {
            controls: Vec::new(),
            checkpoints: Vec::new(),
            metadata: SurfaceExportMetadata::default(),
        };
        result.metadata.truncated = rows.len() > 64;
        rows.truncate(64);
        result.metadata.next_before =
            if result.metadata.truncated { rows.last().map(|(order, _)| *order) } else { None };
        let mut bytes = 0usize;
        let mut blocks = Vec::new();
        // Select the newest bounded window, dropping older items first. Import each selected
        // surface/checkpoint before its decisions; metadata makes every omission explicit.
        for (_, view) in rows {
            let mut block = Vec::new();
            let Some(reference) = view["surface_ref"].as_str() else {
                result.metadata.skip("invalid_view");
                continue;
            };
            let Ok(checkpoint) = self.export_owned_surface_checkpoint(reference) else {
                result.metadata.skip("checkpoint_unavailable_or_below_floor");
                continue;
            };
            let prefix = key("history", reference) + "/";
            let normal = db
                .load_actor_state::<Value>(&format!(
                    "{prefix}{:020}",
                    view["version"].as_u64().unwrap_or(0)
                ))?
                .and_then(|history| {
                    serde_json::from_value::<Carrier>(history["carrier"].clone()).ok()
                })
                .filter(|carrier| carrier.snapshot.is_some())
                .and_then(|carrier| {
                    self.surface_control_packet(&carrier, ControlKind::Own, checkpoint.group_epoch)
                        .ok()
                })
                .filter(|control| control.bytes().is_ok());
            let size = if let Some(control) = &normal {
                serde_json::to_vec(control)?.len()
            } else {
                serde_json::to_vec(&checkpoint)?.len()
            };
            if bytes + size > 8 * 1024 * 1024 {
                result.metadata.truncated = true;
                result.metadata.skip("surface_byte_budget");
                continue;
            }
            bytes += size;
            let epoch = checkpoint.group_epoch;
            let floor = if let Some(group) = checkpoint.conversation["group_id"].as_str() {
                let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                db.group_member_joined_epoch(group, &local.device_id)?
            } else {
                None
            };
            if let Some(control) = normal {
                block.push(control);
            } else {
                result.checkpoints.push(checkpoint);
            }
            block.extend(self.surface_export_decisions(
                reference,
                floor,
                epoch,
                &mut bytes,
                &mut result.metadata,
            )?);
            blocks.push(block);
        }
        result.checkpoints.reverse();
        result.controls = blocks.into_iter().rev().flatten().collect();
        db.persist_actor_state("surface/export_metadata", &result.metadata)?;
        Ok(result)
    }
    fn surface_export_decisions(
        &self,
        reference: &str,
        floor: Option<u64>,
        epoch: Option<u64>,
        bytes: &mut usize,
        metadata: &mut SurfaceExportMetadata,
    ) -> Result<Vec<SurfaceControl>, SdkError> {
        let prefix = key("actions", reference) + "/";
        let mut actions = self.account_db()?.surface_recent_records::<Value>(&prefix, None, 129)?;
        metadata.truncated |= actions.len() > 128;
        actions.truncate(128);
        let mut controls = Vec::new();
        for (_, action) in actions {
            if floor.is_some_and(|floor| {
                action["group_epoch"].as_u64().is_none_or(|epoch| epoch < floor)
            }) {
                metadata.skip("action_below_join_floor");
                continue;
            }
            let control = serde_json::from_value::<Carrier>(action["attestation"].clone())
                .ok()
                .and_then(|receipt| {
                    self.surface_control_packet(
                        &receipt,
                        ControlKind::Own,
                        action["group_epoch"].as_u64().or(epoch),
                    )
                    .ok()
                });
            let Some(control) = control.filter(|control| control.bytes().is_ok()) else {
                metadata.skip("action_attestation_unavailable");
                continue;
            };
            let size = serde_json::to_vec(&control)?.len();
            if *bytes + size > 8 * 1024 * 1024 {
                metadata.truncated = true;
                metadata.skip("action_byte_budget");
                continue;
            }
            *bytes += size;
            controls.push(control);
        }
        controls.reverse();
        Ok(controls)
    }
    pub(crate) fn import_own_surface_history(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        controls: &[SurfaceControl],
    ) -> Result<(), SdkError> {
        if controls.len() > 64 * 129 || serde_json::to_vec(controls)?.len() > 8 * 1024 * 1024 {
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
