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
#[derive(Clone, Default, Serialize, Deserialize)]
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
        let owner = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        let mut rows = db.surface_export_records::<super::StoredSurface>(owner, before, 65)?;
        let mut result = SurfaceHistoryExport {
            controls: Vec::new(),
            checkpoints: Vec::new(),
            metadata: SurfaceExportMetadata::default(),
        };
        result.metadata.truncated = rows.len() > 64;
        rows.truncate(64);
        result.metadata.next_before =
            if result.metadata.truncated { rows.last().map(|(order, _)| *order) } else { None };
        let mut bytes = serde_json::to_vec(&result)?.len() + 4096;
        let mut blocks = Vec::new();
        // Select the newest bounded window, dropping older items first. Import each selected
        // surface/checkpoint before its decisions; metadata makes every omission explicit.
        for (_, stored) in rows {
            let mut block = Vec::new();
            let reference = &super::scope::surface_reference(
                &stored.conversation_id,
                &stored.author_principal_id,
                &stored.surface_id,
            )?;
            let Ok(checkpoint) = self.export_owned_surface_checkpoint(reference) else {
                result.metadata.skip("checkpoint_unavailable_or_below_floor");
                continue;
            };
            let prefix = key("history", reference) + "/";
            let normal = db
                .load_actor_state::<Value>(&format!("{prefix}{:020}", checkpoint.version))?
                .and_then(|history| {
                    serde_json::from_value::<Carrier>(history["carrier"].clone()).ok()
                })
                .filter(|carrier| {
                    carrier.snapshot.as_ref().is_some_and(super::snapshot::SnapshotProof::is_full)
                })
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
            bytes += size + 1;
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
        fit_export(&mut result, HISTORY_BYTES)?;
        db.persist_actor_state("surface/export_metadata", &result.metadata)?;
        Ok(result)
    }
    pub(crate) fn own_surface_history_pages(&self) -> Result<Vec<SurfaceHistoryExport>, SdkError> {
        let mut pages: Vec<SurfaceHistoryExport> = Vec::new();
        let mut cursor = None;
        for _ in 0..64 {
            let mut page = self.own_surface_history_export(cursor)?;
            cursor = page.metadata.next_before;
            // Account for the outer page array, separators, and serialized metadata as well
            // as every control/checkpoint. Trim individual items rather than losing a page.
            let used = serde_json::to_vec(&pages)?.len();
            let available = HISTORY_BYTES.saturating_sub(used + usize::from(!pages.is_empty()));
            if available < 4096 {
                if let Some(last) = pages.last_mut() {
                    last.metadata.truncated = true;
                    last.metadata.skip("history_byte_budget");
                }
                break;
            }
            fit_export(&mut page, available.saturating_sub(4096))?;
            pages.push(page);
            if cursor.is_none() {
                break;
            }
        }
        Ok(pages)
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
            *bytes += size + 1;
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
        let page_scope = ramflux_protocol::hash_base64url(
            "ramflux.surface.history_page.v1",
            &serde_json::to_vec(controls)?,
        );
        for (index, control) in controls.iter().enumerate() {
            let imported = self.account_db()?.surface_transaction(|| {
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
                        envelope_id: format!("{}:{page_scope}:{index}", envelope.snapshot_id),
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
                Ok::<_, SdkError>(())
            });
            if let Err(error) = imported {
                self.account_db()?.persist_actor_state(
                    &key(
                        "import_control_skip",
                        &format!("{}:{page_scope}:{index}", envelope.snapshot_id),
                    ),
                    &serde_json::json!({"reason":error.to_string()}),
                )?;
            }
        }
        Ok(())
    }
}

const HISTORY_BYTES: usize = 8 * 1024 * 1024;
fn fit_export(page: &mut SurfaceHistoryExport, budget: usize) -> Result<(), SdkError> {
    let control_sizes = page
        .controls
        .iter()
        .map(|value| Ok(serde_json::to_vec(value)?.len()))
        .collect::<Result<Vec<usize>, SdkError>>()?;
    let checkpoint_sizes = page
        .checkpoints
        .iter()
        .map(|value| Ok(serde_json::to_vec(value)?.len()))
        .collect::<Result<Vec<usize>, SdkError>>()?;
    let mut content_bytes = control_sizes.iter().chain(&checkpoint_sizes).sum::<usize>()
        + page.controls.len().saturating_sub(1)
        + page.checkpoints.len().saturating_sub(1);
    let mut controls_removed = 0;
    let mut checkpoints_removed = 0;
    loop {
        // Serialize only the small metadata/framing object while selecting the retained
        // suffix. Each potentially large control/checkpoint was measured exactly once.
        let framing = SurfaceHistoryExport {
            controls: Vec::new(),
            checkpoints: Vec::new(),
            metadata: page.metadata.clone(),
        };
        if content_bytes + serde_json::to_vec(&framing)?.len() <= budget {
            break;
        }
        if let Some(size) = control_sizes.get(controls_removed) {
            content_bytes -= size + usize::from(control_sizes.len() - controls_removed > 1);
            controls_removed += 1;
        } else if let Some(size) = checkpoint_sizes.get(checkpoints_removed) {
            content_bytes -= size + usize::from(checkpoint_sizes.len() - checkpoints_removed > 1);
            checkpoints_removed += 1;
        } else {
            return Err(invalid("surface export metadata exceeds byte budget"));
        }
        page.metadata.truncated = true;
        page.metadata.skip("serialized_history_byte_budget");
    }
    // One compaction per array instead of moving the remaining elements for each item.
    page.controls.drain(..controls_removed);
    page.checkpoints.drain(..checkpoints_removed);
    Ok(())
}

impl RamfluxClient {
    pub(crate) fn skip_owned_surface_message(
        &self,
        bundle: &crate::own_device_sync::SdkOwnDeviceHistoryBundle,
        message: &str,
        floors: &std::collections::BTreeMap<String, u64>,
    ) -> Result<bool, SdkError> {
        let Some((group, epoch)) = bundle.surface_message_epochs.get(message) else {
            return Ok(false);
        };
        let reason = match floors.get(group) {
            None => "group_message_unavailable",
            Some(floor) if epoch < floor => "group_message_below_join_floor",
            Some(_) => return Ok(false),
        };
        self.account_db()?.record_own_device_restore_skip(&bundle.snapshot_id, message, reason)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialized_first_page_overflow_keeps_items_and_explicit_metadata() -> Result<(), SdkError> {
        let control = SurfaceControl {
            kind: ControlKind::Own,
            carrier_base64: "x".repeat(2000),
            group_epoch: None,
            context: None,
            manifests: Vec::new(),
        };
        let mut page = SurfaceHistoryExport {
            controls: vec![control.clone(); 4],
            ..SurfaceHistoryExport::default()
        };
        let item_bytes = serde_json::to_vec(&control)?.len();
        fit_export(&mut page, item_bytes * 4)?;
        assert_eq!(page.controls.len(), 3);
        assert!(page.metadata.truncated);
        assert_eq!(page.metadata.skipped["serialized_history_byte_budget"], 1);
        assert!(serde_json::to_vec(&page)?.len() <= item_bytes * 4);
        fit_export(&mut page, 512)?;
        assert_eq!(page.controls.len(), 0);
        assert!(page.metadata.truncated && !page.metadata.skipped.is_empty());
        assert!(serde_json::to_vec(&page)?.len() <= 512);
        Ok(())
    }
    #[test]
    fn two_thousand_and_one_controls_trim_with_a_single_retained_suffix() -> Result<(), SdkError> {
        let controls = (0..2001)
            .map(|index| SurfaceControl {
                kind: ControlKind::Own,
                carrier_base64: format!("{index:04}{}", "x".repeat(1996)),
                group_epoch: None,
                context: None,
                manifests: Vec::new(),
            })
            .collect();
        let mut page = SurfaceHistoryExport { controls, ..SurfaceHistoryExport::default() };
        let budget = serde_json::to_vec(&page)?.len() / 2;
        fit_export(&mut page, budget)?;
        assert!(page.controls.len() > 990 && page.controls.len() < 1010);
        assert!(
            page.controls.first().is_some_and(|control| control.carrier_base64.starts_with("100"))
        );
        assert_eq!(
            usize::try_from(page.metadata.skipped["serialized_history_byte_budget"])
                .map_err(|_| invalid("skip count"))?,
            2001 - page.controls.len()
        );
        assert!(serde_json::to_vec(&page)?.len() <= budget);
        Ok(())
    }
}
