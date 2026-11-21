// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root Surface history retains the authenticated transport entry for every item.
use super::{ControlKind, OwnedSurfaceCheckpoint, StoredSurface, SurfaceControl, invalid};
use crate::client::{generated_fields, identity_authority::HeadUse, task::generated as json};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

impl OwnedSurfaceCheckpoint {
    pub(crate) fn to_generated(&self) -> Result<g::OwnedSurfaceCheckpoint, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&self.record.checkpoint_base64)
            .map_err(|_| invalid("surface history checkpoint encoding"))?;
        let checkpoint: serde_json::Value = serde_json::from_slice(&bytes)?;
        let wire = ramflux_protocol::decode_base64url(&self.snapshot_wire_base64)
            .map_err(|_| invalid("surface history snapshot encoding"))?;
        let event = ramflux_protocol::SurfaceEvent::from_wire_bytes(&wire)?;
        Ok(g::OwnedSurfaceCheckpoint {
            record: Some(g::StoredSurface {
                surface_id: self.record.surface_id.clone(),
                conversation_id: self.record.conversation_id.clone(),
                author_principal_id: self.record.author_principal_id.clone(),
                author_device_id: self.record.author_device_id.clone(),
                checkpoint: Some(serde_json::from_value(generated_fields::convert(
                    "SurfaceCheckpoint",
                    &checkpoint,
                    true,
                )?)?),
                created_at: self.record.created_at,
                updated_at: self.record.updated_at,
            }),
            snapshot_event: Some(super::generated::event(&event)?),
            version: self.version,
            surface_hash: self.surface_hash.clone(),
            conversation: Some(json::json_value(&self.conversation)?),
            group_epoch: self.group_epoch,
        })
    }
    pub(crate) fn from_generated(value: &g::OwnedSurfaceCheckpoint) -> Result<Self, SdkError> {
        let record =
            value.record.as_ref().ok_or_else(|| invalid("surface history record missing"))?;
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or_else(|| invalid("surface history checkpoint missing"))?;
        let checkpoint = generated_fields::convert(
            "SurfaceCheckpoint",
            &serde_json::to_value(checkpoint)?,
            false,
        )?;
        let event = value
            .snapshot_event
            .as_ref()
            .ok_or_else(|| invalid("surface history snapshot missing"))?;
        Ok(Self {
            record: StoredSurface {
                surface_id: record.surface_id.clone(),
                conversation_id: record.conversation_id.clone(),
                author_principal_id: record.author_principal_id.clone(),
                author_device_id: record.author_device_id.clone(),
                checkpoint_base64: ramflux_protocol::encode_base64url(
                    ramflux_protocol::canonical_json_bytes(&checkpoint)?,
                ),
                created_at: record.created_at,
                updated_at: record.updated_at,
            },
            snapshot_wire_base64: ramflux_protocol::encode_base64url(
                super::generated::native_event(event)?,
            ),
            version: value.version,
            surface_hash: value.surface_hash.clone(),
            conversation: json::value_json(
                value
                    .conversation
                    .as_ref()
                    .ok_or_else(|| invalid("surface history context missing"))?,
            )?,
            group_epoch: value.group_epoch,
        })
    }
}

impl RamfluxClient {
    pub(crate) fn import_generated_surface_history(
        &self,
        entry: &GatewayInboxEntry,
        history: &g::SurfaceHistoryExport,
    ) -> Result<(), SdkError> {
        if history.controls.len() > 64 * 129 || history.checkpoints.len() > 64 {
            return Err(invalid("surface history count budget exceeded"));
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let device = self.trusted_device(HeadUse::NewAuthorization, &source)?;
        self.authorize_owned_surface_source(&device)?;
        if let Some(metadata) = &history.metadata {
            self.account_db()?.persist_actor_state(
                &super::key("import_metadata", source.storage_key()),
                metadata,
            )?;
        }
        for (index, value) in history.checkpoints.iter().enumerate() {
            match OwnedSurfaceCheckpoint::from_generated(value) {
                Ok(checkpoint) => self.import_owned_surface_checkpoints(&[checkpoint])?,
                Err(error) => {
                    // Descriptor conversion has no storage side effects; malformed items
                    // must not discard independently valid checkpoints or later controls.
                    self.account_db()?.persist_actor_state(
                        &super::key(
                            "import_checkpoint_skip",
                            &format!("{}:{index}", entry.envelope.envelope_id),
                        ),
                        &serde_json::json!({"reason":error.to_string()}),
                    )?;
                }
            }
        }
        for (index, value) in history.controls.iter().enumerate() {
            let result = self.account_db()?.surface_transaction(|| {
                let control = SurfaceControl::from_generated(value)?;
                if control.kind != ControlKind::Own {
                    return Err(invalid("surface history contains peer delivery"));
                }
                let context = control
                    .context
                    .as_ref()
                    .ok_or_else(|| invalid("surface history context missing"))?;
                if !self.receive_surface_control_from(
                    entry,
                    &source,
                    &context.conversation_id,
                    context.group.as_ref().map(|g| g.group_id.as_str()),
                    &control.bytes()?,
                )? {
                    return Err(invalid("surface history delivery was not admitted"));
                }
                Ok::<_, SdkError>(())
            });
            if let Err(error) = result {
                if !matches!(
                    &error,
                    SdkError::GeneratedRefused { .. }
                        | SdkError::InboundRejected(_)
                        | SdkError::ReplayMismatch
                        | SdkError::SurfaceRefused { .. }
                        | SdkError::SurfaceCheckpointMismatch
                        | SdkError::SurfaceDeliveryTooLarge { .. }
                        | SdkError::Json(_)
                        | SdkError::Protocol(_)
                        | SdkError::Crypto(_)
                        | SdkError::LocalBus(_)
                ) {
                    return Err(error);
                }
                self.account_db()?.persist_actor_state(
                    &super::key(
                        "import_control_skip",
                        &format!("{}:{index}", entry.envelope.envelope_id),
                    ),
                    &serde_json::json!({"reason":error.to_string()}),
                )?;
            }
        }
        Ok(())
    }
}

impl super::SurfaceHistoryExport {
    pub(crate) fn generated_bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(g::Surface {
            payload: Some(g::surface::Payload::OwnHistory(g::SurfaceHistoryExport {
                controls: self
                    .controls
                    .iter()
                    .map(SurfaceControl::to_generated)
                    .collect::<Result<_, _>>()?,
                checkpoints: self
                    .checkpoints
                    .iter()
                    .map(OwnedSurfaceCheckpoint::to_generated)
                    .collect::<Result<_, _>>()?,
                metadata: Some(g::SurfaceExportMetadata {
                    truncated: self.metadata.truncated,
                    next_before: self.metadata.next_before,
                    skipped: self.metadata.skipped.clone(),
                }),
            })),
        }
        .encode_to_vec())
    }
}
