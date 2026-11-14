// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated Surface/Task admission delegates native state transitions after numeric dispatch.
use super::{Routing, invalid};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

#[derive(Clone, Copy)]
pub(super) struct SurfaceProjection<'a> {
    pub metadata: Option<&'a ramflux_storage::MessageMetadata>,
    pub expires_at: i64,
}

impl RamfluxClient {
    pub(super) fn project_generated_surface(
        &self,
        routing: &Routing,
        entry: &GatewayInboxEntry,
        surface: &g::Surface,
        exact: &[u8],
        metadata: Option<&ramflux_storage::MessageMetadata>,
    ) -> Result<(), SdkError> {
        self.project_generated_surface_at(
            routing,
            entry,
            surface,
            exact,
            SurfaceProjection {
                metadata,
                expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
            },
        )
    }

    /// Apply the local retention deadline without changing authenticated transport evidence.
    pub(super) fn project_generated_surface_at(
        &self,
        routing: &Routing,
        entry: &GatewayInboxEntry,
        surface: &g::Surface,
        exact: &[u8],
        projection: SurfaceProjection<'_>,
    ) -> Result<(), SdkError> {
        let SurfaceProjection { metadata, expires_at } = projection;
        let source = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        match surface.payload.as_ref().ok_or_else(|| invalid("Surface payload missing"))? {
            g::surface::Payload::Delivery(delivery) => {
                let native = crate::client::surface::SurfaceControl::from_generated(delivery)?;
                let own_group = if native.kind == crate::client::surface::ControlKind::Own {
                    native
                        .context
                        .as_ref()
                        .and_then(|context| context.group.as_ref())
                        .map(|group| group.group_id.clone())
                        .or(self
                            .account_db()?
                            .client_record("conversation", &routing.conversation_id)?
                            .and_then(|value| value["group_id"].as_str().map(str::to_owned)))
                } else {
                    routing.group_id.clone()
                };
                self.record_surface_origin(
                    &routing.message_id,
                    entry,
                    native.group_epoch,
                    expires_at,
                )?;
                if !self.receive_surface_control_scoped(
                    entry,
                    &source,
                    (&routing.conversation_id, own_group.as_deref(), Some(&routing.message_id)),
                    &native.bytes()?,
                    Some(expires_at),
                )? {
                    return Err(invalid("Surface delivery was not admitted"));
                }
            }
            g::surface::Payload::ResyncRequest(_) => {
                if !self.receive_surface_resync_request(
                    entry,
                    &routing.conversation_id,
                    &surface.encode_to_vec(),
                )? {
                    return Err(invalid("Surface resync request was not admitted"));
                }
                return Ok(());
            }
            g::surface::Payload::OwnHistory(history) => {
                return self.import_generated_surface_history(entry, history);
            }
        }
        self.append_plaintext_projection_once(
            &routing.conversation_id,
            &routing.message_id,
            entry,
            exact,
            metadata,
        )
    }

    pub(super) fn project_generated_task(
        &self,
        routing: &Routing,
        entry: &GatewayInboxEntry,
        task: &g::Task,
        exact: &[u8],
        metadata: Option<&ramflux_storage::MessageMetadata>,
    ) -> Result<(), SdkError> {
        match task.payload.as_ref().ok_or_else(|| invalid("Task payload missing"))? {
            g::task::Payload::Carrier(value) => {
                let carrier = crate::client::task::carrier::Carrier::from_generated(value)?;
                let result = self
                    .project_task_message(
                        &crate::client::task::Delivery {
                            conversation: &routing.conversation_id,
                            message: &routing.message_id,
                            principal: &entry.envelope.source_principal_id,
                            device: &entry.envelope.source_device_id,
                            at: entry.envelope.created_at,
                        },
                        &carrier.bytes()?,
                    )?
                    .ok_or_else(|| invalid("Task projection missing"))?;
                if !result.accepted && !result.pending {
                    return Err(invalid("Task native admission refused"));
                }
            }
            g::task::Payload::Control(_) => {
                if !self.receive_task_control(
                    entry,
                    &routing.conversation_id,
                    routing.group_id.as_deref(),
                    &task.encode_to_vec(),
                )? {
                    return Err(invalid("Task Control was not admitted"));
                }
                return Ok(());
            }
            g::task::Payload::Approval(_) => {
                if !self.receive_task_approval(
                    entry,
                    &routing.conversation_id,
                    &task.encode_to_vec(),
                )? {
                    return Err(invalid("Task Approval was not admitted"));
                }
                return Ok(());
            }
            g::task::Payload::OwnHistory(history) => {
                let source = self.authenticated_device_identity(
                    crate::client::identity_authority::HeadUse::NewAuthorization,
                    entry,
                )?;
                if source.root_commitment() != self.own_account_anchor()? {
                    return Err(invalid("Task history source is not an own-root sibling"));
                }
                self.require_native_operation(
                    &source,
                    crate::client::identity_authority::NativeOperation::Sync,
                )?;
                if let Some(metadata) = &history.metadata {
                    self.account_db()?.persist_actor_state(
                        &crate::client::task::key("import_metadata", source.storage_key()),
                        metadata,
                    )?;
                }
                if history.packets.len() > 100 {
                    return Err(invalid("Task OwnHistory packet budget exceeded"));
                }
                for packet in &history.packets {
                    let item = g::Task {
                        payload: Some(g::task::Payload::OwnHistory(g::TaskHistoryExport {
                            packets: vec![packet.clone()],
                            metadata: history.metadata.clone(),
                        })),
                    };
                    if !self.receive_task_own(
                        entry,
                        &routing.conversation_id,
                        routing.group_id.as_deref(),
                        &item.encode_to_vec(),
                    )? {
                        return Err(invalid("Task OwnHistory was not admitted"));
                    }
                }
                return Ok(());
            }
        }
        self.append_plaintext_projection_once(
            &routing.conversation_id,
            &routing.message_id,
            entry,
            exact,
            metadata,
        )
    }
}
