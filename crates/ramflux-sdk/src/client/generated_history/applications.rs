// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native application history uses typed Surface/Task payloads in the existing own courier.
use crate::client::own_device_copy::{OwnMessageInput, OwnPayloadKind};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;

impl RamfluxClient {
    pub(super) fn stage_native_application_history(
        &self,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<(), SdkError> {
        let conversation = format!("own-history:{}", self.own_account_anchor()?);
        for page in self.own_surface_history_pages()? {
            if page.controls.is_empty() && page.checkpoints.is_empty() {
                continue;
            }
            let surface = g::Surface::decode(page.generated_bytes()?.as_slice()).map_err(|_| {
                SdkError::InboundRejected("Surface history encoding invalid".into())
            })?;
            let Some(g::surface::Payload::OwnHistory(history)) = surface.payload else {
                return Err(SdkError::InboundRejected("Surface history payload missing".into()));
            };
            self.stage_surface_history_pages(target, &conversation, history)?;
        }
        let packets = self.own_task_packets(target.device_id())?;
        let metadata = self.generated_task_export_metadata(target.device_id())?;
        if packets.is_empty()
            && (metadata.truncated || metadata.skipped_items > 0 || metadata.next_cursor.is_some())
        {
            let bytes = g::Task {
                payload: Some(g::task::Payload::OwnHistory(g::TaskHistoryExport {
                    packets: Vec::new(),
                    metadata: Some(metadata.clone()),
                })),
            }
            .encode_to_vec();
            self.stage_application_history(
                target,
                OwnPayloadKind::Task,
                &conversation,
                None,
                &bytes,
            )?;
        }
        for packet in packets {
            let packet = packet.to_generated()?;
            let context = packet
                .context
                .as_ref()
                .ok_or_else(|| SdkError::InboundRejected("Task history context missing".into()))?;
            let group = context.group.as_ref().map(|group| group.group_id.as_str());
            let bytes = g::Task {
                payload: Some(g::task::Payload::OwnHistory(g::TaskHistoryExport {
                    packets: vec![packet.clone()],
                    metadata: Some(metadata.clone()),
                })),
            }
            .encode_to_vec();
            self.stage_application_history(
                target,
                OwnPayloadKind::Task,
                &context.conversation_id,
                group,
                &bytes,
            )?;
        }
        Ok(())
    }

    fn stage_surface_history_pages(
        &self,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        history: g::SurfaceHistoryExport,
    ) -> Result<(), SdkError> {
        const BUDGET: usize = crate::client::own_device_copy::MAX_PACKET_BYTES - 16 * 1024;
        let mut page = g::SurfaceHistoryExport {
            controls: Vec::new(),
            checkpoints: Vec::new(),
            metadata: history.metadata,
        };
        // Checkpoints establish native state before later decision controls, including
        // when a large export spans several independently authenticated courier packets.
        for checkpoint in history.checkpoints {
            page.checkpoints.push(checkpoint);
            if page.encoded_len() > BUDGET {
                let item = page.checkpoints.pop().ok_or(SdkError::ReplayMismatch)?;
                self.stage_surface_history_packet(target, conversation, &page)?;
                page.checkpoints.clear();
                page.controls.clear();
                page.checkpoints.push(item);
                if page.encoded_len() > BUDGET {
                    return Err(SdkError::PayloadTooLarge);
                }
            }
        }
        for control in history.controls {
            page.controls.push(control);
            if page.encoded_len() > BUDGET {
                let item = page.controls.pop().ok_or(SdkError::ReplayMismatch)?;
                self.stage_surface_history_packet(target, conversation, &page)?;
                page.checkpoints.clear();
                page.controls.clear();
                page.controls.push(item);
                if page.encoded_len() > BUDGET {
                    return Err(SdkError::PayloadTooLarge);
                }
            }
        }
        self.stage_surface_history_packet(target, conversation, &page)
    }

    fn stage_surface_history_packet(
        &self,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
        conversation: &str,
        page: &g::SurfaceHistoryExport,
    ) -> Result<(), SdkError> {
        if page.controls.is_empty() && page.checkpoints.is_empty() {
            return Ok(());
        }
        let bytes = g::Surface { payload: Some(g::surface::Payload::OwnHistory(page.clone())) }
            .encode_to_vec();
        self.stage_application_history(target, OwnPayloadKind::Surface, conversation, None, &bytes)
    }

    fn stage_application_history(
        &self,
        target: &ramflux_crypto::RootQualifiedDeviceRef,
        kind: OwnPayloadKind,
        conversation: &str,
        group: Option<&str>,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        let id = ramflux_protocol::hash_base64url(
            "ramflux.message.application-history.v1",
            &ramflux_protocol::canonical_json_bytes(&(target.storage_key(), bytes))?,
        );
        let db = self.account_db()?;
        db.write_transaction(|| {
            // Queue publication and every erasure link commit together. The storage
            // page API caps at 4096, so count before reading the bounded page.
            for prefix in ["surface/message/", "task/message/"] {
                if db.actor_state_usage(prefix)?.0 > 4096 {
                    return Err(SdkError::PayloadTooLarge);
                }
            }
            crate::bus::own_device_copy::stage_to(
                self,
                OwnMessageInput {
                    payload_kind: kind,
                    id: &id,
                    created_at: crate::time::now_unix_timestamp(),
                    conversation,
                    group,
                    body: bytes,
                },
                target,
            )?;
            let actor =
                format!("own-device/send/{}", crate::bus::own_device_copy::copy_id(self, &id)?);
            // Each native application message can retire this opaque container.
            for prefix in ["surface/message/", "task/message/"] {
                for key in db.actor_state_key_page(prefix, 4096)? {
                    db.bind_actor_container_reference(&key, &actor)?;
                }
            }
            Ok(())
        })
    }
}
