// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root task history forwarding, with causal-prefix and original-signer verification.
use super::{AcceptedEvent, TaskHistory, carrier::Carrier, invalid};
use crate::client::identity_authority::HeadUse;
use crate::client::surface::OwnContext;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct TaskExportMetadata {
    pub truncated: bool,
    pub skipped_items: u32,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskOwnPacket {
    context: OwnContext,
    history: TaskHistory,
    manifests: Vec<SdkDeviceManifestResponse>,
    pins: Vec<crate::own_device_sync::SdkOwnDeviceGroupMemberPin>,
    base: usize,
    prefix_hash: String,
}
impl TaskOwnPacket {
    pub(crate) fn to_generated(&self) -> Result<g::TaskOwnPacket, SdkError> {
        if self.history.checkpoint.is_some() {
            return Err(invalid("local Task checkpoints cannot be exported"));
        }
        Ok(g::TaskOwnPacket {
            context: Some(g::OwnContext::try_from(&self.context)?),
            history: Some(g::TaskHistory {
                events: self
                    .history
                    .events
                    .iter()
                    .map(|event| {
                        Ok::<_, SdkError>(g::TaskAcceptedEvent {
                            carrier: Some(event.carrier.to_generated()?),
                            public_key: event.public_key.clone(),
                            actor_kind_verified: event.actor_kind_verified,
                            received_at: event.received_at,
                            decision_certificate: event
                                .decision_certificate
                                .as_ref()
                                .map(g::TaskCertificate::try_from)
                                .transpose()?,
                            membership: event
                                .membership
                                .as_ref()
                                .map(g::TaskMembership::try_from)
                                .transpose()?,
                        })
                    })
                    .collect::<Result<_, _>>()?,
                created_at: self.history.created_at,
                updated_at: self.history.updated_at,
            }),
            manifests: self
                .manifests
                .iter()
                .map(g::NativeDeviceManifest::try_from)
                .collect::<Result<_, _>>()?,
            pins: self.pins.iter().map(g::SdkOwnDeviceGroupMemberPin::from).collect(),
            base: u64::try_from(self.base).map_err(|_| invalid("task page base overflow"))?,
            prefix_hash: self.prefix_hash.clone(),
        })
    }
    pub(crate) fn from_generated(value: &g::TaskOwnPacket) -> Result<Self, SdkError> {
        let history = value.history.as_ref().ok_or_else(|| invalid("Task history missing"))?;
        Ok(Self {
            context: OwnContext::try_from(
                value.context.as_ref().ok_or_else(|| invalid("Task context missing"))?,
            )?,
            history: TaskHistory {
                events: history
                    .events
                    .iter()
                    .map(|event| {
                        Ok::<_, SdkError>(AcceptedEvent {
                            carrier: Carrier::from_generated(
                                event
                                    .carrier
                                    .as_ref()
                                    .ok_or_else(|| invalid("Task event carrier missing"))?,
                            )?,
                            public_key: event.public_key.clone(),
                            actor_kind_verified: event.actor_kind_verified,
                            received_at: event.received_at,
                            decision_certificate: event
                                .decision_certificate
                                .as_ref()
                                .map(super::generated::certificate::native_certificate)
                                .transpose()?,
                            membership: event
                                .membership
                                .as_ref()
                                .map(super::historical::Membership::try_from)
                                .transpose()?,
                        })
                    })
                    .collect::<Result<_, _>>()?,
                created_at: history.created_at,
                updated_at: history.updated_at,
                checkpoint: None,
            },
            manifests: value
                .manifests
                .iter()
                .map(super::generated::manifest::generated_manifest_fields)
                .collect::<Result<_, _>>()?,
            pins: value
                .pins
                .iter()
                .map(crate::own_device_sync::SdkOwnDeviceGroupMemberPin::from)
                .collect(),
            base: usize::try_from(value.base).map_err(|_| invalid("Task page base overflow"))?,
            prefix_hash: value.prefix_hash.clone(),
        })
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(g::Task {
            payload: Some(g::task::Payload::OwnHistory(g::TaskHistoryExport {
                packets: vec![self.to_generated()?],
                metadata: Some(g::TaskExportMetadata::default()),
            })),
        }
        .encode_to_vec())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, SdkError> {
        if bytes.len() > super::MAX_DELIVERY_BYTES {
            return Err(invalid("Task history byte budget exceeded"));
        }
        if g::validation::scan_message("Task", bytes, g::registry::COMPILED_LAYER).is_err() {
            return Ok(None);
        }
        let task = g::Task::decode(bytes).map_err(|_| invalid("Task history malformed"))?;
        let Some(g::task::Payload::OwnHistory(history)) = task.payload else {
            return Ok(None);
        };
        let [packet] = history.packets.as_slice() else {
            return Err(invalid("one Task page per delivery required"));
        };
        Ok(Some(Self::from_generated(packet)?))
    }
}
impl RamfluxClient {
    fn check_task_own_group_fence(&self, context: &OwnContext) -> Result<(), SdkError> {
        if let Some(group) = &context.group
            && self.group_state(&group.group_id).is_ok()
        {
            if !self.local_is_group_member(&group.group_id)? {
                return Err(invalid("own task snapshot cannot restore removed local membership"));
            }
            if self.group_state(&group.group_id)?.group_epoch < group.group_epoch {
                return Err(SdkError::InboundPending(
                    "task snapshot awaits authenticated membership changes".into(),
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn task_own_packets(&self, carrier: &Carrier) -> Result<Vec<Vec<u8>>, SdkError> {
        let db = self.account_db()?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let thread = db
            .client_record("conversation", &carrier.conversation_id)?
            .ok_or_else(|| invalid("own task conversation missing"))?;
        let group = if let Some(id) = thread["group_id"].as_str() {
            Some(
                self.own_device_group_snapshots(&local.device_id)?
                    .into_iter()
                    .find(|g| g.group_id == id)
                    .ok_or_else(|| invalid("own task group access unavailable"))?,
            )
        } else {
            None
        };
        let participants = thread["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut friend = None;
        if group.is_none()
            && let Some(peer) = participants.iter().find(|id| **id != local.principal_id)
        {
            friend = db.friend_link_for_peer(peer)?;
            if friend.is_none()
                && let Some(commitment) = db
                    .client_record("identity", peer)?
                    .as_ref()
                    .and_then(|v| v["contact_identity_commitment"].as_str())
            {
                friend = db.friend_link_for_peer(commitment)?;
            }
        }
        let mut history =
            self.task_history(&carrier.conversation_id, carrier.event()?.event().task_id())?;
        if history.checkpoint.is_some() {
            return Ok(Vec::new());
        }
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        if !history.events.iter().any(|e| {
            e.carrier.message_id == carrier.message_id
                && e.carrier.principal_id == carrier.principal_id
        }) {
            let event = carrier.verify(&public)?;
            let mut state = history.state()?;
            self.authorize_task_relations(carrier, state.task())?;
            state
                .apply(&event, &carrier.signer(&public, &event))
                .map_err(|error| crate::task_refusal::protocol(&error))?;
            let at = crate::time::now_unix_timestamp();
            let membership = self.task_membership_witness(
                carrier,
                state.task().ok_or_else(|| invalid("own task state missing"))?,
                at,
            )?;
            history.events.push(AcceptedEvent {
                carrier: carrier.clone(),
                public_key: public,
                actor_kind_verified: super::carrier_kind_verified(self, carrier),
                received_at: at,
                decision_certificate: None,
                membership: Some(membership),
            });
        }
        let principals = history
            .events
            .iter()
            .map(|e| e.carrier.principal_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut manifests = Vec::new();
        for principal in principals {
            manifests.push(
                db.load_actor_state(&format!("identity/manifest/{principal}"))?
                    .ok_or_else(|| invalid("own task signer manifest missing"))?,
            );
        }
        let pins = self.own_device_group_member_pins(group.as_slice())?;
        let packet = TaskOwnPacket {
            context: OwnContext {
                conversation_id: carrier.conversation_id.clone(),
                participants,
                group,
                friend,
            },
            history,
            manifests,
            pins,
            base: 0,
            prefix_hash: task_prefix_hash(&[])?,
        };
        task_packet_pages(packet)
    }
    pub(crate) fn receive_task_own(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(packet) = TaskOwnPacket::decode(body)? else { return Ok(false) };
        if body.len() > super::MAX_DELIVERY_BYTES {
            return Err(invalid("own task history budget exceeded"));
        }
        let source = self
            .account_db()?
            .client_device_record(
                &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
            )?
            .ok_or_else(|| invalid("own task source missing"))?;
        if source["principal_id"] != entry.envelope.source_principal_id {
            return Err(invalid("own task source owner mismatch"));
        }
        self.authorize_owned_surface_source(&source)?;
        if packet.context.conversation_id != conversation
            || packet.context.group.as_ref().map(|g| g.group_id.as_str()) != group
            || packet.history.events.len() > 289
            || packet.manifests.len() > 64
        {
            return Err(invalid("own task history context or count mismatch"));
        }
        self.import_task_own_packet(&packet).map(|()| true)
    }
    fn import_task_own_packet(&self, packet: &TaskOwnPacket) -> Result<(), SdkError> {
        self.validate_own_context_namespace(&packet.context)?;
        let conversation = &packet.context.conversation_id;
        self.account_db()?.write_transaction(|| {
            self.check_task_own_group_fence(&packet.context)?;
            for manifest in &packet.manifests {
                let existing =
                    self.account_db()?.client_record("identity", &manifest.principal_id)?;
                let commitment = if manifest.principal_id
                    == self
                        .device_branch
                        .as_ref()
                        .ok_or(SdkError::IdentityRootMissing)?
                        .principal_id
                {
                    self.surface_local_root_commitment()?
                } else {
                    existing
                        .as_ref()
                        .and_then(|v| v["contact_identity_commitment"].as_str())
                        .unwrap_or(&manifest.principal_commitment)
                        .to_owned()
                };
                crate::client::contact::verify_device_manifest(manifest, &commitment)?;
                self.persist_identity_directory(manifest)?;
            }
            self.import_surface_context(&packet.context)?;
            let mut active_pins = Vec::new();
            for pin in &packet.pins {
                if let Some(root) = &pin.principal_commitment
                    && let Ok(identity) = self.device_identity_for_root(root, &pin.device_id)
                    && self.account_db()?.group_member_role(&pin.group_id, &identity)?.is_some()
                {
                    active_pins.push(pin.clone());
                }
            }
            for pin in &active_pins {
                self.restore_own_member_pin(pin)?;
            }
            let first =
                packet.history.events.first().ok_or_else(|| invalid("own task history empty"))?;
            let id = first.carrier.event()?.event().task_id().to_owned();
            let existing = self.task_history(conversation, &id)?;
            if packet.base > existing.events.len() {
                return Err(SdkError::InboundPending(
                    "task history page awaits earlier events".into(),
                ));
            }
            if task_prefix_hash(&existing.events[..packet.base])? != packet.prefix_hash {
                return Err(invalid("task history page prefix differs from committed history"));
            }
            for (old, new) in existing.events.iter().skip(packet.base).zip(&packet.history.events) {
                if old.carrier.bytes()? != new.carrier.bytes()? {
                    return Err(invalid("own task history is not a causal extension"));
                }
            }
            for accepted in
                packet.history.events.iter().skip(existing.events.len().saturating_sub(packet.base))
            {
                let carrier = &accepted.carrier;
                if carrier.conversation_id != *conversation
                    || carrier.event()?.event().task_id() != id
                {
                    return Err(invalid("own task event context mismatch"));
                }
                self.project_historical_task_event(accepted, &packet.context)?;
            }
            Ok::<_, SdkError>(())
        })
    }
}

impl RamfluxClient {
    pub(crate) fn generated_task_export_metadata(
        &self,
        target_device: &str,
    ) -> Result<g::TaskExportMetadata, SdkError> {
        let metadata = self
            .account_db()?
            .load_actor_state::<TaskExportMetadata>(&super::key("export_metadata", target_device))?
            .unwrap_or_default();
        Ok(g::TaskExportMetadata {
            truncated: metadata.truncated,
            skipped_items: metadata.skipped_items,
            next_cursor: metadata.next_cursor,
        })
    }

    pub(crate) fn own_task_packets(
        &self,
        target_device: &str,
    ) -> Result<Vec<TaskOwnPacket>, SdkError> {
        self.maintain_task_lifecycle(crate::time::now_unix_timestamp())?;
        let db = self.account_db()?;
        let cursor_key = super::key("export_cursor", target_device);
        let metadata_key = super::key("export_metadata", target_device);
        let mut cursor =
            db.load_actor_state::<String>(&cursor_key)?.unwrap_or_else(|| "task/history/".into());
        let mut packets = Vec::new();
        let mut metadata = TaskExportMetadata::default();
        let mut size = 0usize;
        for _ in 0..32 {
            let rows = db.task_record_page::<TaskHistory>("task/history/", &cursor, 101)?;
            let done = rows.len() < 101;
            for (key, history) in rows {
                let previous = cursor.clone();
                cursor = key;
                if let Some(last) = history.events.last() {
                    let bodies = match self.task_own_packets(&last.carrier) {
                        Ok(bodies) => bodies,
                        Err(SdkError::Storage(error)) => return Err(SdkError::Storage(error)),
                        Err(_) => {
                            metadata.skipped_items += 1;
                            metadata.truncated = true;
                            self.record_task_history_skip(&cursor, "task_export_item_unavailable")?;
                            continue;
                        }
                    };
                    let bytes: usize = bodies.iter().map(Vec::len).sum();
                    if size.saturating_add(bytes) > 4 * 1024 * 1024
                        || packets.len().saturating_add(bodies.len()) > 100
                    {
                        self.record_task_history_skip(&cursor, "task_export_page_budget")?;
                        metadata.truncated = true;
                        if packets.is_empty() {
                            metadata.skipped_items += 1;
                        } else {
                            cursor = previous;
                        }
                        metadata.next_cursor = Some(cursor.clone());
                        db.persist_actor_state(&metadata_key, &metadata)?;
                        db.persist_actor_state(&cursor_key, &cursor)?;
                        return Ok(packets);
                    }
                    for body in bodies {
                        packets.push(
                            TaskOwnPacket::decode(&body)?
                                .ok_or_else(|| invalid("typed task snapshot missing"))?,
                        );
                    }
                    size += bytes;
                }
                if packets.len() >= 100 {
                    metadata.truncated = true;
                    metadata.next_cursor = Some(cursor.clone());
                    db.persist_actor_state(&metadata_key, &metadata)?;
                    db.persist_actor_state(&cursor_key, &cursor)?;
                    return Ok(packets);
                }
            }
            if done {
                cursor = "task/history/".into();
                break;
            }
        }
        if cursor != "task/history/" {
            metadata.truncated = true;
            metadata.next_cursor = Some(cursor.clone());
        }
        db.persist_actor_state(&metadata_key, &metadata)?;
        db.persist_actor_state(&cursor_key, &cursor)?;
        Ok(packets)
    }
    pub(super) fn record_task_history_skip(
        &self,
        item: &str,
        reason: &str,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_actor_state(
            &super::key("import_skip", item),
            &serde_json::json!({"item":item,"reason":reason}),
        )?;
        db.prune_task_diagnostics("task/import_skip/", 256)?;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn import_own_task_packets(
        &self,
        packets: &[TaskOwnPacket],
    ) -> Result<(), SdkError> {
        if packets.len() > 100 || serde_json::to_vec(packets)?.len() > 4 * 1024 * 1024 {
            self.record_task_history_skip("task_import", "task_snapshot_budget_exceeded")?;
            return Ok(());
        }
        for packet in packets {
            match self.account_db()?.write_transaction(|| self.import_task_own_packet(packet)) {
                Ok(()) => {}
                Err(SdkError::Storage(error)) => return Err(SdkError::Storage(error)),
                Err(_) => {
                    let item = packet
                        .history
                        .events
                        .first()
                        .map_or_else(|| "empty".into(), |e| e.carrier.message_id.clone());
                    self.record_task_history_skip(&item, "task_history_item_rejected")?;
                }
            }
        }
        Ok(())
    }
}

fn task_prefix_hash(events: &[AcceptedEvent]) -> Result<String, SdkError> {
    let bytes = events
        .iter()
        .map(|e| e.carrier.to_generated().map(|carrier| carrier.encode_to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ramflux_protocol::hash_base64url(
        "ramflux.task.history_prefix.v1",
        &ramflux_protocol::canonical_json_bytes(&bytes)?,
    ))
}
fn task_packet_pages(mut packet: TaskOwnPacket) -> Result<Vec<Vec<u8>>, SdkError> {
    let events = std::mem::take(&mut packet.history.events);
    let mut pages = Vec::new();
    for event in &events {
        packet.history.events.push(event.clone());
        if packet.bytes()?.len() > super::MAX_DELIVERY_BYTES {
            packet.history.events.pop();
            if packet.history.events.is_empty() {
                return Err(invalid("task snapshot item exceeds the transport byte budget"));
            }
            pages.push(packet.bytes()?);
            packet.base += packet.history.events.len();
            packet.prefix_hash = task_prefix_hash(&events[..packet.base])?;
            packet.history.events = vec![event.clone()];
            if packet.bytes()?.len() > super::MAX_DELIVERY_BYTES {
                return Err(invalid("task snapshot item exceeds the transport byte budget"));
            }
        }
    }
    if !packet.history.events.is_empty() {
        pages.push(packet.bytes()?);
    }
    Ok(pages)
}
