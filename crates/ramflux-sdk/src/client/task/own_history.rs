// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root task history forwarding, with causal-prefix and original-signer verification.
use super::{AcceptedEvent, Delivery, TaskHistory, carrier::Carrier, invalid};
use crate::client::surface::OwnContext;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub(crate) const PREFIX: &[u8] = b"ramflux.task.own.v1\n";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskOwnPacket {
    context: OwnContext,
    history: TaskHistory,
    manifests: Vec<SdkDeviceManifestResponse>,
}
impl RamfluxClient {
    pub(crate) fn task_own_packet(&self, carrier: &Carrier) -> Result<Vec<u8>, SdkError> {
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
        if group.is_none() {
            if let Some(peer) = participants.iter().find(|id| **id != local.principal_id) {
                friend = db.friend_link_for_peer(peer)?;
                if friend.is_none() {
                    if let Some(commitment) = db
                        .client_record("identity", peer)?
                        .as_ref()
                        .and_then(|v| v["contact_identity_commitment"].as_str())
                    {
                        friend = db.friend_link_for_peer(commitment)?;
                    }
                }
            }
        }
        let mut history =
            self.task_history(&carrier.conversation_id, carrier.event()?.event().task_id())?;
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        history.events.push(AcceptedEvent {
            carrier: carrier.clone(),
            public_key: public,
            actor_kind_verified: false,
            received_at: crate::time::now_unix_timestamp(),
        });
        let mut principals = history
            .events
            .iter()
            .map(|e| e.carrier.principal_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        principals.remove(&local.principal_id);
        let mut manifests = Vec::new();
        for principal in principals {
            manifests.push(
                db.load_actor_state(&format!("identity/manifest/{principal}"))?
                    .ok_or_else(|| invalid("own task signer manifest missing"))?,
            );
        }
        let packet = TaskOwnPacket {
            context: OwnContext {
                conversation_id: carrier.conversation_id.clone(),
                participants,
                group,
                friend,
            },
            history,
            manifests,
        };
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(&packet)?);
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("own task history budget exceeded"));
        }
        Ok(bytes)
    }
    pub(crate) fn receive_task_own(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        group: Option<&str>,
        body: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(raw) = body.strip_prefix(PREFIX) else { return Ok(false) };
        if body.len() > 4 * 1024 * 1024 {
            return Err(invalid("own task history budget exceeded"));
        }
        let source = self
            .account_db()?
            .client_record("device", &entry.envelope.source_device_id)?
            .ok_or_else(|| invalid("own task source missing"))?;
        if source["principal_id"] != entry.envelope.source_principal_id {
            return Err(invalid("own task source owner mismatch"));
        }
        self.authorize_owned_surface_source(&source)?;
        let packet: TaskOwnPacket = ramflux_protocol::parse_i_json(raw)?;
        if packet.context.conversation_id != conversation
            || packet.context.group.as_ref().map(|g| g.group_id.as_str()) != group
            || packet.history.events.len() > 256
            || packet.manifests.len() > 64
        {
            return Err(invalid("own task history context or count mismatch"));
        }
        self.account_db()?.write_transaction(|| {
            self.import_surface_context(&packet.context, &entry.envelope.source_device_id)?;
            for manifest in &packet.manifests {
                crate::client::contact::verify_device_manifest(
                    manifest,
                    &manifest.principal_commitment,
                )?;
                self.persist_identity_directory(manifest)?;
            }
            let first =
                packet.history.events.first().ok_or_else(|| invalid("own task history empty"))?;
            let id = first.carrier.event()?.event().task_id().to_owned();
            let existing = self.task_history(conversation, &id)?;
            if existing.events.len() > packet.history.events.len() {
                return Ok(());
            }
            for (old, new) in existing.events.iter().zip(&packet.history.events) {
                if old.carrier.bytes()? != new.carrier.bytes()? {
                    return Err(invalid("own task history is not a causal extension"));
                }
            }
            for accepted in packet.history.events.iter().skip(existing.events.len()) {
                let carrier = &accepted.carrier;
                if carrier.conversation_id != conversation
                    || carrier.event()?.event().task_id() != id
                {
                    return Err(invalid("own task event context mismatch"));
                }
                if self.task_signer_key(&carrier.principal_id, &carrier.device_id)?
                    != accepted.public_key
                {
                    return Err(invalid("own task key differs from verified device"));
                }
                let timeline = super::timeline_id(carrier)?;
                let outcome = self
                    .project_task_message(
                        &Delivery {
                            conversation,
                            message: &timeline,
                            principal: &carrier.principal_id,
                            device: &carrier.device_id,
                            at: crate::time::now_unix_timestamp(),
                        },
                        &carrier.bytes()?,
                    )?
                    .ok_or_else(|| invalid("own task projection absent"))?;
                if !outcome.accepted {
                    return Err(invalid(
                        outcome.reject.unwrap_or_else(|| "own task event rejected".into()),
                    ));
                }
                if self.direct_message_by_id(&timeline)?.is_none() {
                    self.send_direct_message(conversation, &timeline, &carrier.device_id, &[])?;
                }
                self.account_db()?.replace_surface_message_content(
                    conversation,
                    &timeline,
                    outcome.fallback_text.as_bytes(),
                )?;
            }
            Ok::<_, SdkError>(())
        })?;
        Ok(true)
    }
}
