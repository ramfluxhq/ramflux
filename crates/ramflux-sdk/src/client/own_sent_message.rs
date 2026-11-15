// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Outgoing timeline replicas inside authenticated, pair-encrypted own-device controls.
use super::surface::OwnContext;
use crate::prelude::*;
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};
use serde_json::json;

mod attestation;
pub(crate) mod authored;
mod generated;
mod replay;
mod unsupported;

use prost::Message as _;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SentMessage {
    envelope_id: String,
    message_id: String,
    // An authored display label, never a device identity or replay key.
    sender_id: String,
    #[serde(default)]
    original_recipients: Vec<String>,
    #[serde(default)]
    ciphertext_hash: Option<String>,
    context: OwnContext,
    #[serde(default)]
    authored_at: Option<i64>,
    body_base64: zeroize::Zeroizing<String>,
}
impl SentMessage {
    fn validate_route(
        &self,
        envelope: &str,
        conversation: &str,
        group: Option<&str>,
    ) -> Result<(), SdkError> {
        if self.context.group.is_some() {
            ramflux_protocol::message::dm_scope::validate_group(&self.context.conversation_id)
                .map_err(|_| invalid("reserved DM conversation namespace"))?;
        }
        if self.envelope_id.is_empty()
            || self.envelope_id.len() > 256
            || self.envelope_id != envelope
            || self.context.conversation_id != conversation
            || self.context.group.as_ref().map(|g| g.group_id.as_str()) != group
            || self.message_id.is_empty()
            || self.message_id.len() > 256
            || self.sender_id.is_empty()
            || self.sender_id.len() > 256
            || self.original_recipients.len() > 4096
            || self.original_recipients.iter().any(|id| id.is_empty() || id.len() > 256)
        {
            return Err(invalid("own sent message context mismatch"));
        }
        if let Some(hash) = &self.ciphertext_hash
            && ramflux_protocol::decode_base64url(hash).map_or(true, |bytes| bytes.len() != 32)
        {
            return Err(invalid("invalid own sent ciphertext digest"));
        }
        Ok(())
    }
}

impl SentMessage {
    fn to_generated(&self) -> Result<g::OwnSentMessage, SdkError> {
        let body = ramflux_protocol::decode_base64url(&self.body_base64)
            .map_err(|_| invalid("invalid own sent message body encoding"))?;
        let ciphertext_digest = self
            .ciphertext_hash
            .as_deref()
            .map(|hash| {
                let raw = ramflux_protocol::decode_base64url(hash)
                    .map_err(|_| invalid("invalid own sent ciphertext digest"))?;
                if raw.len() != 32 {
                    return Err(invalid("invalid own sent ciphertext digest"));
                }
                Ok(raw)
            })
            .transpose()?;
        Ok(g::OwnSentMessage {
            envelope_id: self.envelope_id.clone(),
            message_id: self.message_id.clone(),
            sender_id: self.sender_id.clone(),
            original_recipients: self.original_recipients.clone(),
            ciphertext_digest,
            context: Some(g::OwnContext::try_from(&self.context)?),
            authored_at: self.authored_at,
            exact_inner: body,
        })
    }

    fn from_generated(sent: &g::OwnSentMessage) -> Result<Self, SdkError> {
        if sent.ciphertext_digest.as_ref().is_some_and(|digest| digest.len() != 32) {
            return Err(invalid("invalid own sent ciphertext digest"));
        }
        Ok(Self {
            envelope_id: sent.envelope_id.clone(),
            message_id: sent.message_id.clone(),
            sender_id: sent.sender_id.clone(),
            original_recipients: sent.original_recipients.clone(),
            ciphertext_hash: sent
                .ciphertext_digest
                .as_deref()
                .map(ramflux_protocol::encode_base64url),
            context: sent
                .context
                .as_ref()
                .map(OwnContext::try_from)
                .transpose()?
                .ok_or_else(|| invalid("own sent message context mismatch"))?,
            authored_at: sent.authored_at,
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(
                &sent.exact_inner,
            )),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OwnSentInput<'a> {
    pub envelope: &'a str,
    pub conversation: &'a str,
    pub message: &'a str,
    pub sender: &'a str,
    pub original_recipients: &'a [String],
    pub group: Option<&'a str>,
    pub peer: Option<&'a str>,
    pub body: &'a [u8],
    pub ciphertext: &'a [u8],
    pub at: i64,
}
impl RamfluxClient {
    pub(crate) fn stage_authored_mutation_copy(
        &self,
        input: OwnSentInput<'_>,
    ) -> Result<(), SdkError> {
        let (identity, content) = Self::decode_generated_inner(input.body)?;
        let owner = match content.value.as_ref() {
            Some(g::content::Value::Delete(_)) => input.message.to_owned(),
            Some(g::content::Value::Reaction(reaction)) => ramflux_protocol::encode_base64url(
                &reaction
                    .target
                    .as_ref()
                    .ok_or_else(|| invalid("authored reaction target missing"))?
                    .id,
            ),
            _ => return Err(invalid("authored mutation copy requires Delete or Reaction")),
        };
        if ramflux_protocol::encode_base64url(&identity.id) != input.message {
            return Err(invalid("authored mutation copy requires its exact generated event"));
        }
        let packet = self.own_sent_packet(input)?;
        let bytes = zeroize::Zeroizing::new(packet.to_generated()?.encode_to_vec());
        // The local mutation and its copy commit together. Siblings must learn the
        // committed erasure even when the peer gateway acknowledgement is lost.
        crate::bus::own_device_copy::stage(
            self,
            super::own_device_copy::OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Sent,
                id: input.envelope,
                created_at: now_unix_timestamp(),
                conversation: input.conversation,
                group: input.group,
                body: &bytes,
            },
            Some(("message", owner.as_str())),
        )?;
        // A mutation has no timeline row and cannot own a message replay alias.
        // Its qualified event, source marker and own-copy logical replay guard
        // provide idempotency without inventing a second displayed message.
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn stage_own_sent_message(&self, input: OwnSentInput<'_>) -> Result<(), SdkError> {
        // Structured controls have their own signed projection and causal replay rules.
        if super::surface::Carrier::decode(input.body)?.is_some()
            || super::task::carrier::Carrier::decode(input.body)?.is_some()
        {
            return Ok(());
        }
        let packet = self.own_sent_packet(input)?;
        let bytes = zeroize::Zeroizing::new(packet.to_generated()?.encode_to_vec());
        crate::bus::own_device_copy::stage_held(
            self,
            super::own_device_copy::OwnMessageInput {
                payload_kind: crate::client::own_device_copy::OwnPayloadKind::Sent,
                id: input.envelope,
                created_at: now_unix_timestamp(),
                conversation: input.conversation,
                group: input.group,
                body: &bytes,
            },
            input.message,
        )?;
        self.record_own_sent_projection(
            &self.owned_device_identity()?,
            input,
            input.message,
            packet.ciphertext_hash.as_deref(),
        )?;
        Ok(())
    }
    fn own_sent_packet(&self, input: OwnSentInput<'_>) -> Result<SentMessage, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let db = self.account_db()?;
        let group = input
            .group
            .map(|id| {
                self.own_device_group_snapshot(id, &local.device_id)?
                    .ok_or_else(|| invalid("own-device group access unavailable"))
            })
            .transpose()?;
        let participants = if let Some(peer) = input.peer {
            vec![local.principal_id.clone(), peer.to_owned()]
        } else {
            Vec::new()
        };
        let friend = input
            .peer
            .filter(|_| input.original_recipients.is_empty())
            .map(|peer| {
                let direct = db.friend_link_for_peer(peer)?;
                if direct.is_some() {
                    return Ok::<_, SdkError>(direct);
                }
                let identity = db.client_record("identity", peer)?;
                identity
                    .as_ref()
                    .and_then(|v| v["contact_identity_commitment"].as_str())
                    .map(|root| db.friend_link_for_peer(root))
                    .transpose()
                    .map(Option::flatten)
                    .map_err(Into::into)
            })
            .transpose()?
            .flatten();
        let ciphertext_hash =
            (!input.ciphertext.is_empty()).then(|| own_sent_ciphertext_hash(input.ciphertext));
        let packet = SentMessage {
            authored_at: Some(input.at),
            envelope_id: input.envelope.into(),
            message_id: input.message.into(),
            sender_id: input.sender.into(),
            original_recipients: input.original_recipients.to_vec(),
            ciphertext_hash,
            context: OwnContext {
                conversation_id: input.conversation.into(),
                participants,
                group,
                friend,
            },
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(input.body)),
        };
        Ok(packet)
    }

    pub(crate) fn own_group_copy_envelope(
        &self,
        group: &str,
        conversation: &str,
        message: &str,
        explicit: Option<&str>,
    ) -> Result<String, SdkError> {
        if let Some(id) = explicit {
            return Ok(id.into());
        }
        let scope = ramflux_protocol::canonical_json_bytes(&(
            self.owned_device_identity()?.storage_key(),
            group,
            conversation,
            message,
        ))?;
        let key = format!(
            "own-device/group-envelope/{}",
            ramflux_crypto::blake3_256_base64url("ramflux.own-group-envelope.v1", &scope)
        );
        let db = self.account_db()?;
        if let Some(id) = db.load_actor_state::<String>(&key)? {
            return Ok(id);
        }
        let id = crate::new_surface_message_id()?;
        db.persist_message_actor_state(message, &key, &id)?;
        Ok(id)
    }
    fn record_own_sent_projection(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        input: OwnSentInput<'_>,
        id: &str,
        ciphertext_hash: Option<&str>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        self.index_own_sent_projection(source, input.envelope, id, ciphertext_hash)?;
        db.persist_message_actor_state(id, &super::delivery_receipts::origin_key(input.conversation, id)?,
            &json!({"sender_device_id":source.device_id(),"sender_root_commitment":source.root_commitment(),
                "sender_device_display":source.storage_key(),"direction":"outgoing",
                "original_message_id":input.message,"envelope_id":input.envelope}))?;
        Ok(())
    }
    pub(super) fn index_own_sent_projection(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &str,
        id: &str,
        ciphertext_hash: Option<&str>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.persist_message_replay_reference(
            &alias_key(db, &own_row_id(source, envelope)?)?,
            Some(id),
            None,
            None,
        )?;
        if let Some(hash) = ciphertext_hash {
            let key = ciphertext_index_key(db, hash)?;
            let binding = db.own_sent_replay_claim(source, envelope)?;
            let existing = db.load_actor_state::<ramflux_storage::MessageReplayReference>(&key)?;
            let ambiguous = existing.as_ref().is_some_and(|old| {
                old.message_id() != Some(id) || old.binding() != Some(binding.as_str())
            });
            db.persist_message_replay_reference(
                &key,
                (!ambiguous).then_some(id),
                (!ambiguous).then_some(binding.as_str()),
                None,
            )?;
        }
        Ok(())
    }
    pub(super) fn own_sent_receipt_owner(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &str,
    ) -> Result<Option<String>, SdkError> {
        let db = self.account_db()?;
        Ok(db
            .load_actor_state::<ramflux_storage::MessageReplayReference>(&alias_key(
                db,
                &own_row_id(source, envelope)?,
            )?)?
            .and_then(|reference| reference.message_id().map(str::to_owned)))
    }

    pub(crate) fn own_original_recipient(
        &self,
        message: &GatewayDirectMessage,
    ) -> Result<Vec<String>, SdkError> {
        if message.recipient_principal_commitment.as_deref()
            == Some(self.owned_device_identity()?.root_commitment())
        {
            return Ok(vec![
                message.recipient_device_id.clone().ok_or(SdkError::IdentityRootMissing)?,
            ]);
        }
        Ok(Vec::new())
    }
    pub(crate) fn own_sent_peer(&self, message: &GatewayDirectMessage) -> Result<String, SdkError> {
        let reference = Self::qualified_recipient(message)?;
        self.account_db()?
            .client_record("device", &reference)?
            .and_then(|v| v["principal_id"].as_str().map(str::to_owned))
            .ok_or_else(|| invalid("own-device direct peer unavailable"))
    }
    #[cfg(test)]
    pub(super) fn receive_own_sent_message(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        input: super::own_device_copy::OwnMessageInput<'_>,
    ) -> Result<bool, SdkError> {
        let super::own_device_copy::OwnMessageInput {
            id: envelope,
            conversation,
            group,
            created_at: at,
            body: bytes,
            ..
        } = input;
        if g::validation::scan_message("OwnSentMessage", bytes, g::registry::COMPILED_LAYER)
            .is_err()
        {
            return Ok(false);
        }
        let generated =
            g::OwnSentMessage::decode(bytes).map_err(|_| invalid("invalid own sent message"))?;
        let packet = SentMessage::from_generated(&generated)?;
        self.apply_own_sent_packet(source, envelope, conversation, group, at, &packet)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn apply_own_sent_packet(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &str,
        conversation: &str,
        group: Option<&str>,
        at: i64,
        packet: &SentMessage,
    ) -> Result<bool, SdkError> {
        packet.validate_route(envelope, conversation, group)?;
        let body = zeroize::Zeroizing::new(
            ramflux_protocol::decode_base64url(&packet.body_base64)
                .map_err(|_| invalid("invalid own sent message body encoding"))?,
        );
        if super::surface::Carrier::decode(&body)?.is_some()
            || super::task::carrier::Carrier::decode(&body)?.is_some()
        {
            return Err(invalid("structured own message requires signed control projection"));
        }
        self.import_surface_context(&packet.context)?;
        if let Some(group) = group {
            self.merge_routed_group_link(group, conversation)?;
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if packet.original_recipients.contains(&local.device_id) {
            // The original pair/group delivery owns the timeline row. Still consume this
            // authenticated control so its key-slot ratchet advances and later copies progress.
            return Ok(true);
        }
        let db = self.account_db()?;
        let ciphertext_hash = packet.ciphertext_hash.as_deref();
        let alias = db.load_actor_state::<ramflux_storage::MessageReplayReference>(&alias_key(
            db,
            &own_row_id(source, envelope)?,
        )?)?;
        let alias_deleted = matches!(
            alias,
            Some(ramflux_storage::MessageReplayReference::Target { deleted: true, .. })
        );
        let history = self.own_sent_history_row(source, packet, envelope, conversation, &body)?;
        // Authenticated source/envelope aliases remain authoritative after attribution erasure.
        let id = if let Some(row) = &history {
            row.message_id.clone()
        } else if let Some(id) =
            alias.as_ref().and_then(ramflux_storage::MessageReplayReference::message_id)
        {
            id.to_owned()
        } else {
            own_row_id(source, envelope)?
        };
        if history.is_none() {
            if alias_deleted {
                db.import_deleted_message_projection(
                    conversation,
                    &id,
                    true,
                    packet.authored_at.unwrap_or(at),
                )?;
            } else {
                db.import_direct_message_projection(DirectMessageWrite {
                    conversation_id: conversation,
                    message_id: &id,
                    sender_id: source.device_id(),
                    encrypted_body: &[],
                    metadata: &MessageMetadata::default(),
                    created_at: packet.authored_at.unwrap_or(at),
                })?;
            }
        }
        if history.as_ref().is_some_and(|row| row.deleted) || alias_deleted {
            // Keep authenticated replay aliases without restoring deleted content or attribution.
            self.index_own_sent_projection(source, envelope, &id, ciphertext_hash)?;
            return Ok(true);
        }
        db.store_message_content(conversation, &id, &body)?;
        self.record_own_sent_projection(
            source,
            OwnSentInput {
                envelope,
                conversation,
                message: &packet.message_id,
                sender: &packet.sender_id,
                original_recipients: &packet.original_recipients,
                group,
                peer: None,
                body: &body,
                ciphertext: &[],
                at,
            },
            &id,
            ciphertext_hash,
        )?;
        Ok(true)
    }
    #[cfg(test)]
    fn own_sent_history_row(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        packet: &SentMessage,
        envelope: &str,
        conversation: &str,
        body: &[u8],
    ) -> Result<Option<DirectMessageRecord>, SdkError> {
        let db = self.account_db()?;
        if let Some(row) = self.direct_message_by_id(&packet.message_id)?
            && row.conversation_id == conversation
            && row.is_own
            && row.deleted
        {
            return Ok(Some(row));
        }
        let known = db
            .load_actor_state::<ramflux_storage::MessageReplayReference>(&alias_key(
                db,
                &own_row_id(source, envelope)?,
            )?)?
            .and_then(|reference| reference.message_id().map(str::to_owned));
        let hash = packet.ciphertext_hash.as_deref();
        let Some(row) =
            self.direct_message_by_id(known.as_deref().unwrap_or(&packet.message_id))?
        else {
            return Ok(None);
        };
        if row.conversation_id != conversation {
            return Ok(None);
        }
        let source_matches =
            if let Some(origin) = self.message_origin(conversation, &row.message_id)? {
                origin["sender_root_commitment"] == source.root_commitment()
                    && origin["sender_device_id"] == source.device_id()
                    && origin["envelope_id"] == envelope
            } else if known.as_deref() == Some(row.message_id.as_str()) {
                true
            } else {
                let claim = hash
                    .map(|hash| {
                        db.load_actor_state::<ramflux_storage::MessageReplayReference>(
                            &ciphertext_index_key(db, hash)?,
                        )
                    })
                    .transpose()?
                    .flatten();
                let expected = db.own_sent_replay_claim(source, envelope)?;
                // An imported digest must not override an authenticated source or an ambiguity fence.
                claim.as_ref().is_none_or(|claim| {
                    claim.message_id() == Some(row.message_id.as_str())
                        && claim.binding() == Some(expected.as_str())
                }) && !row.encrypted_body.is_empty()
                    && hash == Some(own_sent_ciphertext_hash(&row.encrypted_body).as_str())
            };
        if source_matches
            && (row.deleted || db.message_content(&row.message_id)?.as_deref() == Some(body))
        {
            Ok(Some(row))
        } else {
            Ok(None)
        }
    }
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

pub(super) fn own_sent_ciphertext_hash(ciphertext: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.own-sent-ciphertext.v1", ciphertext)
}
fn ciphertext_index_key(
    db: &ramflux_storage::AccountDb,
    hash: &str,
) -> Result<String, ramflux_storage::StorageError> {
    Ok(format!("own-device/sent-ciphertext/{}", db.own_sent_index_digest("ciphertext", hash)?))
}

fn own_row_id(
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &str,
) -> Result<String, SdkError> {
    Ok(format!(
        "routed:own:{}",
        super::own_device_copy::copy_id(source.root_commitment(), source.device_id(), envelope)?
    ))
}
fn alias_key(
    db: &ramflux_storage::AccountDb,
    message: &str,
) -> Result<String, ramflux_storage::StorageError> {
    Ok(format!("own-device/sent-alias/{}", db.own_sent_index_digest("alias", message)?))
}

#[cfg(test)]
#[path = "own_sent_history_tests.rs"]
mod history_tests;
