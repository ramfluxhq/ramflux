// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Outgoing timeline replicas inside authenticated, pair-encrypted own-device controls.
use super::surface::OwnContext;
use crate::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

const PREFIX: &[u8] = b"ramflux.own_sent_message.v1\n";
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
        if self.envelope_id != envelope
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
    pub(crate) fn stage_own_sent_message(&self, input: OwnSentInput<'_>) -> Result<(), SdkError> {
        // Structured controls have their own signed projection and causal replay rules.
        if super::surface::Carrier::decode(input.body)?.is_some()
            || super::task::carrier::Carrier::decode(input.body)?.is_some()
        {
            return Ok(());
        }
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
        let ciphertext_hash = own_sent_ciphertext_hash(input.ciphertext);
        let packet = SentMessage {
            authored_at: Some(input.at),
            envelope_id: input.envelope.into(),
            message_id: input.message.into(),
            sender_id: input.sender.into(),
            original_recipients: input.original_recipients.to_vec(),
            ciphertext_hash: Some(ciphertext_hash.clone()),
            context: OwnContext {
                conversation_id: input.conversation.into(),
                participants,
                group,
                friend,
            },
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(input.body)),
        };
        let mut bytes = zeroize::Zeroizing::new(PREFIX.to_vec());
        bytes.extend(serde_json::to_vec(&packet)?);
        crate::bus::own_device_copy::stage_held(
            self,
            super::own_device_copy::OwnMessageInput {
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
            Some(&ciphertext_hash),
        )?;
        Ok(())
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
        db.persist_actor_state(&key, &id)?;
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
        db.persist_actor_state(&super::delivery_receipts::origin_key(input.conversation, id)?,
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
        db.persist_actor_state(&alias_key(&own_row_id(source, envelope)?), &id)?;
        if let Some(hash) = ciphertext_hash {
            let key = ciphertext_index_key(hash);
            let existing = db.load_actor_state::<serde_json::Value>(&key)?;
            let value = if existing.as_ref().is_some_and(|old| {
                old["id"] != id
                    || old["source"] != source.storage_key()
                    || old["envelope_id"] != envelope
            }) {
                // History without an authenticated per-row source must never select one of
                // several claimants to the same ciphertext. Exact source/envelope aliases remain.
                json!({"ambiguous":true})
            } else {
                json!({"id":id,"source":source.storage_key(),"envelope_id":envelope})
            };
            db.persist_actor_state(&key, &value)?;
        }
        Ok(())
    }
    pub(super) fn index_imported_own_sent_ciphertext(
        &self,
        message: &DirectMessageRecord,
    ) -> Result<(), SdkError> {
        if message.encrypted_body.is_empty() {
            return Ok(());
        }
        let db = self.account_db()?;
        let key = imported_ciphertext_key(&own_sent_ciphertext_hash(&message.encrypted_body));
        let old = db.load_actor_state::<serde_json::Value>(&key)?;
        let record = if old.as_ref().is_some_and(|row| {
            row["id"] != message.message_id || row["conversation"] != message.conversation_id
        }) {
            json!({"ambiguous":true})
        } else {
            json!({"id":message.message_id,"conversation":message.conversation_id})
        };
        db.persist_actor_state(&key, &record)?;
        Ok(())
    }
    pub(crate) fn already_projected_own_sent_message(
        &self,
        message: &DirectMessageRecord,
        content: Option<&[u8]>,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let alias = db.load_actor_state::<String>(&alias_key(&message.message_id))?;
        let digest = (!message.encrypted_body.is_empty())
            .then(|| own_sent_ciphertext_hash(&message.encrypted_body));
        let indexed = digest
            .as_deref()
            .map(|hash| db.load_actor_state::<serde_json::Value>(&ciphertext_index_key(hash)))
            .transpose()?
            .flatten();
        let Some(id) = alias.as_deref().or_else(|| indexed.as_ref().and_then(|v| v["id"].as_str()))
        else {
            return Ok(false);
        };
        let Some(row) = self.direct_message_by_id(id)? else { return Ok(false) };
        Ok(row.conversation_id == message.conversation_id
            && (row.deleted || db.message_content(id)?.as_deref() == content))
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
        } = input;
        let Some(bytes) = bytes.strip_prefix(PREFIX) else { return Ok(false) };
        let packet: SentMessage = ramflux_protocol::parse_i_json(bytes)?;
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
        self.import_surface_context(&packet.context, source.device_id())?;
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
        let known = db.load_actor_state::<String>(&alias_key(&own_row_id(source, envelope)?))?;
        let imported = packet
            .ciphertext_hash
            .as_deref()
            .map(|hash| db.load_actor_state::<serde_json::Value>(&imported_ciphertext_key(hash)))
            .transpose()?
            .flatten()
            .filter(|record| record["conversation"] == conversation);
        let imported_id = imported.as_ref().and_then(|record| record["id"].as_str());
        let candidate = self
            .direct_message_by_id(known.as_deref().or(imported_id).unwrap_or(&packet.message_id))?;
        let history = if let Some(row) = candidate.as_ref() {
            let origin = self.message_origin(conversation, &row.message_id)?;
            row.conversation_id == conversation
                && origin.as_ref().map_or_else(
                    || {
                        known.as_deref() == Some(row.message_id.as_str())
                            || imported_id == Some(row.message_id.as_str())
                            || (!row.encrypted_body.is_empty()
                                && packet.ciphertext_hash.as_deref()
                                    == Some(own_sent_ciphertext_hash(&row.encrypted_body).as_str()))
                    },
                    |v| {
                        v["sender_root_commitment"] == source.root_commitment()
                            && v["sender_device_id"] == source.device_id()
                            && v["envelope_id"] == envelope
                    },
                )
                && (row.deleted
                    || db.message_content(&row.message_id)?.as_deref() == Some(body.as_slice()))
        } else {
            false
        };
        // An authenticated source/envelope gets its own id unless the exact authored row was
        // already imported by history. Provenance prevents another device's row being merged.
        let id = if history {
            candidate.as_ref().ok_or_else(|| invalid("own history row absent"))?.message_id.clone()
        } else {
            own_row_id(source, envelope)?
        };
        if !history {
            db.import_direct_message_projection(DirectMessageWrite {
                conversation_id: conversation,
                message_id: &id,
                sender_id: source.device_id(),
                encrypted_body: &[],
                metadata: &MessageMetadata::default(),
                created_at: packet.authored_at.unwrap_or(at),
            })?;
        }
        if history && candidate.as_ref().is_some_and(|row| row.deleted) {
            // Keep authenticated replay aliases without restoring deleted content or attribution.
            self.index_own_sent_projection(
                source,
                envelope,
                &id,
                packet.ciphertext_hash.as_deref(),
            )?;
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
            packet.ciphertext_hash.as_deref(),
        )?;
        Ok(true)
    }
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

pub(super) fn own_sent_ciphertext_hash(ciphertext: &[u8]) -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.own-sent-ciphertext.v1", ciphertext)
}
fn ciphertext_index_key(hash: &str) -> String {
    format!("own-device/sent-ciphertext/{hash}")
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
fn alias_key(message: &str) -> String {
    format!("own-device/sent-alias/{message}")
}

fn imported_ciphertext_key(hash: &str) -> String {
    format!("own-device/imported-ciphertext/{hash}")
}
