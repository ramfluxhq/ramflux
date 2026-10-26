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
    sender_id: String,
    context: OwnContext,
    body_base64: zeroize::Zeroizing<String>,
}
#[derive(Clone, Copy)]
pub(crate) struct OwnSentInput<'a> {
    pub envelope: &'a str,
    pub conversation: &'a str,
    pub message: &'a str,
    pub sender: &'a str,
    pub group: Option<&'a str>,
    pub peer: Option<&'a str>,
    pub body: &'a [u8],
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
        let packet = SentMessage {
            envelope_id: input.envelope.into(),
            message_id: input.message.into(),
            sender_id: input.sender.into(),
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
        crate::bus::own_device_copy::stage(
            self,
            super::own_device_copy::OwnMessageInput {
                id: input.envelope,
                created_at: input.at,
                conversation: input.conversation,
                group: input.group,
                body: &bytes,
            },
            Some(("message", input.message)),
        )?;
        Ok(())
    }
    pub(crate) fn already_projected_own_sent_message(
        &self,
        message: &DirectMessageRecord,
        content: Option<&[u8]>,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let Some(record) = db.load_actor_state::<serde_json::Value>(&sent_history_key(
            &message.conversation_id,
            &message.message_id,
            &message.sender_id,
        )?)?
        else {
            return Ok(false);
        };
        let Some(id) = record["id"].as_str() else { return Ok(false) };
        let Some(row) = self.direct_message_by_id(id)? else { return Ok(false) };
        Ok(row.conversation_id == message.conversation_id
            && db.message_content(id)?.as_deref() == content)
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
        if packet.envelope_id != envelope
            || packet.context.conversation_id != conversation
            || packet.context.group.as_ref().map(|g| g.group_id.as_str()) != group
            || packet.message_id.is_empty()
            || packet.message_id.len() > 256
            || packet.sender_id.is_empty()
            || packet.sender_id.len() > 256
        {
            return Err(invalid("own sent message context mismatch"));
        }
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
        // Physical row ids include the authenticated source and envelope. Logical ids may be
        // reused by another device; that must neither overwrite nor suppress its outgoing copy.
        let id = format!(
            "own:{}",
            super::own_device_copy::copy_id(
                source.root_commitment(),
                source.device_id(),
                envelope,
            )?
        );
        let db = self.account_db()?;
        db.import_direct_message_projection(DirectMessageWrite {
            conversation_id: conversation,
            message_id: &id,
            sender_id: source.device_id(),
            encrypted_body: &[],
            metadata: &MessageMetadata::default(),
            created_at: at,
        })?;
        db.store_message_content(conversation, &id, &body)?;
        db.persist_actor_state(
            &sent_history_key(conversation, &packet.message_id, &packet.sender_id)?,
            &json!({"id":id,"source":source.storage_key()}),
        )?;
        db.persist_actor_state(&super::delivery_receipts::origin_key(conversation, &id)?,
            &json!({"sender_device_id":source.device_id(),"sender_root_commitment":source.root_commitment(),
                "sender_device_display":source.storage_key(),"direction":"outgoing",
                "original_message_id":packet.message_id,"envelope_id":envelope}))?;
        Ok(true)
    }
}
fn invalid(message: &str) -> SdkError {
    SdkError::InboundRejected(message.into())
}

fn sent_history_key(conversation: &str, message: &str, sender: &str) -> Result<String, SdkError> {
    Ok(format!(
        "own-device/sent-history/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.own-sent-history.v1",
            &ramflux_protocol::canonical_json_bytes(&(conversation, message, sender))?,
        )
    ))
}
