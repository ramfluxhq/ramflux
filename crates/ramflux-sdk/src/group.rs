// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkGroupSenderKeyDistribution {
    pub schema: String,
    pub version: u32,
    pub group_id: String,
    pub sender_id: String,
    pub group_key_epoch: u64,
    pub sender_key_seed: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_device_signing_public_key: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkGroupSenderKeyDistributionEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) membership_event_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor_manifest_url: Option<String>,
    pub(crate) distribution_base64: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkGroupSenderKeyState {
    pub(crate) group_id: String,
    pub(crate) sender_id: String,
    pub(crate) group_key_epoch: u64,
    pub(crate) session_snapshot: ramflux_crypto::DmSessionSnapshot,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkGroupEncryptedEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) group_id: String,
    pub(crate) sender_id: String,
    pub(crate) group_key_epoch: u64,
    pub(crate) ciphertext: ramflux_crypto::DmCiphertext,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkGroupControlEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) event: ramflux_protocol::GroupEvent,
}

pub(crate) enum GroupGatewayDeliveryResult {
    Message(Vec<u8>),
    SenderKeyDistribution(SdkGroupSenderKeyDistribution),
}

pub(crate) struct SdkGroupPendingPlaintext {
    pub(crate) group_id: String,
    pub(crate) conversation_id: String,
    pub(crate) message_id: String,
    pub(crate) plaintext: Vec<u8>,
}

pub(crate) fn group_sender_key_checkpoint_name(
    group_id: &str,
    sender_id: &str,
    epoch: u64,
    direction: &str,
) -> String {
    format!("group_sender_key:{group_id}:{sender_id}:{epoch}:{direction}")
}

pub(crate) fn group_sender_session_id(group_id: &str, sender_id: &str, epoch: u64) -> String {
    format!("group:{group_id}:sender:{sender_id}:epoch:{epoch}")
}

pub(crate) fn group_sender_device_hash(group_id: &str, sender_id: &str, role: &str) -> [u8; 32] {
    ramflux_crypto::blake3_256(
        ramflux_protocol::domain::GROUP_SENDER_KEY_DISTRIBUTION,
        format!("{group_id}|{sender_id}|{role}").as_bytes(),
    )
}

pub(crate) fn group_sender_transcript_hash(
    group_id: &str,
    sender_id: &str,
    epoch: u64,
) -> [u8; 32] {
    ramflux_crypto::blake3_256(
        ramflux_protocol::domain::DM_RATCHET_ROOT,
        group_sender_session_id(group_id, sender_id, epoch).as_bytes(),
    )
}

pub(crate) fn group_sender_key_distribution_conversation_id(
    group_id: &str,
    sender_id: &str,
    recipient_device_id: &str,
) -> String {
    format!("group.sender_key.distribution:{group_id}:{sender_id}:{recipient_device_id}")
}

pub(crate) fn group_member_route_event_id(group_id: &str, member_id: &str) -> String {
    format!("group.member.route:{group_id}:{member_id}")
}

pub(crate) fn group_role_changed_event_id(
    group_id: &str,
    actor_device_id: &str,
    target_member_id: &str,
    new_group_epoch: u64,
) -> String {
    format!("group.role_changed:{group_id}:{actor_device_id}:{target_member_id}:{new_group_epoch}")
}

pub(crate) fn group_member_kicked_event_id(
    group_id: &str,
    actor_device_id: &str,
    target_member_id: &str,
    new_group_epoch: u64,
) -> String {
    format!("group.member_kicked:{group_id}:{actor_device_id}:{target_member_id}:{new_group_epoch}")
}

pub(crate) fn group_member_banned_event_id(
    group_id: &str,
    actor_device_id: &str,
    target_member_id: &str,
    new_group_epoch: u64,
) -> String {
    format!("group.member_banned:{group_id}:{actor_device_id}:{target_member_id}:{new_group_epoch}")
}

pub(crate) fn group_message_deleted_event_id(
    group_id: &str,
    actor_device_id: &str,
    target_message_id: &str,
    group_epoch: u64,
) -> String {
    format!("group.message_deleted:{group_id}:{actor_device_id}:{target_message_id}:{group_epoch}")
}

pub(crate) fn group_member_invited_event_id(
    group_id: &str,
    actor_device_id: &str,
    invitee_identity: &str,
    group_epoch: u64,
) -> String {
    format!("group.member_invited:{group_id}:{actor_device_id}:{invitee_identity}:{group_epoch}")
}

pub(crate) fn group_member_accepted_event_id(
    group_id: &str,
    invitee_identity: &str,
    invite_id: &str,
    new_group_epoch: u64,
) -> String {
    format!("group.member_accepted:{group_id}:{invitee_identity}:{invite_id}:{new_group_epoch}")
}

pub(crate) fn group_member_joined_event_id(
    group_id: &str,
    actor_device_id: &str,
    joined_identity: &str,
    new_group_epoch: u64,
) -> String {
    format!("group.member_joined:{group_id}:{actor_device_id}:{joined_identity}:{new_group_epoch}")
}

pub(crate) fn group_entry_is_sender_key_message(
    entry: &GatewayInboxEntry,
) -> Result<bool, SdkError> {
    let encrypted_body = ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)
        .map_err(|error| SdkError::LocalBus(format!("invalid group payload: {error}")))?;
    Ok(serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&encrypted_body)
        .is_ok_and(|envelope| envelope.schema == "ramflux.sdk.group_sender_key.message.v1"))
}

pub(crate) fn group_plaintext_json(
    conversation_id: &str,
    group_id: &str,
    message_id: &str,
    plaintext: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "conversation_id": conversation_id,
        "group_id": group_id,
        "message_id": message_id,
        "plaintext_body_base64": ramflux_protocol::encode_base64url(plaintext),
        "body_utf8": String::from_utf8_lossy(plaintext),
    })
}

pub(crate) fn is_missing_group_sender_key_error(error: &SdkError) -> bool {
    let message = error.to_string();
    message.contains("missing group sender key")
}

pub(crate) fn group_associated_data(group_id: &str, sender_id: &str, epoch: u64) -> Vec<u8> {
    format!("ramflux.group.sender_key.v1|{group_id}|{sender_id}|{epoch}").into_bytes()
}
