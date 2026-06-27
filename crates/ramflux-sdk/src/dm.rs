// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkDmEncryptedEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) x3dh: Option<SdkDmX3dhHeader>,
    pub(crate) ciphertext: ramflux_crypto::DmCiphertext,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkDmAttachmentEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) body_base64: String,
    pub(crate) attachments: Vec<SdkDmAttachmentRef>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkDmAttachmentRef {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) object_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) plaintext_hash: String,
    pub(crate) cipher_size: u64,
    pub(crate) chunk_size: usize,
    pub(crate) total_chunks: u32,
    pub(crate) relay_endpoint: String,
    pub(crate) key_slot: SdkObjectKeySlot,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkDmAttachmentImportResult {
    pub object_id: String,
    pub manifest_hash: String,
    pub plaintext_base64: String,
    pub plaintext_hash: String,
    pub imported: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkReceiptEventEnvelope {
    pub(crate) schema: String,
    pub(crate) version: u32,
    pub(crate) receipt_id: String,
    pub(crate) event_seq: u64,
    pub(crate) nonce: String,
    pub(crate) reader_device_id: String,
    pub(crate) event: SdkReceiptEventBody,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type")]
pub(crate) enum SdkReceiptEventBody {
    #[serde(rename = "ReceiptDelivered")]
    Delivered {
        conversation_id: String,
        message_id: String,
        delivered_at: i64,
        receiver_device_id: String,
        scope: String,
        ttl_seconds: u32,
    },
    #[serde(rename = "ReceiptReadPrivate")]
    ReadPrivate {
        conversation_id: String,
        message_id: String,
        reader_identity: String,
        read_at: i64,
        own_device_scope: String,
    },
    #[serde(rename = "ReceiptReadPublic")]
    ReadPublic {
        conversation_id: String,
        message_id: String,
        reader_identity: String,
        read_at: i64,
        visibility_scope: String,
        ttl_seconds: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_event_body_uses_explicit_private_read_variant() -> Result<(), serde_json::Error> {
        let envelope = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".to_owned(),
            version: 1,
            receipt_id: "receipt_read_test".to_owned(),
            event_seq: 7,
            nonce: "nonce".to_owned(),
            reader_device_id: "reader_device".to_owned(),
            event: SdkReceiptEventBody::ReadPrivate {
                conversation_id: "conv".to_owned(),
                message_id: "msg".to_owned(),
                reader_identity: "reader_device".to_owned(),
                read_at: 1_900_000_000,
                own_device_scope: "e2ee_private".to_owned(),
            },
        };
        let encoded = serde_json::to_vec(&envelope)?;
        let decoded: SdkReceiptEventEnvelope = serde_json::from_slice(&encoded)?;
        assert!(matches!(
            decoded.event,
            SdkReceiptEventBody::ReadPrivate {
                conversation_id,
                message_id,
                reader_identity,
                ..
            } if conversation_id == "conv"
                && message_id == "msg"
                && reader_identity == "reader_device"
        ));
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkDmX3dhHeader {
    pub initiator_identity_public: [u8; 32],
    pub initiator_ephemeral_public: [u8; 32],
    pub initiator_device_id_hash: [u8; 32],
    pub recipient_device_id_hash: [u8; 32],
    pub recipient_device_id: String,
    pub recipient_signed_prekey_id: String,
    pub recipient_one_time_prekey_id: Option<String>,
    pub prekey_bundle_hash: [u8; 32],
    pub bootstrap_transcript_hash: [u8; 32],
    pub session_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkX3dhPrivateState {
    pub(crate) device_id: String,
    pub(crate) identity_seed: [u8; 32],
    pub(crate) signed_prekey_id: String,
    pub(crate) signed_prekey_seed: [u8; 32],
    pub(crate) bundle: ramflux_crypto::PrekeyBundle,
}

pub(crate) fn gateway_cursor_checkpoint_name(target_delivery_id: &str) -> String {
    format!("gateway_cursor:{target_delivery_id}")
}

pub(crate) fn gateway_receive_cursor_checkpoint_name(target_delivery_id: &str) -> String {
    format!("gateway_receive_cursor:{target_delivery_id}")
}

pub(crate) fn dm_session_checkpoint_name(conversation_id: &str, direction: &str) -> String {
    format!("dm_session:{conversation_id}:{direction}")
}

pub(crate) fn dm_attachment_slot_conversation_id(
    conversation_id: &str,
    object_id: &str,
    recipient_device_id: &str,
) -> String {
    format!("dm.attachment.slot:{conversation_id}:{object_id}:{recipient_device_id}")
}

pub(crate) fn dm_device_id_hash(device_id: &str) -> [u8; 32] {
    ramflux_crypto::blake3_256(ramflux_protocol::domain::DEVICE_PROOF, device_id.as_bytes())
}
pub(crate) fn x3dh_private_checkpoint_name(device_id: &str) -> String {
    format!("x3dh_private:{device_id}")
}

pub(crate) fn x3dh_private_seed(domain: &str, device_seed: &[u8; 32]) -> [u8; 32] {
    ramflux_crypto::blake3_256(domain, device_seed)
}

pub(crate) fn prekey_bundle_hash(
    bundle: &ramflux_crypto::PrekeyBundle,
) -> Result<[u8; 32], SdkError> {
    let bytes = serde_json::to_vec(bundle)?;
    Ok(ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bytes))
}

pub(crate) fn dm_associated_data(conversation_id: &str) -> &[u8] {
    conversation_id.as_bytes()
}
pub(crate) fn gateway_ack(
    envelope_id: &str,
    receiver_device_id: &str,
    received_at: i64,
) -> Result<ramflux_protocol::Ack, SdkError> {
    let mut ack = ramflux_protocol::Ack {
        schema: "ramflux.ack.v1".to_owned(),
        version: 1,
        domain: "ramflux.ack.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_signed_fields(""),
        ack_id: format!("ack_{envelope_id}_{receiver_device_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: receiver_device_id.to_owned(),
        received_at,
        cursor_after: None,
    };
    ack.signed.signature = ramflux_crypto::sign_protocol_object(&ack)?;
    Ok(ack)
}

pub(crate) fn gateway_direct_message_envelope(
    config: &GatewaySessionConfig,
    message: &GatewayDirectMessage,
) -> Result<ramflux_protocol::Envelope, SdkError> {
    let encrypted_payload = ramflux_protocol::encode_base64url(&message.encrypted_body);
    let payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        encrypted_payload.as_bytes(),
    );
    let mut envelope = ramflux_protocol::Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.envelope.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: sdk_signed_fields(""),
        envelope_id: message.envelope_id.clone(),
        source_principal_id: message.source_principal_id.clone(),
        source_device_id: config.device_id.clone(),
        target_delivery_id: message.target_delivery_id.clone(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: message.ttl,
        created_at: message.created_at,
        encrypted_payload,
        payload_hash,
    };
    envelope.signed.signature = ramflux_crypto::sign_protocol_object(&envelope)?;
    Ok(envelope)
}

pub(crate) fn dedup_gateway_entries(entries: Vec<GatewayInboxEntry>) -> Vec<GatewayInboxEntry> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for entry in entries {
        if seen.insert(entry.envelope.envelope_id.clone()) {
            deduped.push(entry);
        }
    }
    deduped
}

pub(crate) fn a2i_control_conversation_id(
    source_device_id: &str,
    target_device_id: &str,
) -> String {
    format!("a2i.control:{source_device_id}:{target_device_id}")
}
