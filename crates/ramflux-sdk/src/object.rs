// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkObjectKeySlot {
    pub schema: String,
    pub version: u32,
    pub object_id: String,
    pub conversation_id: String,
    pub recipient_device_id: String,
    pub x3dh: Option<SdkDmX3dhHeader>,
    pub ciphertext: ramflux_crypto::DmCiphertext,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SdkObjectSharePackage {
    pub schema: String,
    pub version: u32,
    pub object: EncryptedObject,
    pub ciphertext_base64: String,
    pub key_slot: SdkObjectKeySlot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SdkObjectRelayCapability {
    Put,
    Get,
    Ack,
    Tombstone,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum SdkRelayChunkStatus {
    Available,
    Expired,
    AckedDeleted,
    Tombstoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkRelayToken {
    pub token_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub issuer_service: String,
    pub capabilities: Vec<SdkObjectRelayCapability>,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub mac: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectPermissionEnvelope {
    pub object_id: String,
    pub manifest_hash: String,
    pub grantee_device_hash: String,
    pub capability: SdkObjectRelayCapability,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectChunkFrame {
    pub schema: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_id: String,
    pub chunk_cipher_hash: String,
    pub cipher_size: u64,
    pub encrypted_chunk: Vec<u8>,
    pub relay_token: SdkRelayToken,
    pub object_permission_envelope: SdkObjectPermissionEnvelope,
    pub expires_at: u64,
    pub delete_after_ack: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkRelayChunkEntry {
    pub chunk_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_cipher_hash: String,
    pub encrypted_chunk: Vec<u8>,
    pub stored_at: u64,
    pub expires_at: u64,
    pub delete_after_ack: bool,
    pub acked_by: BTreeSet<String>,
    pub status: SdkRelayChunkStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectRelayPutResponse {
    pub chunk_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub expires_at: u64,
    pub status: SdkRelayChunkStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectRelayGetRequest {
    pub chunk_id: String,
    pub relay_token: SdkRelayToken,
    pub object_permission_envelope: SdkObjectPermissionEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectRelayGetResponse {
    pub chunk: SdkRelayChunkEntry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectRelayAck {
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub relay_token: SdkRelayToken,
    pub object_permission_envelope: SdkObjectPermissionEnvelope,
    pub acked_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectRelayAckResponse {
    pub chunk_id: String,
    pub status: SdkRelayChunkStatus,
    pub acked_by_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SdkObjectTransferStatus {
    pub transfer_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub direction: String,
    pub state: String,
    pub total_bytes: u64,
    pub done_bytes: u64,
    pub total_chunks: u32,
    pub completed_chunks: usize,
    pub next_chunk_index: Option<u32>,
    pub percent: u32,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct RelayTransferOptions {
    pub relay_endpoint: String,
    pub relay_service_key: Vec<u8>,
    pub interrupt_after_chunks: Option<u32>,
}

pub(crate) const OBJECT_TRANSFER_UPLOAD: &str = "upload";
pub(crate) const OBJECT_TRANSFER_DOWNLOAD: &str = "download";

pub(crate) fn object_key_slot_associated_data(
    object_id: &str,
    conversation_id: &str,
    recipient_device_id: &str,
) -> Vec<u8> {
    format!("ramflux.object_key_slot.v1|{object_id}|{conversation_id}|{recipient_device_id}")
        .into_bytes()
}
pub(crate) fn object_chunks(object: &EncryptedObject, chunk_size: usize) -> Vec<serde_json::Value> {
    let chunk_size = chunk_size.max(1);
    object
        .ciphertext
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            serde_json::json!({
                "index": index,
                "ciphertext_base64": ramflux_protocol::encode_base64url(chunk),
                "chunk_cipher_hash": ramflux_crypto::blake3_256_base64url(
                    ramflux_protocol::domain::OBJECT,
                    chunk,
                ),
            })
        })
        .collect()
}

pub(crate) fn object_relay_chunk_id(
    object_id: &str,
    manifest_hash: &str,
    chunk_index: u32,
) -> String {
    format!("object-relay:{object_id}:{manifest_hash}:{chunk_index}")
}

pub(crate) fn object_transfer_id(object_id: &str, manifest_hash: &str, direction: &str) -> String {
    format!("{direction}:{object_id}:{manifest_hash}")
}

pub(crate) fn object_transfer_status(record: ObjectTransferRecord) -> SdkObjectTransferStatus {
    let percent = record
        .done_bytes
        .saturating_mul(100)
        .checked_div(record.total_bytes)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    SdkObjectTransferStatus {
        transfer_id: record.transfer_id,
        object_id: record.object_id,
        manifest_hash: record.manifest_hash,
        direction: record.direction,
        state: record.state,
        total_bytes: record.total_bytes,
        done_bytes: record.done_bytes,
        total_chunks: record.total_chunks,
        completed_chunks: record.completed_chunks.len(),
        next_chunk_index: record.next_chunk_index,
        percent,
        last_error: record.last_error,
        updated_at: record.updated_at,
    }
}

pub(crate) fn parse_relay_transfer_options(
    relay_endpoint: Option<String>,
    relay_service_key_base64: Option<String>,
    interrupt_after_chunks: Option<u32>,
) -> Result<Option<RelayTransferOptions>, SdkError> {
    let Some(relay_endpoint) = relay_endpoint else {
        return Ok(None);
    };
    let key = relay_service_key_base64
        .or_else(|| std::env::var("RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64").ok())
        .ok_or_else(|| SdkError::LocalBus("object relay service key is required".to_owned()))?;
    let relay_service_key = ramflux_protocol::decode_base64url(&key)
        .or_else(|_| Ok::<Vec<u8>, ramflux_protocol::ProtocolError>(key.into_bytes()))
        .map_err(|error| {
            SdkError::LocalBus(format!("invalid object relay service key: {error}"))
        })?;
    Ok(Some(RelayTransferOptions { relay_endpoint, relay_service_key, interrupt_after_chunks }))
}

pub(crate) fn object_relay_chunk_cipher_hash(
    manifest_hash: &str,
    chunk_index: u32,
    encrypted_chunk: &[u8],
) -> String {
    ramflux_sync::chunk_cipher_hash(manifest_hash, chunk_index, encrypted_chunk)
}

pub(crate) fn relay_token_mac(
    service_key: &[u8],
    token: &SdkRelayToken,
) -> Result<String, SdkError> {
    let mut canonical = token.clone();
    canonical.mac.clear();
    let mut mac = HmacSha256::new_from_slice(service_key)
        .map_err(|source| SdkError::LocalBus(source.to_string()))?;
    mac.update(&ramflux_protocol::canonical_json_bytes(&canonical)?);
    Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
}

pub(crate) fn object_permission_signature(
    permission: &SdkObjectPermissionEnvelope,
    branch: &DeviceBranch,
) -> Result<String, SdkError> {
    let mut canonical = permission.clone();
    canonical.owner_signature.clear();
    Ok(ramflux_crypto::sign_protocol_object_with_device_branch(branch, &canonical)?)
}

pub(crate) fn relay_token_for_chunk(
    service_key: &[u8],
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    capability: SdkObjectRelayCapability,
    expires_at: u64,
) -> Result<SdkRelayToken, SdkError> {
    let owner_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let now = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let mut token = SdkRelayToken {
        token_id: format!("token:{chunk_id}:{capability:?}"),
        object_id: object.object_id.clone(),
        manifest_hash: object.manifest_hash.clone(),
        chunk_id,
        recipient_device_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            branch.device_id.as_bytes(),
        ),
        owner_signing_key_id: branch.device_id.clone(),
        owner_public_key,
        issuer_service: "router".to_owned(),
        capabilities: vec![capability],
        delete_after_ack: false,
        issued_at: now,
        expires_at,
        nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token)?;
    Ok(token)
}

pub(crate) fn object_permission_for_chunk(
    branch: &DeviceBranch,
    object: &EncryptedObject,
    _chunk_index: u32,
    capability: SdkObjectRelayCapability,
    expires_at: u64,
) -> Result<SdkObjectPermissionEnvelope, SdkError> {
    let owner_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let mut permission = SdkObjectPermissionEnvelope {
        object_id: object.object_id.clone(),
        manifest_hash: object.manifest_hash.clone(),
        grantee_device_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            branch.device_id.as_bytes(),
        ),
        capability,
        issued_at: u64::try_from(now_unix_timestamp()).unwrap_or(0),
        expires_at,
        owner_signing_key_id: branch.device_id.clone(),
        owner_public_key,
        owner_signature: String::new(),
    };
    permission.owner_signature = object_permission_signature(&permission, branch)?;
    Ok(permission)
}

pub(crate) fn relay_post_json<T, R>(
    relay_endpoint: &str,
    path: &str,
    value: &T,
) -> Result<R, SdkError>
where
    T: Serialize,
    R: serde::de::DeserializeOwned,
{
    sdk_http_post_json(relay_endpoint, path, value)
}
