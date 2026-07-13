// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
#[cfg(feature = "itest-local-mint")]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
#[cfg(feature = "itest-local-mint")]
use sha2::Sha256;
use std::collections::BTreeSet;

#[cfg(feature = "itest-local-mint")]
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
    #[serde(default = "sdk_relay_token_default_version")]
    pub token_version: u32,
    pub token_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub issuer_service: String,
    #[serde(default)]
    pub audience_service: String,
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

#[cfg(feature = "itest-local-mint")]
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

#[cfg(feature = "itest-local-mint")]
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

#[cfg(feature = "itest-local-mint")]
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
    pub token_provider: RelayTokenProvider,
    pub interrupt_after_chunks: Option<u32>,
    pub relay_quic_peer_addr: Option<String>,
    pub relay_quic_server_name: Option<String>,
    pub relay_quic_ca_cert: Option<std::path::PathBuf>,
    pub relay_owner_home_node_id: Option<String>,
    pub relay_owner_principal_id: Option<String>,
    pub relay_audience_node_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum RelayTokenProvider {
    GatewayIssued,
    // T22-A1 / RQ-04: legacy v2 shared-HMAC local minting is compiled only under the
    // `itest-local-mint` feature. In production builds this variant does not exist, so no code path
    // can select or mint a v2 relay token — the v3 GatewayIssued path is the only reachable option.
    #[cfg(feature = "itest-local-mint")]
    LocalMint {
        relay_service_key: Vec<u8>,
    },
}

pub(crate) const OBJECT_TRANSFER_UPLOAD: &str = "upload";
pub(crate) const OBJECT_TRANSFER_DOWNLOAD: &str = "download";
// T22-A1 / RQ-04: v2 relay-token constants and the LocalMint runtime-opt-in env are compiled only
// under the `itest-local-mint` feature, so production SDK/rf binaries carry no v2 mint metadata or
// LocalMint env string.
#[cfg(feature = "itest-local-mint")]
pub(crate) const SDK_RELAY_TOKEN_VERSION: u32 = 2;
#[cfg(feature = "itest-local-mint")]
pub(crate) const SDK_RELAY_TOKEN_ISSUER_GATEWAY: &str = "ramflux-gateway";
#[cfg(feature = "itest-local-mint")]
pub(crate) const SDK_RELAY_TOKEN_AUDIENCE_RELAY: &str = "ramflux-relay";
#[cfg(feature = "itest-local-mint")]
pub(crate) const SDK_RELAY_LOCAL_MINT_ENV: &str = "RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT";

pub(crate) fn object_key_slot_associated_data(
    object_id: &str,
    conversation_id: &str,
    recipient_device_id: &str,
) -> Vec<u8> {
    format!("ramflux.object_key_slot.v1|{object_id}|{conversation_id}|{recipient_device_id}")
        .into_bytes()
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
    let token_provider = relay_token_provider_from_service_key(relay_service_key_base64)?;
    let relay_quic_peer_addr = std::env::var("RAMFLUX_SDK_RELAY_QUIC_ADDR").ok();
    let relay_quic_server_name = std::env::var("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME").ok();
    let relay_quic_ca_cert = std::env::var("RAMFLUX_SDK_RELAY_QUIC_CA_CERT").ok().map(Into::into);
    let relay_owner_home_node_id = std::env::var("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID").ok();
    let relay_owner_principal_id = std::env::var("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID").ok();
    let relay_audience_node_id = std::env::var("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID").ok();
    let configured_count = [
        relay_quic_peer_addr.is_some(),
        relay_quic_server_name.is_some(),
        relay_quic_ca_cert.is_some(),
    ]
    .into_iter()
    .filter(|configured| *configured)
    .count();
    if configured_count != 0 && configured_count != 3 {
        return Err(SdkError::LocalBus(
            "relay QUIC requires RAMFLUX_SDK_RELAY_QUIC_ADDR, SERVER_NAME, and CA_CERT together"
                .to_owned(),
        ));
    }
    Ok(Some(RelayTransferOptions {
        relay_endpoint,
        token_provider,
        interrupt_after_chunks,
        relay_quic_peer_addr,
        relay_quic_server_name,
        relay_quic_ca_cert,
        relay_owner_home_node_id,
        relay_owner_principal_id,
        relay_audience_node_id,
    }))
}

pub(crate) fn relay_quic_config(
    options: &RelayTransferOptions,
) -> Result<Option<ramflux_transport::RelayClientQuicConfig>, SdkError> {
    match (
        options.relay_quic_peer_addr.as_deref(),
        options.relay_quic_server_name.as_deref(),
        options.relay_quic_ca_cert.as_ref(),
    ) {
        (Some(peer_addr), Some(server_name), Some(ca_cert)) => Ok(Some(
            ramflux_transport::RelayClientQuicConfig::new(peer_addr, server_name, ca_cert)?,
        )),
        (None, None, None) => Ok(None),
        _ => Err(SdkError::LocalBus("relay QUIC configuration is incomplete".to_owned())),
    }
}

fn sdk_relay_token_default_version() -> u32 {
    1
}

// T22-A1 / RQ-04: production builds never mint a v2 relay token. Any caller-provided service key is
// ignored and the gateway-issued v3 path is always used; no service-key env is read, so the default
// SDK/rf binary carries no `RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64` string.
#[cfg(not(feature = "itest-local-mint"))]
#[allow(clippy::unnecessary_wraps)] // Result parity with the itest-local-mint variant.
fn relay_token_provider_from_service_key(
    _relay_service_key_base64: Option<String>,
) -> Result<RelayTokenProvider, SdkError> {
    Ok(RelayTokenProvider::GatewayIssued)
}

// itest LocalMint compatibility: still double-gated — the compile feature merely admits the code;
// activation additionally requires the `RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT` runtime opt-in.
#[cfg(feature = "itest-local-mint")]
fn relay_token_provider_from_service_key(
    relay_service_key_base64: Option<String>,
) -> Result<RelayTokenProvider, SdkError> {
    match relay_service_key_base64
        .or_else(|| std::env::var("RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64").ok())
    {
        Some(key) if sdk_relay_local_mint_enabled() => {
            let relay_service_key = ramflux_protocol::decode_base64url(&key)
                .or_else(|_| Ok::<Vec<u8>, ramflux_protocol::ProtocolError>(key.into_bytes()))
                .map_err(|error| {
                    SdkError::LocalBus(format!("invalid object relay service key: {error}"))
                })?;
            Ok(RelayTokenProvider::LocalMint { relay_service_key })
        }
        Some(_key) => {
            tracing::warn!(
                "object relay service key was provided but local mint is disabled; requesting gateway-issued relay token"
            );
            Ok(RelayTokenProvider::GatewayIssued)
        }
        None => Ok(RelayTokenProvider::GatewayIssued),
    }
}

#[cfg(feature = "itest-local-mint")]
fn sdk_relay_local_mint_enabled() -> bool {
    sdk_relay_local_mint_enabled_from_value(std::env::var(SDK_RELAY_LOCAL_MINT_ENV).ok().as_deref())
}

#[cfg(feature = "itest-local-mint")]
fn sdk_relay_local_mint_enabled_from_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes")
    })
}

pub(crate) fn object_relay_chunk_cipher_hash(
    manifest_hash: &str,
    chunk_index: u32,
    encrypted_chunk: &[u8],
) -> String {
    ramflux_sync::chunk_cipher_hash(manifest_hash, chunk_index, encrypted_chunk)
}

#[cfg(feature = "itest-local-mint")]
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

#[cfg(feature = "itest-local-mint")]
pub(crate) fn object_permission_signature(
    permission: &SdkObjectPermissionEnvelope,
    branch: &DeviceBranch,
) -> Result<String, SdkError> {
    let mut canonical = permission.clone();
    canonical.owner_signature.clear();
    Ok(ramflux_crypto::sign_protocol_object_with_device_branch(branch, &canonical)?)
}

// ---- RQ-03 v3 SDK-owned envelope builders (shared `ramflux_protocol::object_relay_v3` types) ----
//
// These construct and sign the SDK-owned v3 payloads with the caller's device branch key over the
// protocol's canonical signing bytes, so the produced signatures verify against the relay's
// `verify_canonical_signature`. They do NOT mint gateway certificates or relay tokens (those are
// gateway-issued) and do NOT wire any HTTP/QUIC transport.

/// Base64url of the branch device's Ed25519 public key (the owner/signer identity for v3 payloads).
#[allow(dead_code)]
fn branch_v3_public_key(branch: &DeviceBranch) -> String {
    ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
}

/// Signs canonical v3 signing bytes with the branch device key, yielding a detached signature that
/// `ramflux_crypto::verify_canonical_signature` accepts under the branch public key.
#[allow(dead_code)]
fn sign_v3_canonical_bytes(branch: &DeviceBranch, bytes: &[u8]) -> String {
    ramflux_crypto::sign_canonical_bytes_with_seed(bytes, branch.signing_key.to_bytes())
}

/// Builds and owner-signs a v3 [`ramflux_protocol::ObjectAccessGrant`] authorizing a Get/Ack grantee.
///
/// # Errors
/// Returns an error when the grant cannot be canonicalized for signing.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_signed_object_access_grant(
    branch: &DeviceBranch,
    object_id: String,
    manifest_hash: String,
    grantee_device_hash: String,
    capabilities: Vec<ramflux_protocol::ObjectRelayCapability>,
    issued_at: u64,
    expires_at: u64,
) -> Result<ramflux_protocol::ObjectAccessGrant, SdkError> {
    let mut grant = ramflux_protocol::ObjectAccessGrant {
        schema: ramflux_protocol::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
        object_id,
        manifest_hash,
        grantee_device_hash,
        capabilities,
        issued_at,
        expires_at,
        owner_signing_key_id: branch.device_id.clone(),
        owner_public_key: branch_v3_public_key(branch),
        owner_signature: String::new(),
    };
    grant.owner_signature = sign_v3_canonical_bytes(
        branch,
        &ramflux_protocol::object_access_grant_signing_bytes(&grant)?,
    );
    Ok(grant)
}

/// Builds and owner-signs a v3 [`ramflux_protocol::OwnerAuthorizationProof`] for a Put/Tombstone.
///
/// # Errors
/// Returns an error when the proof cannot be canonicalized for signing.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn build_signed_owner_authorization_proof(
    branch: &DeviceBranch,
    capability: ramflux_protocol::ObjectRelayCapability,
    object_id: String,
    manifest_hash: Option<String>,
    chunk_id: Option<String>,
    owner_home_node_id: String,
    owner_principal_id: String,
    owner_device_epoch: u64,
    request_nonce: String,
    body_hash: String,
    issued_at: u64,
    expires_at: u64,
) -> Result<ramflux_protocol::OwnerAuthorizationProof, SdkError> {
    let mut proof = ramflux_protocol::OwnerAuthorizationProof {
        schema: ramflux_protocol::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
        version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
        capability,
        object_id,
        manifest_hash,
        chunk_id,
        owner_home_node_id,
        owner_principal_id,
        owner_device_epoch,
        request_nonce,
        body_hash,
        issued_at,
        expires_at,
        owner_signing_key_id: branch.device_id.clone(),
        owner_public_key: branch_v3_public_key(branch),
        owner_signature: String::new(),
    };
    proof.owner_signature = sign_v3_canonical_bytes(
        branch,
        &ramflux_protocol::owner_authorization_proof_signing_bytes(&proof)?,
    );
    Ok(proof)
}

/// Builds and requester-signs a per-invocation v3 [`ramflux_protocol::RequesterProofOfPossession`].
///
/// # Errors
/// Returns an error when the `PoP` cannot be canonicalized for signing.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn build_signed_requester_pop(
    branch: &DeviceBranch,
    token_id: String,
    capability: ramflux_protocol::ObjectRelayCapability,
    object_id: String,
    manifest_hash: String,
    chunk_id: String,
    request_nonce: String,
    body_hash: String,
    issued_at: u64,
    expires_at: u64,
) -> Result<ramflux_protocol::RequesterProofOfPossession, SdkError> {
    let mut pop = ramflux_protocol::RequesterProofOfPossession {
        schema: ramflux_protocol::REQUESTER_POP_SCHEMA.to_owned(),
        version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
        token_id,
        capability,
        object_id,
        manifest_hash,
        chunk_id,
        request_nonce,
        body_hash,
        issued_at,
        expires_at,
        signer_device_id: branch.device_id.clone(),
        signer_public_key: branch_v3_public_key(branch),
        signature: String::new(),
    };
    pop.signature =
        sign_v3_canonical_bytes(branch, &ramflux_protocol::requester_pop_signing_bytes(&pop)?);
    Ok(pop)
}

#[cfg(feature = "itest-local-mint")]
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
        token_version: SDK_RELAY_TOKEN_VERSION,
        issuer_service: SDK_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: SDK_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
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

#[cfg(feature = "itest-local-mint")]
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

/// Recipient-side domain hash of this device id, matching the uploader-embedded `grantee_device_hash`
/// in an owner-signed v3 grant.
#[allow(dead_code)]
pub(crate) fn recipient_device_hash(branch: &DeviceBranch) -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        branch.device_id.as_bytes(),
    )
}

/// Verifies an uploader-signed [`ramflux_protocol::ObjectAccessGrant`] on the RECIPIENT side before it
/// is used for a relay Get/Ack download. The recipient NEVER mints or self-signs a grant: it only
/// accepts an owner-signed grant that names THIS device as grantee and is bound to the object being
/// downloaded. It is fail-closed — a missing (`None`), tampered, wrong-grantee, wrong-object, expired,
/// or non-Get/Ack grant is rejected — so an older share that carries no grant does not silently
/// downgrade to unauthorized access.
///
/// # Errors
/// Returns an error when the grant is absent or fails any binding, capability, TTL, or owner-signature
/// check.
#[allow(dead_code)]
pub(crate) fn verify_recipient_object_access_grant(
    grant: Option<&ramflux_protocol::ObjectAccessGrant>,
    branch: &DeviceBranch,
    object_id: &str,
    manifest_hash: &str,
    now: u64,
) -> Result<(), SdkError> {
    let grant = grant.ok_or_else(|| {
        SdkError::CapabilityDenied(
            "object access grant is required but was not provided".to_owned(),
        )
    })?;
    if grant.schema != ramflux_protocol::OBJECT_ACCESS_GRANT_SCHEMA
        || grant.version != ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION
    {
        return Err(SdkError::CapabilityDenied(
            "object access grant schema/version rejected".to_owned(),
        ));
    }
    // This device must be the named grantee — the grant is not transferable to another device.
    if grant.grantee_device_hash != recipient_device_hash(branch) {
        return Err(SdkError::CapabilityDenied(
            "object access grant grantee does not match this device".to_owned(),
        ));
    }
    // The grant must be bound to the exact object/manifest being downloaded.
    if grant.object_id != object_id || grant.manifest_hash != manifest_hash {
        return Err(SdkError::CapabilityDenied(
            "object access grant object/manifest binding mismatch".to_owned(),
        ));
    }
    // Grants may only authorize Get/Ack.
    if grant.capabilities.is_empty()
        || grant.capabilities.iter().any(|capability| {
            !matches!(
                capability,
                ramflux_protocol::ObjectRelayCapability::Get
                    | ramflux_protocol::ObjectRelayCapability::Ack
            )
        })
    {
        return Err(SdkError::CapabilityDenied(
            "object access grant carries a non get/ack capability".to_owned(),
        ));
    }
    if now < grant.issued_at || now >= grant.expires_at {
        return Err(SdkError::CapabilityDenied(
            "object access grant is outside its validity window".to_owned(),
        ));
    }
    // The ultimate authenticity check: the owner signature over the canonical grant bytes.
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::object_access_grant_signing_bytes(grant)?,
        &grant.owner_signature,
        &grant.owner_public_key,
    )
    .map_err(|error| {
        SdkError::SignatureVerificationFailed(format!(
            "object access grant signature invalid: {error}"
        ))
    })?;
    Ok(())
}

/// Resolves the owner-lineage value written into an outgoing DM attachment.
///
/// T21-A2: an explicit per-message override always wins; only when the caller supplies `None` do we
/// fix the lineage that this upload actually used (the effective relay options resolved from the
/// daemon environment). An explicit empty string is deliberately preserved rather than replaced, so
/// a caller that intentionally clears the field still fails closed in the v3 grantee token builder
/// instead of silently inheriting the environment default. Lineage is never derived from other
/// fields such as the gateway host or recipient node.
pub(crate) fn effective_attachment_lineage(
    explicit: Option<String>,
    effective: Option<String>,
) -> Option<String> {
    explicit.or(effective)
}

/// Builds the gateway v3 Get-token request body from an already verified owner grant. Issuer
/// identity/certificate fields are intentionally placeholders: the gateway adapter overwrites them
/// with its configured certificate. Owner lineage and relay audience remain caller-provided and are
/// rejected when absent instead of being guessed.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn build_v3_get_token_issue_body(
    grant: Option<&ramflux_protocol::ObjectAccessGrant>,
    attachment: &SdkDmAttachmentRef,
    branch: &DeviceBranch,
    chunk_id: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<SdkRelayTokenV3IssueBody, SdkError> {
    verify_recipient_object_access_grant(
        grant,
        branch,
        &attachment.object_id,
        &attachment.manifest_hash,
        issued_at,
    )?;
    let grant = grant
        .ok_or_else(|| SdkError::CapabilityDenied("object access grant is required".to_owned()))?;
    // The received grant must explicitly authorize Get: a grant scoped to only Ack cannot download.
    if !grant.capabilities.contains(&ramflux_protocol::ObjectRelayCapability::Get) {
        return Err(SdkError::CapabilityDenied(
            "object access grant does not authorize get".to_owned(),
        ));
    }
    let owner_home_node_id =
        attachment.owner_home_node_id.clone().filter(|value| !value.trim().is_empty()).ok_or_else(
            || SdkError::CapabilityDenied("owner home node id is required".to_owned()),
        )?;
    let audience_node_id = attachment
        .relay_audience_node_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            SdkError::CapabilityDenied("relay audience node id is required".to_owned())
        })?;
    if attachment.owner_principal_id.is_empty() || attachment.owner_device_epoch == 0 {
        return Err(SdkError::CapabilityDenied("owner lineage is incomplete".to_owned()));
    }
    let grant_bytes = ramflux_protocol::canonical_json_bytes(grant)?;
    let authorization_binding_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_access_grant.binding.v3",
        &grant_bytes,
    );
    let requester_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    Ok(SdkRelayTokenV3IssueBody {
        requester_device_id: branch.device_id.clone(),
        requester_device_hash: recipient_device_hash(branch),
        requester_public_key,
        requester_device_epoch: branch.device_epoch,
        owner_signing_key_id: grant.owner_signing_key_id.clone(),
        owner_public_key: grant.owner_public_key.clone(),
        owner_home_node_id,
        owner_principal_id: attachment.owner_principal_id.clone(),
        owner_device_epoch: attachment.owner_device_epoch,
        issuer_node_id: String::new(),
        gateway_instance_id: String::new(),
        audience_node_id,
        relay_instance_id: None,
        object_id: attachment.object_id.clone(),
        manifest_hash: attachment.manifest_hash.clone(),
        chunk_id: chunk_id.to_owned(),
        capabilities: vec![ramflux_protocol::ObjectRelayCapability::Get],
        authorization_kind: ramflux_protocol::RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash,
        delete_after_ack: false,
        issued_at,
        expires_at,
        nonce: nonce.to_owned(),
        issuer_certificate: ramflux_protocol::GatewayIssuerCertificate {
            schema: ramflux_protocol::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
            version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
            cert_id: String::new(),
            node_id: String::new(),
            gateway_instance_id: String::new(),
            attestation_public_key: String::new(),
            attestation_key_id: String::new(),
            not_before: 0,
            not_after: 0,
            issued_at: 0,
            node_root_signing_key_id: String::new(),
            node_root_signature: String::new(),
            revoked_at: None,
        },
    })
}

/// Builds the gateway v3 Ack-token body from an already verified owner grant.
///
/// # Errors
/// Returns an error when the grant, recipient lineage, or attachment routing metadata is invalid.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_v3_ack_token_issue_body(
    grant: Option<&ramflux_protocol::ObjectAccessGrant>,
    attachment: &SdkDmAttachmentRef,
    branch: &DeviceBranch,
    chunk_id: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<SdkRelayTokenV3IssueBody, SdkError> {
    // Reuse the get-token binding/verification (grantee/object/manifest/owner-signature/lineage),
    // then require the received grant to explicitly authorize Ack before switching capability. The
    // grant is never re-signed here: the same A-signed bytes back both the Get and Ack tokens.
    let mut body = build_v3_get_token_issue_body(
        grant, attachment, branch, chunk_id, issued_at, expires_at, nonce,
    )?;
    let grant = grant
        .ok_or_else(|| SdkError::CapabilityDenied("object access grant is required".to_owned()))?;
    if !grant.capabilities.contains(&ramflux_protocol::ObjectRelayCapability::Ack) {
        return Err(SdkError::CapabilityDenied(
            "object access grant does not authorize ack".to_owned(),
        ));
    }
    body.capabilities = vec![ramflux_protocol::ObjectRelayCapability::Ack];
    Ok(body)
}

/// Builds an owner-session v3 token request for a Put or Tombstone operation. The lineage values
/// are explicit inputs so a generic object transfer cannot silently invent a home node or principal.
///
/// # Errors
/// Returns an error when a required lineage value is empty, the capability is not owner-session, or
/// the operation window is invalid.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_v3_owner_session_token_issue_body(
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_id: &str,
    capability: ramflux_protocol::ObjectRelayCapability,
    owner_home_node_id: &str,
    audience_node_id: &str,
    owner_principal_id: &str,
    authorization_binding_hash: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<SdkRelayTokenV3IssueBody, SdkError> {
    if !matches!(
        capability,
        ramflux_protocol::ObjectRelayCapability::Put
            | ramflux_protocol::ObjectRelayCapability::Tombstone
    ) {
        return Err(SdkError::CapabilityDenied(
            "owner-session token requires put or tombstone capability".to_owned(),
        ));
    }
    if owner_home_node_id.trim().is_empty()
        || audience_node_id.trim().is_empty()
        || owner_principal_id.trim().is_empty()
        || chunk_id.trim().is_empty()
        || expires_at <= issued_at
        || branch.device_epoch == 0
    {
        return Err(SdkError::CapabilityDenied(
            "owner-session token lineage or validity window is incomplete".to_owned(),
        ));
    }
    let requester_public_key = branch_v3_public_key(branch);
    Ok(SdkRelayTokenV3IssueBody {
        requester_device_id: branch.device_id.clone(),
        requester_device_hash: recipient_device_hash(branch),
        requester_public_key: requester_public_key.clone(),
        requester_device_epoch: branch.device_epoch,
        owner_signing_key_id: branch.device_id.clone(),
        owner_public_key: requester_public_key,
        owner_home_node_id: owner_home_node_id.to_owned(),
        owner_principal_id: owner_principal_id.to_owned(),
        owner_device_epoch: branch.device_epoch,
        issuer_node_id: String::new(),
        gateway_instance_id: String::new(),
        audience_node_id: audience_node_id.to_owned(),
        relay_instance_id: None,
        object_id: object.object_id.clone(),
        manifest_hash: object.manifest_hash.clone(),
        chunk_id: chunk_id.to_owned(),
        capabilities: vec![capability],
        authorization_kind: ramflux_protocol::RelayAuthorizationKind::OwnerSession,
        authorization_binding_hash: authorization_binding_hash.to_owned(),
        delete_after_ack: false,
        issued_at,
        expires_at,
        nonce: nonce.to_owned(),
        issuer_certificate: empty_v3_issuer_certificate(),
    })
}

fn empty_v3_issuer_certificate() -> ramflux_protocol::GatewayIssuerCertificate {
    ramflux_protocol::GatewayIssuerCertificate {
        schema: ramflux_protocol::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: String::new(),
        node_id: String::new(),
        gateway_instance_id: String::new(),
        attestation_public_key: String::new(),
        attestation_key_id: String::new(),
        not_before: 0,
        not_after: 0,
        issued_at: 0,
        node_root_signing_key_id: String::new(),
        node_root_signature: String::new(),
        revoked_at: None,
    }
}

/// Builds a grant-backed v3 token request for generic object Get/Ack transfers.
///
/// # Errors
/// Returns an error when the grant is absent, invalid for the recipient, or does not authorize the
/// requested capability.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_v3_grant_token_issue_body(
    grant: &ramflux_protocol::ObjectAccessGrant,
    branch: &DeviceBranch,
    object_id: &str,
    manifest_hash: &str,
    chunk_id: &str,
    capability: ramflux_protocol::ObjectRelayCapability,
    owner_home_node_id: &str,
    owner_principal_id: &str,
    owner_device_epoch: u64,
    audience_node_id: &str,
    issued_at: u64,
    expires_at: u64,
    nonce: &str,
) -> Result<SdkRelayTokenV3IssueBody, SdkError> {
    if !matches!(
        capability,
        ramflux_protocol::ObjectRelayCapability::Get | ramflux_protocol::ObjectRelayCapability::Ack
    ) {
        return Err(SdkError::CapabilityDenied(
            "grant-backed token requires get or ack capability".to_owned(),
        ));
    }
    verify_recipient_object_access_grant(Some(grant), branch, object_id, manifest_hash, issued_at)?;
    if !grant.capabilities.contains(&capability)
        || owner_home_node_id.trim().is_empty()
        || owner_principal_id.trim().is_empty()
        || audience_node_id.trim().is_empty()
        || owner_device_epoch == 0
    {
        return Err(SdkError::CapabilityDenied(
            "grant-backed token lineage or capability is incomplete".to_owned(),
        ));
    }
    let requester_public_key = branch_v3_public_key(branch);
    let grant_binding_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_access_grant.binding.v3",
        &ramflux_protocol::canonical_json_bytes(grant)?,
    );
    Ok(SdkRelayTokenV3IssueBody {
        requester_device_id: branch.device_id.clone(),
        requester_device_hash: recipient_device_hash(branch),
        requester_public_key,
        requester_device_epoch: branch.device_epoch,
        owner_signing_key_id: grant.owner_signing_key_id.clone(),
        owner_public_key: grant.owner_public_key.clone(),
        owner_home_node_id: owner_home_node_id.to_owned(),
        owner_principal_id: owner_principal_id.to_owned(),
        owner_device_epoch,
        issuer_node_id: String::new(),
        gateway_instance_id: String::new(),
        audience_node_id: audience_node_id.to_owned(),
        relay_instance_id: None,
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        chunk_id: chunk_id.to_owned(),
        capabilities: vec![capability],
        authorization_kind: ramflux_protocol::RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash: grant_binding_hash,
        delete_after_ack: false,
        issued_at,
        expires_at,
        nonce: nonce.to_owned(),
        issuer_certificate: empty_v3_issuer_certificate(),
    })
}

#[cfg(feature = "itest-local-mint")]
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

/// Explicit relay client-facing QUIC health/diagnostic probe.
///
/// Validates the connection parameters (fail-closed on a malformed peer address, empty server name,
/// or missing CA certificate) and performs a control-plane `GET /healthz` against the relay's
/// client-facing QUIC surface, reusing the shared transport helper. This is diagnostic only: it does
/// NOT carry object data or relay tokens, does NOT replace the object `relay_post_json` transport,
/// and never falls back to plaintext HTTP.
///
/// # Errors
/// Returns an error when the parameters are invalid, the TLS handshake fails, or the health
/// request/response fails.
// Diagnostic-only entry point; not yet invoked by SDK internals (see report).
#[allow(dead_code)]
pub(crate) async fn relay_quic_health_probe(
    peer_addr: &str,
    server_name: &str,
    ca_cert: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError> {
    let config = ramflux_transport::RelayClientQuicConfig::new(peer_addr, server_name, ca_cert)?;
    let response = ramflux_transport::relay_client_quic_health(&config, timeout).await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_grant_verify_present_missing_tampered() -> Result<(), SdkError> {
        let now = 1_000_000;
        let owner = ramflux_crypto::create_device_branch("owner_p", "owner_device", 1, [9u8; 32]);
        let recipient = ramflux_crypto::create_device_branch("rcpt_p", "rcpt_device", 1, [8u8; 32]);
        let grantee = recipient_device_hash(&recipient);
        let grant = build_signed_object_access_grant(
            &owner,
            "object_v3".to_owned(),
            "manifest_v3".to_owned(),
            grantee,
            vec![
                ramflux_protocol::ObjectRelayCapability::Get,
                ramflux_protocol::ObjectRelayCapability::Ack,
            ],
            now,
            now + 300,
        )?;

        // Present + valid -> accepted.
        verify_recipient_object_access_grant(
            Some(&grant),
            &recipient,
            "object_v3",
            "manifest_v3",
            now,
        )?;

        // Missing -> fail closed (an older grantless share never downgrades to open access).
        assert!(
            verify_recipient_object_access_grant(None, &recipient, "object_v3", "manifest_v3", now)
                .is_err()
        );

        // Tampered after signing (object_id changed) -> owner signature no longer verifies, even when
        // the caller's object id is updated to match the tampered value.
        let mut tampered = grant.clone();
        tampered.object_id = "object_forged".to_owned();
        assert!(
            verify_recipient_object_access_grant(
                Some(&tampered),
                &recipient,
                "object_forged",
                "manifest_v3",
                now,
            )
            .is_err()
        );

        // A grant addressed to a DIFFERENT device cannot be replayed by this recipient.
        let attacker =
            ramflux_crypto::create_device_branch("atk_p", "attacker_device", 1, [7u8; 32]);
        assert!(
            verify_recipient_object_access_grant(
                Some(&grant),
                &attacker,
                "object_v3",
                "manifest_v3",
                now,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn v3_grant_and_pop_builders_sign_and_bind() -> Result<(), SdkError> {
        let branch = ramflux_crypto::create_device_branch("principal_a", "device_a", 1, [7u8; 32]);
        let public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());

        // Grant: the owner signature verifies over the protocol canonical signing bytes, and the
        // owner identity/version binding fields are populated.
        let grant = build_signed_object_access_grant(
            &branch,
            "object_v3".to_owned(),
            "manifest_v3".to_owned(),
            "grantee_v3".to_owned(),
            vec![
                ramflux_protocol::ObjectRelayCapability::Get,
                ramflux_protocol::ObjectRelayCapability::Ack,
            ],
            1_000,
            1_300,
        )?;
        assert_eq!(grant.owner_public_key, public_key);
        assert_eq!(grant.owner_signing_key_id, "device_a");
        assert_eq!(grant.version, ramflux_protocol::OBJECT_RELAY_V3_PROOF_VERSION);
        assert!(!grant.owner_signature.is_empty());
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::object_access_grant_signing_bytes(&grant)?,
            &grant.owner_signature,
            &grant.owner_public_key,
        )?;
        // The capability set is bound: tampering it invalidates the signature.
        let mut tampered = grant.clone();
        tampered.capabilities = vec![ramflux_protocol::ObjectRelayCapability::Put];
        assert!(
            ramflux_crypto::verify_canonical_signature(
                &ramflux_protocol::object_access_grant_signing_bytes(&tampered)?,
                &tampered.owner_signature,
                &tampered.owner_public_key,
            )
            .is_err()
        );

        // PoP: the requester signature verifies and is bound to the token/body/capability frame.
        let pop = build_signed_requester_pop(
            &branch,
            "tok_v3".to_owned(),
            ramflux_protocol::ObjectRelayCapability::Ack,
            "object_v3".to_owned(),
            "manifest_v3".to_owned(),
            "chunk_v3".to_owned(),
            "nonce_v3".to_owned(),
            "body_hash_v3".to_owned(),
            1_000,
            1_060,
        )?;
        assert_eq!(pop.signer_public_key, public_key);
        assert_eq!(pop.token_id, "tok_v3");
        assert_eq!(pop.body_hash, "body_hash_v3");
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::requester_pop_signing_bytes(&pop)?,
            &pop.signature,
            &pop.signer_public_key,
        )?;
        // The body hash is bound: tampering it invalidates the signature.
        let mut tampered_pop = pop.clone();
        tampered_pop.body_hash = "forged".to_owned();
        assert!(
            ramflux_crypto::verify_canonical_signature(
                &ramflux_protocol::requester_pop_signing_bytes(&tampered_pop)?,
                &tampered_pop.signature,
                &tampered_pop.signer_public_key,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn relay_transfer_options_default_to_gateway_issued_tokens() -> Result<(), SdkError> {
        let options =
            parse_relay_transfer_options(Some("http://127.0.0.1:18084".to_owned()), None, None)?
                .ok_or_else(|| SdkError::LocalBus("missing relay options".to_owned()))?;
        assert!(matches!(options.token_provider, RelayTokenProvider::GatewayIssued));
        Ok(())
    }

    #[test]
    fn relay_transfer_options_ignore_service_key_without_local_mint_gate() -> Result<(), SdkError> {
        let options = parse_relay_transfer_options(
            Some("http://127.0.0.1:18084".to_owned()),
            Some("ramflux-relay-itest-service-key".to_owned()),
            None,
        )?
        .ok_or_else(|| SdkError::LocalBus("missing relay options".to_owned()))?;
        assert!(matches!(options.token_provider, RelayTokenProvider::GatewayIssued));
        Ok(())
    }

    #[test]
    fn relay_quic_config_matrix_fails_closed_on_partial_config() -> Result<(), SdkError> {
        fn options(
            peer: Option<&str>,
            server: Option<&str>,
            ca: Option<&str>,
        ) -> RelayTransferOptions {
            RelayTransferOptions {
                relay_endpoint: "http://127.0.0.1:18084".to_owned(),
                token_provider: RelayTokenProvider::GatewayIssued,
                interrupt_after_chunks: None,
                relay_quic_peer_addr: peer.map(str::to_owned),
                relay_quic_server_name: server.map(str::to_owned),
                relay_quic_ca_cert: ca.map(Into::into),
                relay_owner_home_node_id: None,
                relay_owner_principal_id: None,
                relay_audience_node_id: None,
            }
        }

        // Fully unconfigured -> None (no QUIC transport requested); the GatewayIssued production
        // path rejects this before any relay call, so it never silently uses HTTP.
        assert!(relay_quic_config(&options(None, None, None))?.is_none());

        // Every partial combination fails closed rather than silently degrading transport.
        for (peer, server, ca) in [
            (Some("127.0.0.1:9000"), None, None),
            (None, Some("ramflux-relay"), None),
            (None, None, Some("/tmp/ca.pem")),
            (Some("127.0.0.1:9000"), Some("ramflux-relay"), None),
            (Some("127.0.0.1:9000"), None, Some("/tmp/ca.pem")),
            (None, Some("ramflux-relay"), Some("/tmp/ca.pem")),
        ] {
            assert!(
                relay_quic_config(&options(peer, server, ca)).is_err(),
                "partial QUIC config must fail closed: {peer:?}/{server:?}/{ca:?}"
            );
        }
        Ok(())
    }

    fn sample_grantee_attachment(
        capabilities: Vec<ramflux_protocol::ObjectRelayCapability>,
    ) -> Result<(SdkDmAttachmentRef, DeviceBranch), SdkError> {
        let owner = ramflux_crypto::create_device_branch("owner_a2", "owner_dev_a2", 1, [9u8; 32]);
        let recipient =
            ramflux_crypto::create_device_branch("rcpt_a2", "rcpt_dev_a2", 1, [8u8; 32]);
        let now = 1_000_000;
        let grant = build_signed_object_access_grant(
            &owner,
            "object_a2".to_owned(),
            "manifest_a2".to_owned(),
            recipient_device_hash(&recipient),
            capabilities,
            now,
            now + 300,
        )?;
        let attachment = SdkDmAttachmentRef {
            schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
            version: 1,
            object_id: "object_a2".to_owned(),
            manifest_hash: "manifest_a2".to_owned(),
            plaintext_hash: "plaintext_a2".to_owned(),
            cipher_size: 16,
            chunk_size: 16,
            total_chunks: 1,
            relay_endpoint: "http://127.0.0.1:1".to_owned(),
            owner_home_node_id: Some("node_a2".to_owned()),
            relay_audience_node_id: Some("audience_a2".to_owned()),
            owner_principal_id: "owner_principal_a2".to_owned(),
            owner_device_epoch: 1,
            access_grant: Some(grant),
            key_slot: SdkObjectKeySlot {
                schema: "ramflux.sdk.object_key_slot.v1".to_owned(),
                version: 1,
                object_id: "object_a2".to_owned(),
                conversation_id: "conv_a2".to_owned(),
                recipient_device_id: "rcpt_dev_a2".to_owned(),
                x3dh: None,
                ciphertext: serde_json::from_value(serde_json::json!({
                    "session_id": "session_a2",
                    "counter": 0,
                    "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    "ciphertext": []
                }))?,
            },
        };
        Ok((attachment, recipient))
    }

    #[test]
    fn grantee_token_builders_require_the_matching_grant_capability() -> Result<(), SdkError> {
        use ramflux_protocol::ObjectRelayCapability::{Ack, Get};
        let now = 1_000_000;
        let chunk_id = "object-relay:object_a2:manifest_a2:0";

        // A grant carrying both Get and Ack backs both token bodies; the Ack body is scoped to Ack
        // and the Get body to Get. The grant is never re-signed — the same A-signed grant is reused.
        let (attachment, recipient) = sample_grantee_attachment(vec![Get, Ack])?;
        let get_body = build_v3_get_token_issue_body(
            attachment.access_grant.as_ref(),
            &attachment,
            &recipient,
            chunk_id,
            now,
            now + 120,
            "nonce-get",
        )?;
        assert_eq!(get_body.capabilities, vec![Get]);
        let ack_body = build_v3_ack_token_issue_body(
            attachment.access_grant.as_ref(),
            &attachment,
            &recipient,
            chunk_id,
            now,
            now + 120,
            "nonce-ack",
        )?;
        assert_eq!(ack_body.capabilities, vec![Ack]);

        // A Get-only grant cannot back an Ack token, and an Ack-only grant cannot back a Get token.
        let (get_only, recipient) = sample_grantee_attachment(vec![Get])?;
        assert!(matches!(
            build_v3_ack_token_issue_body(
                get_only.access_grant.as_ref(),
                &get_only,
                &recipient,
                chunk_id,
                now,
                now + 120,
                "nonce-ack",
            ),
            Err(SdkError::CapabilityDenied(_))
        ));
        let (ack_only, recipient) = sample_grantee_attachment(vec![Ack])?;
        assert!(matches!(
            build_v3_get_token_issue_body(
                ack_only.access_grant.as_ref(),
                &ack_only,
                &recipient,
                chunk_id,
                now,
                now + 120,
                "nonce-get",
            ),
            Err(SdkError::CapabilityDenied(_))
        ));

        // A missing grant, or a grant addressed to another device, is rejected before any token.
        let (attachment, _recipient) = sample_grantee_attachment(vec![Get, Ack])?;
        assert!(matches!(
            build_v3_ack_token_issue_body(
                None,
                &attachment,
                &recipient,
                chunk_id,
                now,
                now + 120,
                "nonce-ack",
            ),
            Err(SdkError::CapabilityDenied(_))
        ));
        let attacker =
            ramflux_crypto::create_device_branch("atk_a2", "attacker_dev_a2", 1, [7u8; 32]);
        assert!(matches!(
            build_v3_ack_token_issue_body(
                attachment.access_grant.as_ref(),
                &attachment,
                &attacker,
                chunk_id,
                now,
                now + 120,
                "nonce-ack",
            ),
            Err(SdkError::CapabilityDenied(_))
        ));
        Ok(())
    }

    #[test]
    fn effective_attachment_lineage_prefers_explicit_and_never_masks_empty() {
        // An explicit override always wins over the effective (env) lineage.
        assert_eq!(
            effective_attachment_lineage(Some("explicit".to_owned()), Some("effective".to_owned())),
            Some("explicit".to_owned())
        );
        // A missing value is fixed to the effective lineage this upload actually used.
        assert_eq!(
            effective_attachment_lineage(None, Some("effective".to_owned())),
            Some("effective".to_owned())
        );
        // An explicit empty string is preserved, not replaced by the effective value; it fails
        // closed later in the grantee token builder instead of silently inheriting the default.
        assert_eq!(
            effective_attachment_lineage(Some(String::new()), Some("effective".to_owned())),
            Some(String::new())
        );
        // With neither source the lineage stays absent (v3 grantee use fails closed).
        assert_eq!(effective_attachment_lineage(None, None), None);
    }

    #[test]
    fn grantee_token_builder_fails_closed_on_empty_owner_lineage() -> Result<(), SdkError> {
        use ramflux_protocol::ObjectRelayCapability::{Ack, Get};
        let (mut attachment, recipient) = sample_grantee_attachment(vec![Get, Ack])?;
        // An explicit empty owner home node must fail closed rather than be treated as present.
        attachment.owner_home_node_id = Some(String::new());
        let now = 1_000_000;
        assert!(matches!(
            build_v3_get_token_issue_body(
                attachment.access_grant.as_ref(),
                &attachment,
                &recipient,
                "object-relay:object_a2:manifest_a2:0",
                now,
                now + 120,
                "nonce-get",
            ),
            Err(SdkError::CapabilityDenied(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_sdk_builders_sign_shared_protocol_payloads() -> Result<(), SdkError> {
        let branch =
            ramflux_crypto::create_device_branch("principal-v3", "device-v3", 7, [0x31; 32]);
        let public_key =
            ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
        let grant = build_signed_object_access_grant(
            &branch,
            "object-v3".to_owned(),
            "manifest-v3".to_owned(),
            "recipient-v3".to_owned(),
            vec![ramflux_protocol::ObjectRelayCapability::Get],
            1_000,
            1_300,
        )?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::object_access_grant_signing_bytes(&grant)?,
            &grant.owner_signature,
            &public_key,
        )?;
        let pop = build_signed_requester_pop(
            &branch,
            "token-v3".to_owned(),
            ramflux_protocol::ObjectRelayCapability::Get,
            "object-v3".to_owned(),
            "manifest-v3".to_owned(),
            "chunk-v3".to_owned(),
            "nonce-v3".to_owned(),
            "body-v3".to_owned(),
            1_000,
            1_060,
        )?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::requester_pop_signing_bytes(&pop)?,
            &pop.signature,
            &public_key,
        )?;
        let proof = build_signed_owner_authorization_proof(
            &branch,
            ramflux_protocol::ObjectRelayCapability::Put,
            "object-v3".to_owned(),
            Some("manifest-v3".to_owned()),
            Some("chunk-v3".to_owned()),
            "node-v3".to_owned(),
            "principal-v3".to_owned(),
            7,
            "nonce-v3".to_owned(),
            "body-v3".to_owned(),
            1_000,
            1_060,
        )?;
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::owner_authorization_proof_signing_bytes(&proof)?,
            &proof.owner_signature,
            &public_key,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn relay_quic_health_probe_rejects_invalid_config() {
        // Malformed peer address: fail closed before any network I/O.
        assert!(
            relay_quic_health_probe(
                "not-an-address",
                "ramflux-relay",
                std::path::Path::new("/nonexistent/relay-client-ca.pem"),
                std::time::Duration::from_millis(50),
            )
            .await
            .is_err()
        );
        // Missing CA certificate: fail closed (no plaintext fallback).
        assert!(
            relay_quic_health_probe(
                "127.0.0.1:17447",
                "ramflux-relay",
                std::path::Path::new("/nonexistent/relay-client-ca.pem"),
                std::time::Duration::from_millis(50),
            )
            .await
            .is_err()
        );
    }

    #[cfg(feature = "itest-local-mint")]
    #[test]
    fn relay_local_mint_gate_parses_explicit_values() {
        assert!(sdk_relay_local_mint_enabled_from_value(Some("1")));
        assert!(sdk_relay_local_mint_enabled_from_value(Some("true")));
        assert!(sdk_relay_local_mint_enabled_from_value(Some("on")));
        assert!(!sdk_relay_local_mint_enabled_from_value(Some("0")));
        assert!(!sdk_relay_local_mint_enabled_from_value(None));
    }
}
