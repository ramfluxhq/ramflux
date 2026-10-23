// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy v2 relay tokens, MAC validation, and object permissions.

use super::{
    Deserialize, Hmac, NodeCoreError, ObjectChunkFrame, ObjectRelayCapability,
    ObjectRelayTombstone, Serialize, clamp_relay_chunk_expires_at, object_relay_chunk_cipher_hash,
};

use hmac::Mac;

pub(super) type HmacSha256 = Hmac<sha2::Sha256>;
pub const OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS: u64 = 60;
pub const OBJECT_RELAY_TOKEN_VERSION: u32 = 2;
pub const OBJECT_RELAY_TOKEN_ISSUER_GATEWAY: &str = "ramflux-gateway";
pub const OBJECT_RELAY_TOKEN_AUDIENCE_RELAY: &str = "ramflux-relay";
pub const OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS: u64 = 300;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayToken {
    #[serde(default = "relay_token_default_version")]
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
    pub capabilities: Vec<ObjectRelayCapability>,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub mac: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenIssueBody {
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub capability: ObjectRelayCapability,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub object_permission_envelope: ObjectPermissionEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenIssueRequest {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: RelayTokenIssueBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenIssueResponse {
    pub relay_token: RelayToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectPermissionEnvelope {
    pub object_id: String,
    pub manifest_hash: String,
    pub grantee_device_hash: String,
    pub capability: ObjectRelayCapability,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

pub(super) fn relay_token_default_version() -> u32 {
    1
}

/// # Errors
/// Returns an error when the canonical token encoding cannot be serialized.
pub fn relay_token_canonical_bytes(token: &RelayToken) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = token.clone();
    canonical.mac.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when HMAC initialization fails.
pub fn relay_token_mac(service_key: &[u8], token: &RelayToken) -> Result<String, NodeCoreError> {
    let mut mac = HmacSha256::new_from_slice(service_key)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    mac.update(&relay_token_canonical_bytes(token)?);
    Ok(ramflux_protocol::encode_base64url(mac.finalize().into_bytes()))
}

/// # Errors
/// Returns an error when the body TTL, capability, or permission binding is invalid.
pub fn validate_relay_token_issue_body(
    body: &RelayTokenIssueBody,
    now: u64,
) -> Result<(), NodeCoreError> {
    if body.issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || body.expires_at <= now
        || body.expires_at > now.saturating_add(OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS)
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: body.chunk_id.clone() });
    }
    // Only the owner's put token may carry a destructive delete-on-ack policy. Get/Ack/Tombstone
    // tokens must never request `delete_after_ack`, so a recipient cannot mint a token that
    // elevates itself to delete the owner's ciphertext.
    if body.delete_after_ack && body.capability != ObjectRelayCapability::Put {
        return Err(NodeCoreError::Unauthorized(
            "delete_after_ack is only permitted on put relay tokens".to_owned(),
        ));
    }
    validate_object_permission(&body.object_permission_envelope, body.capability, now)?;
    if body.object_permission_envelope.object_id != body.object_id
        || body.object_permission_envelope.manifest_hash != body.manifest_hash
        || body.object_permission_envelope.grantee_device_hash != body.recipient_device_hash
        || body.object_permission_envelope.owner_signing_key_id != body.owner_signing_key_id
        || body.object_permission_envelope.owner_public_key != body.owner_public_key
    {
        return Err(NodeCoreError::ItestHttp(
            "object relay token issue binding mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// # Errors
/// Returns an error when the token MAC, capability, issuer or TTL is invalid.
pub fn validate_relay_token(
    token: &RelayToken,
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if token.token_version != OBJECT_RELAY_TOKEN_VERSION {
        return Err(NodeCoreError::ItestHttp("object relay token version rejected".to_owned()));
    }
    if token.issuer_service != OBJECT_RELAY_TOKEN_ISSUER_GATEWAY {
        return Err(NodeCoreError::ItestHttp("object relay token issuer rejected".to_owned()));
    }
    if token.audience_service != OBJECT_RELAY_TOKEN_AUDIENCE_RELAY {
        return Err(NodeCoreError::ItestHttp("object relay token audience rejected".to_owned()));
    }
    if token.capabilities.len() != 1 || !token.capabilities.contains(&capability) {
        return Err(NodeCoreError::ItestHttp("object relay token capability rejected".to_owned()));
    }
    if token.issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || token.expires_at <= now
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: token.token_id.clone() });
    }
    let expected = relay_token_mac(service_key, token)?;
    if !constant_time_eq(expected.as_bytes(), token.mac.as_bytes()) {
        return Err(NodeCoreError::ItestHttp("object relay token mac rejected".to_owned()));
    }
    Ok(())
}

/// # Errors
/// Returns an error when the permission signature, capability or TTL is invalid.
pub fn validate_object_permission(
    permission: &ObjectPermissionEnvelope,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if permission.capability != capability {
        return Err(NodeCoreError::ItestHttp("object permission capability rejected".to_owned()));
    }
    if permission.issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || permission.expires_at <= now
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: permission.object_id.clone() });
    }
    ramflux_crypto::verify_canonical_signature(
        &object_permission_canonical_bytes(permission)?,
        &permission.owner_signature,
        &permission.owner_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

/// # Errors
/// Returns an error when the canonical permission encoding cannot be serialized.
pub fn object_permission_canonical_bytes(
    permission: &ObjectPermissionEnvelope,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = permission.clone();
    canonical.owner_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when any token, permission or chunk binding is invalid.
pub fn validate_object_chunk_frame(
    frame: &ObjectChunkFrame,
    relay_service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if frame.schema != "ramflux.object_chunk_frame.v1" {
        return Err(NodeCoreError::ItestJson("invalid object chunk frame schema".to_owned()));
    }
    validate_relay_token(&frame.relay_token, relay_service_key, capability, now)?;
    validate_object_permission(&frame.object_permission_envelope, capability, now)?;
    if frame.relay_token.object_id != frame.object_id
        || frame.relay_token.manifest_hash != frame.manifest_hash
        || frame.relay_token.chunk_id != frame.chunk_id
        || frame.object_permission_envelope.object_id != frame.object_id
        || frame.object_permission_envelope.manifest_hash != frame.manifest_hash
        || frame.object_permission_envelope.grantee_device_hash
            != frame.relay_token.recipient_device_hash
        || !permission_owner_matches_token(&frame.object_permission_envelope, &frame.relay_token)
    {
        return Err(NodeCoreError::ItestHttp("object relay frame binding mismatch".to_owned()));
    }
    let cipher_size = u64::try_from(frame.encrypted_chunk.len())
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    if frame.cipher_size != cipher_size {
        return Err(NodeCoreError::ItestHttp("object relay cipher_size mismatch".to_owned()));
    }
    let expected_hash = object_relay_chunk_cipher_hash(
        &frame.manifest_hash,
        frame.chunk_index,
        &frame.encrypted_chunk,
    );
    if frame.chunk_cipher_hash != expected_hash {
        return Err(NodeCoreError::ItestHttp("object relay chunk hash mismatch".to_owned()));
    }
    let capped_expires_at = clamp_relay_chunk_expires_at(now, frame.expires_at);
    if capped_expires_at > frame.relay_token.expires_at || frame.expires_at <= now {
        return Err(NodeCoreError::TtlExpired { envelope_id: frame.chunk_id.clone() });
    }
    Ok(())
}

pub(super) fn permission_owner_matches_token(
    permission: &ObjectPermissionEnvelope,
    token: &RelayToken,
) -> bool {
    permission.owner_signing_key_id == token.owner_signing_key_id
        && permission.owner_public_key == token.owner_public_key
}

/// Returns `true` when an incoming tombstone request is a semantically identical replay of an
/// already-stored tombstone: same object, manifest scope, tombstone hash, source event, signed-at,
/// the retention expiry recorded on first apply, and the same owner identity. The per-request
/// `relay_token`/`object_permission_envelope` nonces and MAC/signature are intentionally excluded
/// (a legitimate retry re-signs them). Any other difference is treated as a conflicting request by
/// the caller and rejected — the expiry is never recomputed or extended.
pub(super) fn existing_tombstone_matches_replay(
    existing: &ObjectRelayTombstone,
    incoming: &ObjectRelayTombstone,
) -> bool {
    existing.object_id == incoming.object_id
        && existing.manifest_hash == incoming.manifest_hash
        && existing.tombstone_hash == incoming.tombstone_hash
        && existing.source_event_id == incoming.source_event_id
        && existing.signed_at == incoming.signed_at
        && existing.expires_at == incoming.expires_at
        && existing.relay_token.owner_signing_key_id == incoming.relay_token.owner_signing_key_id
        && existing.relay_token.owner_public_key == incoming.relay_token.owner_public_key
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).fold(0_u8, |acc, (left, right)| acc | (left ^ right)) == 0
}
#[cfg(test)]
#[path = "tests/legacy.rs"]
mod tests;
