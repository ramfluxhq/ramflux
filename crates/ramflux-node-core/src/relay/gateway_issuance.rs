// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deferred Gateway token issuance and object-permission verification.

use super::{
    Hmac, NodeCoreError, OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS,
    OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS, ObjectPermissionEnvelope, ObjectRelayCapability,
    RelayToken, RelayTokenIssueBody,
};

use hmac::{KeyInit, Mac};

pub(super) type HmacSha256 = Hmac<sha2::Sha256>;
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

#[cfg(test)]
#[path = "tests/gateway_issuance.rs"]
mod tests;
