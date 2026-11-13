// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared token representations, current timing constants and retained tombstone identity.
use super::{Deserialize, ObjectRelayCapability, ObjectRelayTombstone, Serialize};

pub const OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS: u64 = 60;
pub const OBJECT_RELAY_TOKEN_VERSION: u32 = 2;
pub const OBJECT_RELAY_TOKEN_ISSUER_GATEWAY: &str = "ramflux-gateway";
pub const OBJECT_RELAY_TOKEN_AUDIENCE_RELAY: &str = "ramflux-relay";
pub const OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS: u64 = 300;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayToken {
    pub token_version: u32,
    pub token_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub issuer_service: String,
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
