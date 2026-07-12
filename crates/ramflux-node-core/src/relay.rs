// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    NodeCoreError, RELAY_CACHE_KEY, RELAY_CACHE_TABLE, RELAY_CHUNK_ENTRY_TABLE,
    RELAY_TOMBSTONE_TABLE,
};
use hmac::{Hmac, Mac};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, fs};

type HmacSha256 = Hmac<sha2::Sha256>;

pub const OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS: u64 = 15 * 60;
pub const OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const OBJECT_RELAY_CHUNK_MAX_TTL_ENV: &str = "RAMFLUX_RELAY_OBJECT_MAX_TTL_SECONDS";
pub const OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;
pub const OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS: u64 = 60;
pub const OBJECT_RELAY_TOKEN_VERSION: u32 = 2;
pub const OBJECT_RELAY_TOKEN_ISSUER_GATEWAY: &str = "ramflux-gateway";
pub const OBJECT_RELAY_TOKEN_AUDIENCE_RELAY: &str = "ramflux-relay";
pub const OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS: u64 = 300;
const RELAY_COMMIT_BATCH_MAX_ENV: &str = "RAMFLUX_RELAY_COMMIT_BATCH_MAX";
const RELAY_COMMIT_BATCH_MAX_DEFAULT: usize = 256;
const RELAY_COMMIT_WINDOW_US_ENV: &str = "RAMFLUX_RELAY_COMMIT_WINDOW_US";
const RELAY_COMMIT_WINDOW_US_DEFAULT: u64 = 1_000;
const RELAY_COMMIT_QUEUE_CAPACITY_ENV: &str = "RAMFLUX_RELAY_COMMIT_QUEUE_CAPACITY";
const RELAY_COMMIT_QUEUE_CAPACITY_DEFAULT: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayChunkStatus {
    Available,
    Expired,
    AckedDeleted,
    Tombstoned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRelayCapability {
    Put,
    Get,
    Ack,
    Tombstone,
}

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
pub struct GatewayRelayTokenV3IssueRequest {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: RelayTokenV3IssueRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayRelayTokenV3IssueResponse {
    pub relay_token: RelayTokenV3,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectChunkFrame {
    pub schema: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_id: String,
    pub chunk_cipher_hash: String,
    pub cipher_size: u64,
    pub encrypted_chunk: Vec<u8>,
    pub relay_token: RelayToken,
    pub object_permission_envelope: ObjectPermissionEnvelope,
    pub expires_at: u64,
    pub delete_after_ack: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayAck {
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub relay_token: RelayToken,
    pub object_permission_envelope: ObjectPermissionEnvelope,
    pub acked_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayGetRequest {
    pub chunk_id: String,
    pub relay_token: RelayToken,
    pub object_permission_envelope: ObjectPermissionEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayPutResponse {
    pub chunk_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub expires_at: u64,
    pub status: RelayChunkStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayGetResponse {
    pub chunk: RelayChunkEntry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayAckResponse {
    pub chunk_id: String,
    pub status: RelayChunkStatus,
    pub acked_by_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayTombstoneResponse {
    pub object_id: String,
    pub tombstone_hash: String,
    pub expires_at: u64,
}

impl From<RelayChunkEntry> for ObjectRelayPutResponse {
    fn from(entry: RelayChunkEntry) -> Self {
        Self {
            chunk_id: entry.chunk_id,
            object_id: entry.object_id,
            manifest_hash: entry.manifest_hash,
            expires_at: entry.expires_at,
            status: entry.status,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectRelayTombstone {
    pub object_id: String,
    pub manifest_hash: Option<String>,
    pub tombstone_hash: String,
    pub source_event_id: String,
    pub signed_at: u64,
    pub expires_at: u64,
    pub relay_token: RelayToken,
    pub object_permission_envelope: ObjectPermissionEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayChunkEntry {
    pub chunk_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_cipher_hash: String,
    /// Immutable identity of the device that originally uploaded this chunk. Bound at put time
    /// and never mutated. Legacy records persisted before owner binding existed deserialize with
    /// empty strings via `serde(default)`.
    ///
    /// Enforcement status (RQ-03, partial): only put-overwrite and tombstone currently fail closed
    /// on an empty (legacy) or foreign owner binding. Get/Ack owner enforcement is NOT yet landed
    /// (deferred to the owner-grant / issuer-attestation work), so an unbound legacy chunk is at
    /// present still readable and ackable. Do not rely on this field to gate reads/acks yet.
    #[serde(default)]
    pub owner_signing_key_id: String,
    #[serde(default)]
    pub owner_public_key: String,
    pub encrypted_chunk: Vec<u8>,
    pub stored_at: u64,
    pub expires_at: u64,
    pub delete_after_ack: bool,
    pub acked_by: BTreeSet<String>,
    pub status: RelayChunkStatus,
}

impl RelayChunkEntry {
    /// Returns `true` only when the chunk carries a non-empty immutable owner binding.
    #[must_use]
    pub fn has_owner_binding(&self) -> bool {
        !self.owner_signing_key_id.is_empty() && !self.owner_public_key.is_empty()
    }

    /// Returns `true` when the chunk's persisted original owner matches the token's owner. A chunk
    /// missing its owner binding (legacy record) never matches. This is currently consulted only by
    /// put-overwrite and tombstone, which therefore fail closed on a legacy or foreign owner;
    /// get/ack do not yet call this (their owner enforcement is deferred).
    #[must_use]
    fn owner_matches_token(&self, token: &RelayToken) -> bool {
        self.has_owner_binding()
            && self.owner_signing_key_id == token.owner_signing_key_id
            && self.owner_public_key == token.owner_public_key
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayCacheState {
    chunks_by_id: BTreeMap<String, RelayChunkEntry>,
    tombstones_by_object_id: BTreeMap<String, ObjectRelayTombstone>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRelayTombstoneMutation {
    pub tombstone: ObjectRelayTombstone,
    pub affected_chunks: Vec<RelayChunkEntry>,
    /// `true` only when this mutation applied a durable change (the first tombstone for the object).
    /// A stable idempotent replay sets this to `false`, so `record_relay_tombstone_mutation` is a
    /// complete no-op and never rewrites the redb tombstone/chunk rows.
    pub changed: bool,
}

/// The already-verified inputs for an owner-session (v3) tombstone. The caller (relay client QUIC
/// ingress) must have verified the v3 invocation — owner authorization proof + requester `PoP` — and
/// pass the owner identity and tombstone metadata it bound. `manifest_hash` scopes the tombstone to a
/// single manifest (`Some`) or the whole object (`None`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSessionTombstoneRequest {
    pub object_id: String,
    pub manifest_hash: Option<String>,
    pub tombstone_hash: String,
    pub source_event_id: String,
    pub signed_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayExpiryMutation {
    pub expired_chunk_ids: Vec<String>,
    pub expired_tombstone_object_ids: Vec<String>,
}

impl RelayExpiryMutation {
    #[must_use]
    pub fn expired_count(&self) -> usize {
        self.expired_chunk_ids.len() + self.expired_tombstone_object_ids.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expired_chunk_ids.is_empty() && self.expired_tombstone_object_ids.is_empty()
    }
}

impl RelayCacheState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_chunk(&mut self, entry: RelayChunkEntry) {
        self.chunks_by_id.insert(entry.chunk_id.clone(), entry);
    }

    /// # Errors
    /// Returns an error when token, object permission, TTL, tombstone, size or ciphertext hash
    /// validation fails.
    pub fn put_object_chunk_frame(
        &mut self,
        frame: ObjectChunkFrame,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkEntry, NodeCoreError> {
        validate_object_chunk_frame(&frame, relay_service_key, ObjectRelayCapability::Put, now)?;
        if self.tombstones_by_object_id.contains_key(&frame.object_id) {
            return Err(NodeCoreError::ItestHttp(
                "object relay tombstone blocks chunk put".to_owned(),
            ));
        }
        // The token owner equals the permission owner (verified in `validate_object_chunk_frame`).
        // This immutable identity becomes the chunk's original owner binding.
        let owner_signing_key_id = frame.relay_token.owner_signing_key_id.clone();
        let owner_public_key = frame.relay_token.owner_public_key.clone();
        if owner_signing_key_id.is_empty() || owner_public_key.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "object relay put missing owner binding".to_owned(),
            ));
        }
        // A chunk id can be re-put only by its original owner with byte-identical content
        // (idempotent replay for resume/retry). Cross-owner writes, content overwrites, and
        // resurrection of an already-consumed chunk are rejected without mutating state.
        if let Some(existing) = self.chunks_by_id.get(&frame.chunk_id) {
            if !existing.has_owner_binding()
                || existing.owner_signing_key_id != owner_signing_key_id
                || existing.owner_public_key != owner_public_key
            {
                return Err(NodeCoreError::Unauthorized(
                    "object relay put rejects cross-owner chunk overwrite".to_owned(),
                ));
            }
            if existing.object_id != frame.object_id
                || existing.manifest_hash != frame.manifest_hash
                || existing.chunk_index != frame.chunk_index
                || existing.chunk_cipher_hash != frame.chunk_cipher_hash
                || existing.encrypted_chunk != frame.encrypted_chunk
            {
                return Err(NodeCoreError::Unauthorized(
                    "object relay put rejects chunk content overwrite".to_owned(),
                ));
            }
            if existing.status != RelayChunkStatus::Available {
                return Err(NodeCoreError::Unauthorized(
                    "object relay put cannot resurrect a consumed chunk".to_owned(),
                ));
            }
            // Exact same-owner, same-content replay is idempotent: return the stored entry
            // unchanged so acked_by, stored_at, expires_at, delete policy and status are preserved
            // (never reset). Zero mutation.
            return Ok(existing.clone());
        }
        let expires_at = clamp_relay_chunk_expires_at(now, frame.expires_at);
        let entry = RelayChunkEntry {
            chunk_id: frame.chunk_id,
            object_id: frame.object_id,
            manifest_hash: frame.manifest_hash,
            chunk_index: frame.chunk_index,
            chunk_cipher_hash: frame.chunk_cipher_hash,
            owner_signing_key_id,
            owner_public_key,
            encrypted_chunk: frame.encrypted_chunk,
            stored_at: now,
            expires_at,
            delete_after_ack: frame.delete_after_ack,
            acked_by: BTreeSet::new(),
            status: RelayChunkStatus::Available,
        };
        self.put_chunk(entry.clone());
        Ok(entry)
    }

    /// # Errors
    /// Returns an error when token or permission validation fails, the chunk is missing, or it is
    /// expired/tombstoned.
    pub fn get_object_chunk(
        &self,
        chunk_id: &str,
        token: &RelayToken,
        permission: &ObjectPermissionEnvelope,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkEntry, NodeCoreError> {
        validate_relay_token(token, relay_service_key, ObjectRelayCapability::Get, now)?;
        validate_object_permission(permission, ObjectRelayCapability::Get, now)?;
        if token.chunk_id != chunk_id
            || permission.object_id != token.object_id
            || permission.manifest_hash != token.manifest_hash
            || permission.grantee_device_hash != token.recipient_device_hash
            || !permission_owner_matches_token(permission, token)
        {
            return Err(NodeCoreError::ItestHttp("object relay get binding mismatch".to_owned()));
        }
        let chunk = self
            .get_available_chunk(chunk_id, now)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(chunk_id.to_owned()))?;
        // NOTE (RQ-03 follow-up / finding "C"): binding the retrieved chunk's original owner to the
        // requester requires an uploader-signed Get/Ack grant. The current SDK self-signs the
        // downloader device as owner==grantee, so an owner-equality check here would reject the
        // legitimate own-device-sync (A uploads, B downloads) and DM-attachment flows. Owner
        // binding on get is intentionally deferred until the owner-signed grant model lands.
        if self.tombstones_by_object_id.contains_key(&chunk.object_id) {
            return Err(NodeCoreError::ItestHttp(
                "object relay tombstone blocks chunk get".to_owned(),
            ));
        }
        Ok(chunk.clone())
    }

    /// # Errors
    /// Returns an error when token/permission validation fails or the chunk is missing.
    pub fn ack_object_chunk(
        &mut self,
        ack: ObjectRelayAck,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<RelayChunkEntry, NodeCoreError> {
        validate_relay_token(&ack.relay_token, relay_service_key, ObjectRelayCapability::Ack, now)?;
        validate_object_permission(
            &ack.object_permission_envelope,
            ObjectRelayCapability::Ack,
            now,
        )?;
        if ack.relay_token.object_id != ack.object_id
            || ack.relay_token.manifest_hash != ack.manifest_hash
            || ack.relay_token.chunk_id != ack.chunk_id
            || ack.relay_token.recipient_device_hash != ack.recipient_device_hash
            || ack.object_permission_envelope.object_id != ack.object_id
            || ack.object_permission_envelope.manifest_hash != ack.manifest_hash
            || ack.object_permission_envelope.grantee_device_hash != ack.recipient_device_hash
            || !permission_owner_matches_token(&ack.object_permission_envelope, &ack.relay_token)
        {
            return Err(NodeCoreError::ItestHttp("object relay ack binding mismatch".to_owned()));
        }
        let chunk = self
            .chunks_by_id
            .get_mut(&ack.chunk_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.chunk_id.clone()))?;
        if chunk.object_id != ack.object_id || chunk.manifest_hash != ack.manifest_hash {
            return Err(NodeCoreError::ItestHttp("object relay ack binding mismatch".to_owned()));
        }
        // NOTE (RQ-03 follow-up / finding "C"): matching the ack to the chunk's original owner
        // depends on the same uploader-signed grant model as get and is deferred; the current SDK
        // self-signs the acking device as owner. The delete-policy hardening below is independent
        // of that model and is enforced now.
        chunk.acked_by.insert(ack.recipient_device_hash);
        // Deletion on ack is governed solely by the delete policy the owner stored at put time.
        // A requester cannot self-elevate deletion by flipping `delete_after_ack` in the token.
        if chunk.delete_after_ack {
            chunk.status = RelayChunkStatus::AckedDeleted;
            chunk.encrypted_chunk.clear();
        }
        Ok(chunk.clone())
    }

    /// # Errors
    /// Returns an error when token/permission validation fails.
    pub fn apply_object_tombstone(
        &mut self,
        tombstone: ObjectRelayTombstone,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<ObjectRelayTombstone, NodeCoreError> {
        Ok(self.apply_object_tombstone_mutation(tombstone, relay_service_key, now)?.tombstone)
    }

    /// # Errors
    /// Returns an error when token/permission validation fails.
    pub fn apply_object_tombstone_mutation(
        &mut self,
        tombstone: ObjectRelayTombstone,
        relay_service_key: &[u8],
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        validate_relay_token(
            &tombstone.relay_token,
            relay_service_key,
            ObjectRelayCapability::Tombstone,
            now,
        )?;
        validate_object_permission(
            &tombstone.object_permission_envelope,
            ObjectRelayCapability::Tombstone,
            now,
        )?;
        if tombstone.relay_token.object_id != tombstone.object_id
            || tombstone
                .manifest_hash
                .as_ref()
                .is_some_and(|manifest_hash| &tombstone.relay_token.manifest_hash != manifest_hash)
            || tombstone.object_permission_envelope.object_id != tombstone.object_id
            || tombstone.manifest_hash.as_ref().is_some_and(|manifest_hash| {
                &tombstone.object_permission_envelope.manifest_hash != manifest_hash
            })
            || !permission_owner_matches_token(
                &tombstone.object_permission_envelope,
                &tombstone.relay_token,
            )
        {
            return Err(NodeCoreError::ItestHttp(
                "object relay tombstone binding mismatch".to_owned(),
            ));
        }
        self.apply_object_tombstone_record(tombstone, now)
    }

    /// Post-validation tombstone core shared by the v2 (`apply_object_tombstone_mutation`) and the v3
    /// owner-session (`apply_owner_session_tombstone`) paths. `retained` must already carry the
    /// verified owner identity in `relay_token.owner_signing_key_id`/`owner_public_key`. The
    /// fail-closed TTL, idempotent-replay (zero mutation), cross-owner scope, empty-scope, and
    /// tombstone-wins (chunk cleared) semantics are unchanged from the original v2 implementation.
    fn apply_object_tombstone_record(
        &mut self,
        retained: ObjectRelayTombstone,
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        // Retention TTL is fail-closed for both first application and replay: the signed
        // tombstone's own expiry must still be a bounded future value. It is never clamped down to
        // MAX nor silently promoted from a past value to now+DEFAULT (which would be an implicit
        // privilege extension). Keeping the stored value equal to the request value also makes a
        // byte-identical in-window replay match after a lost response.
        if retained.expires_at <= now
            || retained.expires_at > now.saturating_add(OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS)
        {
            return Err(NodeCoreError::TtlExpired { envelope_id: retained.object_id.clone() });
        }
        // Idempotent replay guard, before any expiry recompute or chunk mutation. A tombstone for an
        // object id is recorded exactly once: a byte-for-byte semantically identical replay (same
        // owner, manifest scope, tombstone_hash, source_event_id, signed_at and the retention
        // expiry stored on first apply) returns the stored record unchanged — expiry is never
        // recomputed or extended, chunk state is not rewritten. Any deviation is rejected.
        if let Some(existing) = self.tombstones_by_object_id.get(&retained.object_id) {
            if existing_tombstone_matches_replay(existing, &retained) {
                return Ok(ObjectRelayTombstoneMutation {
                    tombstone: existing.clone(),
                    affected_chunks: Vec::new(),
                    changed: false,
                });
            }
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone conflicts with existing record".to_owned(),
            ));
        }
        // Verify ownership across every chunk this tombstone would touch before mutating anything.
        // A tombstone may only delete chunks uploaded by its own owner; a chunk owned by a
        // different device (or an unbound legacy record) makes the whole request fail closed so no
        // partial deletion is persisted.
        let matches_scope = |chunk: &RelayChunkEntry| {
            chunk.object_id == retained.object_id
                && retained
                    .manifest_hash
                    .as_ref()
                    .is_none_or(|manifest| manifest == &chunk.manifest_hash)
        };
        if self
            .chunks_by_id
            .values()
            .any(|chunk| matches_scope(chunk) && !chunk.owner_matches_token(&retained.relay_token))
        {
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone owner binding mismatch".to_owned(),
            ));
        }
        // Fail closed on an empty scope: with no object-owner registry, a tombstone that matches
        // zero currently stored chunks cannot prove the requester owns the object id, so it must be
        // rejected without recording an object-level tombstone. Otherwise any authenticated device
        // could pre-place a tombstone on an object id and block the real owner's future puts.
        let mut affected_chunks = Vec::new();
        for chunk in self.chunks_by_id.values_mut() {
            if matches_scope(chunk) {
                chunk.status = RelayChunkStatus::Tombstoned;
                chunk.encrypted_chunk.clear();
                affected_chunks.push(chunk.clone());
            }
        }
        if affected_chunks.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "object relay tombstone matches no owned chunk".to_owned(),
            ));
        }
        self.tombstones_by_object_id.insert(retained.object_id.clone(), retained.clone());
        Ok(ObjectRelayTombstoneMutation { tombstone: retained, affected_chunks, changed: true })
    }

    /// Applies an owner-session (v3) tombstone whose invocation the caller has already verified
    /// (owner authorization proof + requester `PoP`). It takes the verified owner identity and the
    /// tombstone metadata directly — it does NOT re-run v2 token/permission MAC validation — and
    /// delegates to the shared post-validation core, so the empty-scope, cross-owner, replay
    /// zero-mutation, and tombstone-wins semantics are identical to the v2 path.
    ///
    /// # Errors
    /// Returns an error when the owner binding is missing, or when the shared core rejects the
    /// tombstone (bad TTL, replay conflict, cross-owner scope, or an empty scope).
    pub fn apply_owner_session_tombstone(
        &mut self,
        request: OwnerSessionTombstoneRequest,
        now: u64,
    ) -> Result<ObjectRelayTombstoneMutation, NodeCoreError> {
        if request.owner_signing_key_id.is_empty() || request.owner_public_key.is_empty() {
            return Err(NodeCoreError::Unauthorized(
                "owner-session tombstone missing owner binding".to_owned(),
            ));
        }
        // The stored record is an `ObjectRelayTombstone`; the shared core (and the replay guard) only
        // consult the owner identity on `relay_token`, so the verified owner identity is carried
        // there and the v2-only MAC/nonce/permission fields are left inert.
        let relay_token = RelayToken {
            token_version: OBJECT_RELAY_TOKEN_VERSION,
            token_id: String::new(),
            object_id: request.object_id.clone(),
            manifest_hash: request.manifest_hash.clone().unwrap_or_default(),
            chunk_id: String::new(),
            recipient_device_hash: String::new(),
            owner_signing_key_id: request.owner_signing_key_id.clone(),
            owner_public_key: request.owner_public_key.clone(),
            issuer_service: String::new(),
            audience_service: String::new(),
            capabilities: vec![ObjectRelayCapability::Tombstone],
            delete_after_ack: false,
            issued_at: request.signed_at,
            expires_at: request.expires_at,
            nonce: String::new(),
            mac: String::new(),
        };
        let object_permission_envelope = ObjectPermissionEnvelope {
            object_id: request.object_id.clone(),
            manifest_hash: request.manifest_hash.clone().unwrap_or_default(),
            grantee_device_hash: String::new(),
            capability: ObjectRelayCapability::Tombstone,
            issued_at: request.signed_at,
            expires_at: request.expires_at,
            owner_signing_key_id: request.owner_signing_key_id.clone(),
            owner_public_key: request.owner_public_key.clone(),
            owner_signature: String::new(),
        };
        let retained = ObjectRelayTombstone {
            object_id: request.object_id,
            manifest_hash: request.manifest_hash,
            tombstone_hash: request.tombstone_hash,
            source_event_id: request.source_event_id,
            signed_at: request.signed_at,
            expires_at: request.expires_at,
            relay_token,
            object_permission_envelope,
        };
        self.apply_object_tombstone_record(retained, now)
    }

    #[must_use]
    pub fn get_available_chunk(&self, chunk_id: &str, now: u64) -> Option<&RelayChunkEntry> {
        self.chunks_by_id
            .get(chunk_id)
            .filter(|entry| entry.status == RelayChunkStatus::Available && entry.expires_at > now)
    }

    #[must_use]
    pub fn chunk_entry(&self, chunk_id: &str) -> Option<&RelayChunkEntry> {
        self.chunks_by_id.get(chunk_id)
    }

    pub fn expire_chunks(&mut self, now: u64) -> usize {
        self.expire_chunks_mutation(now).expired_count()
    }

    #[must_use]
    pub fn expire_chunks_mutation(&mut self, now: u64) -> RelayExpiryMutation {
        let mut expired_chunk_ids = Vec::new();
        self.chunks_by_id.retain(|chunk_id, entry| {
            if entry.expires_at <= now {
                expired_chunk_ids.push(chunk_id.clone());
                false
            } else {
                true
            }
        });
        let mut expired_tombstone_object_ids = Vec::new();
        self.tombstones_by_object_id.retain(|object_id, tombstone| {
            if tombstone.expires_at <= now {
                expired_tombstone_object_ids.push(object_id.clone());
                false
            } else {
                true
            }
        });
        RelayExpiryMutation { expired_chunk_ids, expired_tombstone_object_ids }
    }

    #[must_use]
    pub fn available_count(&self, now: u64) -> usize {
        self.chunks_by_id
            .values()
            .filter(|entry| entry.status == RelayChunkStatus::Available && entry.expires_at > now)
            .count()
    }

    #[must_use]
    pub fn tombstone(&self, object_id: &str) -> Option<&ObjectRelayTombstone> {
        self.tombstones_by_object_id.get(object_id)
    }
}

fn relay_token_default_version() -> u32 {
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
/// Returns an error when the issuance body is invalid or token signing fails.
pub fn issue_gateway_relay_token(
    service_key: &[u8],
    body: &RelayTokenIssueBody,
    now: u64,
) -> Result<RelayToken, NodeCoreError> {
    validate_relay_token_issue_body(body, now)?;
    let mut token = RelayToken {
        token_version: OBJECT_RELAY_TOKEN_VERSION,
        token_id: format!("token:{}:{}:{:?}", body.chunk_id, body.expires_at, body.capability),
        object_id: body.object_id.clone(),
        manifest_hash: body.manifest_hash.clone(),
        chunk_id: body.chunk_id.clone(),
        recipient_device_hash: body.recipient_device_hash.clone(),
        owner_signing_key_id: body.owner_signing_key_id.clone(),
        owner_public_key: body.owner_public_key.clone(),
        issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
        audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
        capabilities: vec![body.capability],
        delete_after_ack: body.delete_after_ack,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        nonce: ramflux_protocol::encode_base64url(
            ramflux_crypto::random_32()
                .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?,
        ),
        mac: String::new(),
    };
    token.mac = relay_token_mac(service_key, &token)?;
    Ok(token)
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

fn permission_owner_matches_token(
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
fn existing_tombstone_matches_replay(
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

#[must_use]
pub fn object_relay_chunk_cipher_hash(
    manifest_hash: &str,
    chunk_index: u32,
    encrypted_chunk: &[u8],
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(manifest_hash.as_bytes());
    bytes.extend_from_slice(&chunk_index.to_be_bytes());
    bytes.extend_from_slice(encrypted_chunk);
    ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_CHUNK_ID, &bytes)
}

#[must_use]
pub fn clamp_relay_chunk_expires_at(now: u64, requested: u64) -> u64 {
    clamp_relay_chunk_expires_at_with_max_ttl(now, requested, object_relay_chunk_max_ttl_seconds())
}

#[must_use]
pub fn clamp_relay_chunk_expires_at_with_max_ttl(
    now: u64,
    requested: u64,
    max_ttl_seconds: u64,
) -> u64 {
    let default = now.saturating_add(OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS);
    let max = now.saturating_add(max_ttl_seconds.max(1));
    if requested <= now { default } else { requested.min(max) }
}

#[must_use]
pub fn object_relay_chunk_max_ttl_seconds() -> u64 {
    object_relay_chunk_max_ttl_seconds_from_env(
        env::var(OBJECT_RELAY_CHUNK_MAX_TTL_ENV).ok().as_deref(),
    )
}

#[must_use]
fn object_relay_chunk_max_ttl_seconds_from_env(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|ttl| *ttl > 0)
        .unwrap_or(OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS)
}

#[must_use]
pub fn object_relay_retention_record(
    entry: &RelayChunkEntry,
    now: u64,
) -> crate::RetentionMetadataRecord {
    crate::RetentionMetadataRecord {
        record_id: format!("object_relay:{}:{}", entry.object_id, entry.chunk_id),
        subject_hash: entry.object_id.clone(),
        metadata_class: "transport_relay_chunk_cache".to_owned(),
        source_service_id: "relay".to_owned(),
        retention_policy_id: "transport_relay_chunk_cache.default_15m_max_24h".to_owned(),
        created_at: now,
        expires_at: entry.expires_at,
        delete_after_ack: if entry.delete_after_ack { Some(now) } else { None },
        legal_hold: false,
        legal_hold_next_review_at: None,
        legal_basis: None,
        legal_hold_actor: None,
        legal_hold_created_at: None,
        metadata_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.retention_metadata.v1",
            format!("{}:{}:{}", entry.object_id, entry.manifest_hash, entry.chunk_id).as_bytes(),
        ),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).fold(0_u8, |acc, (left, right)| acc | (left ^ right)) == 0
}

// ===========================================================================================
// RQ-03-V3-T1: object relay v3 proof types + pure verification logic.
//
// This block is NOT wired into any production handler. It defines the asymmetric issuer-attestation
// token (v3), the owner-signed access grant, the owner authorization proof and the per-invocation
// requester proof-of-possession, plus pure verifiers and a capability/proof matrix. The existing v2
// HMAC path (RelayToken/validate_relay_token) is untouched. v3 has no HMAC/shared-key surface.
// ===========================================================================================

pub const OBJECT_RELAY_TOKEN_V3_VERSION: u32 = 3;
pub const OBJECT_ACCESS_GRANT_SCHEMA: &str = "ramflux.object_access_grant.v3";
pub const OWNER_AUTHORIZATION_PROOF_SCHEMA: &str = "ramflux.owner_authorization_proof.v3";
pub const REQUESTER_POP_SCHEMA: &str = "ramflux.requester_proof_of_possession.v3";
pub const RELAY_TOKEN_V3_AUDIENCE_RELAY: &str = "ramflux-relay";
pub const GATEWAY_ISSUER_CERTIFICATE_SCHEMA: &str = "ramflux.gateway_issuer_certificate.v3";
pub const GATEWAY_CERTIFICATE_REQUEST_SCHEMA: &str = "ramflux.gateway_certificate_request.v3";
/// Hard upper bound on an issued certificate's validity window (`not_after - now`). Short-lived
/// certificates keep the revocation/rotation risk window small.
pub const GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS: u64 = 6 * 60 * 60;
/// Maximum accepted age of a certificate request's `requested_at` relative to `now`. Bounds how long
/// a captured, validly-signed request stays acceptable; it is a freshness window only and is NOT a
/// persistent nonce replay guard (that lives in the signer integration).
pub const GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS: u64 = 300;
pub const FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot.v3";
/// T23-A2b2b: legacy single-pinned-key envelope schema — gated to the legacy compatibility path.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub const FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot_envelope.v3";
/// T23-A2b2: the out-of-band, offline-root-signed provider keyring document (independent of any
/// snapshot; never self-certified by a provider/snapshot key).
pub const PROVIDER_KEYRING_SCHEMA: &str = "ramflux.federation_provider_keyring.v1";
pub const PROVIDER_KEYRING_VERSION: u32 = 1;
const PROVIDER_KEYRING_FINGERPRINT_DOMAIN: &str =
    "ramflux.federation_provider_keyring.fingerprint.v1";
/// T23-A2b2: the versioned provider-signed trust-snapshot envelope carrying `provider_epoch`. This is
/// the production keyring-era envelope; the legacy single-pin `..._envelope.v3` schema is hard-rejected
/// by the keyring verifier and only parsed by the compile-gated `itest-provider-single-key` path.
pub const PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_issuer_trust_snapshot_envelope.v4";
pub const PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION: u32 = 4;
const OBJECT_ACCESS_GRANT_BINDING_DOMAIN: &str = "ramflux.object_access_grant.binding.v3";
const OWNER_AUTHORIZATION_PROOF_BINDING_DOMAIN: &str =
    "ramflux.owner_authorization_proof.binding.v3";
const GATEWAY_ISSUER_CERTIFICATE_BINDING_DOMAIN: &str =
    "ramflux.gateway_issuer_certificate.binding.v3";

/// Which authorization instrument backs a v3 token. Get/Ack are backed by an owner-signed grant;
/// Put/Tombstone are backed by an authenticated owner session + owner authorization proof.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayAuthorizationKind {
    OwnerGrant,
    OwnerSession,
}

/// Owner-signed authorization that grantee `grantee_device_hash` may Get/Ack an object. Signed by
/// the owner device; the relay's chunk-owner binding is the ultimate anchor. Grants may only carry
/// Get/Ack capabilities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectAccessGrant {
    pub schema: String,
    pub version: u32,
    pub object_id: String,
    pub manifest_hash: String,
    pub grantee_device_hash: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

/// Owner-signed proof authorizing a Put/Tombstone. Deliberately does NOT contain a `token_id`: it is
/// produced before any token exists, so binding it to a future token id would be circular. The
/// per-invocation `RequesterProofOfPossession` is what binds `token_id`/capability/chunk/nonce/body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerAuthorizationProof {
    pub schema: String,
    pub version: u32,
    pub capability: ObjectRelayCapability,
    pub object_id: String,
    pub manifest_hash: Option<String>,
    pub chunk_id: Option<String>,
    pub owner_home_node_id: String,
    pub owner_principal_id: String,
    pub owner_device_epoch: u64,
    pub request_nonce: String,
    pub body_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_signature: String,
}

/// Per-invocation proof that the caller currently holds the requester device private key. Signed by
/// the requester device at call time and bound to the specific token and request frame, so a leaked
/// bearer token cannot be replayed by a party without the requester key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequesterProofOfPossession {
    pub schema: String,
    pub version: u32,
    pub token_id: String,
    pub capability: ObjectRelayCapability,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub request_nonce: String,
    pub body_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signer_device_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

/// Asymmetric issuer-attestation relay token (v3). Signed by the issuing gateway's attestation key
/// (verified by the relay against a node-root-signed certificate, out of scope for T1). No HMAC/mac
/// field exists; there is no shared-key path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenV3 {
    pub token_version: u32,
    pub token_id: String,
    pub requester_device_id: String,
    pub requester_device_hash: String,
    pub requester_public_key: String,
    pub requester_device_epoch: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_home_node_id: String,
    pub owner_principal_id: String,
    pub owner_device_epoch: u64,
    pub issuer_node_id: String,
    pub gateway_instance_id: String,
    pub issuer_certificate_id: String,
    pub attestation_key_id: String,
    /// The gateway issuer certificate carried inline with the token/frame. It participates in the
    /// token's canonical bytes, so `issuer_signature` commits to it and a frame cannot swap it. The
    /// relay still verifies this certificate against a pinned node-root key and against the expected
    /// certificate it holds.
    pub issuer_certificate: GatewayIssuerCertificate,
    pub audience_service: String,
    pub audience_node_id: String,
    pub relay_instance_id: Option<String>,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub authorization_kind: RelayAuthorizationKind,
    pub authorization_binding_hash: String,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub issuer_signature: String,
}

/// Inputs supplied by an authenticated gateway when issuing an asymmetric v3 relay token.
/// Certificate/root trust verification is performed by the relay verifier; issuance still checks
/// the certificate identity/window and all token binding invariants before signing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayTokenV3IssueRequest {
    pub requester_device_id: String,
    pub requester_device_hash: String,
    pub requester_public_key: String,
    pub requester_device_epoch: u64,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub owner_home_node_id: String,
    pub owner_principal_id: String,
    pub owner_device_epoch: u64,
    pub issuer_node_id: String,
    pub gateway_instance_id: String,
    pub audience_node_id: String,
    pub relay_instance_id: Option<String>,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub authorization_kind: RelayAuthorizationKind,
    pub authorization_binding_hash: String,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub issuer_certificate: GatewayIssuerCertificate,
}

/// Issues an issuer-signed v3 relay token after validating its security bindings.
///
/// This is deliberately independent of gateway session/authentication state. The caller must
/// authenticate the session and provide the issuer private key; this function enforces the token
/// shape, certificate binding, capability/authorization matrix, and bounded TTL.
///
/// # Errors
/// Returns an error when identity fields, certificate binding, TTL, capability matrix, or signing
/// inputs are invalid.
pub fn issue_gateway_relay_token_v3(
    request: &RelayTokenV3IssueRequest,
    issuer_signing_seed: [u8; 32],
    now: u64,
) -> Result<RelayTokenV3, NodeCoreError> {
    require_non_empty(&request.requester_device_id, "requester_device_id")?;
    require_non_empty(&request.requester_device_hash, "requester_device_hash")?;
    require_non_empty(&request.requester_public_key, "requester_public_key")?;
    require_non_empty(&request.owner_signing_key_id, "owner_signing_key_id")?;
    require_non_empty(&request.owner_public_key, "owner_public_key")?;
    require_non_empty(&request.owner_home_node_id, "owner_home_node_id")?;
    require_non_empty(&request.owner_principal_id, "owner_principal_id")?;
    require_non_empty(&request.issuer_node_id, "issuer_node_id")?;
    require_non_empty(&request.gateway_instance_id, "gateway_instance_id")?;
    require_non_empty(&request.audience_node_id, "audience_node_id")?;
    require_non_empty(&request.object_id, "object_id")?;
    require_non_empty(&request.manifest_hash, "manifest_hash")?;
    require_non_empty(&request.chunk_id, "chunk_id")?;
    require_non_empty(&request.authorization_binding_hash, "authorization_binding_hash")?;
    require_non_empty(&request.nonce, "nonce")?;
    if request.issuer_certificate.node_id != request.issuer_node_id
        || request.issuer_certificate.gateway_instance_id != request.gateway_instance_id
    {
        return Err(NodeCoreError::Unauthorized(
            "relay token issuer certificate identity mismatch".to_owned(),
        ));
    }
    if request.issuer_certificate.revoked_at.is_some()
        || now < request.issuer_certificate.not_before
        || now >= request.issuer_certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.object_id.clone() });
    }
    if request.issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || request.expires_at <= now
        || request.expires_at > now.saturating_add(OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS)
        || request.expires_at > request.issuer_certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.chunk_id.clone() });
    }
    if request.capabilities.len() != 1 {
        return Err(NodeCoreError::Unauthorized(
            "relay v3 token must carry exactly one capability".to_owned(),
        ));
    }
    let capability = request.capabilities[0];
    let expected_kind =
        if matches!(capability, ObjectRelayCapability::Get | ObjectRelayCapability::Ack) {
            RelayAuthorizationKind::OwnerGrant
        } else {
            RelayAuthorizationKind::OwnerSession
        };
    if request.authorization_kind != expected_kind {
        return Err(NodeCoreError::Unauthorized(
            "relay v3 authorization kind does not match capability".to_owned(),
        ));
    }
    if request.delete_after_ack && capability != ObjectRelayCapability::Put {
        return Err(NodeCoreError::Unauthorized(
            "delete_after_ack is only permitted on put relay tokens".to_owned(),
        ));
    }
    let mut token = RelayTokenV3 {
        token_version: OBJECT_RELAY_TOKEN_V3_VERSION,
        token_id: format!("v3:{}:{}:{capability:?}", request.chunk_id, request.expires_at),
        requester_device_id: request.requester_device_id.clone(),
        requester_device_hash: request.requester_device_hash.clone(),
        requester_public_key: request.requester_public_key.clone(),
        requester_device_epoch: request.requester_device_epoch,
        owner_signing_key_id: request.owner_signing_key_id.clone(),
        owner_public_key: request.owner_public_key.clone(),
        owner_home_node_id: request.owner_home_node_id.clone(),
        owner_principal_id: request.owner_principal_id.clone(),
        owner_device_epoch: request.owner_device_epoch,
        issuer_node_id: request.issuer_node_id.clone(),
        gateway_instance_id: request.gateway_instance_id.clone(),
        issuer_certificate_id: request.issuer_certificate.cert_id.clone(),
        attestation_key_id: request.issuer_certificate.attestation_key_id.clone(),
        issuer_certificate: request.issuer_certificate.clone(),
        audience_service: RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
        audience_node_id: request.audience_node_id.clone(),
        relay_instance_id: request.relay_instance_id.clone(),
        object_id: request.object_id.clone(),
        manifest_hash: request.manifest_hash.clone(),
        chunk_id: request.chunk_id.clone(),
        capabilities: request.capabilities.clone(),
        authorization_kind: request.authorization_kind,
        authorization_binding_hash: request.authorization_binding_hash.clone(),
        delete_after_ack: request.delete_after_ack,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        nonce: request.nonce.clone(),
        issuer_signature: String::new(),
    };
    token.issuer_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &relay_token_v3_signing_bytes(&token)?,
        issuer_signing_seed,
    );
    Ok(token)
}

/// Node-root-signed certificate binding a gateway's attestation public key to its node id and
/// instance, with a bounded validity window. The relay verifies this against a pinned node-root
/// public key, then uses `attestation_public_key` to verify a token's `issuer_signature`. Root
/// keyring distribution, rotation, and CRL are out of scope for T2 (the root public key is a pure
/// input here).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayIssuerCertificate {
    pub schema: String,
    pub version: u32,
    pub cert_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub attestation_public_key: String,
    pub attestation_key_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub issued_at: u64,
    pub node_root_signing_key_id: String,
    pub node_root_signature: String,
    pub revoked_at: Option<u64>,
}

/// A gateway's request to a node signer for a `GatewayIssuerCertificate`. It is self-signed with the
/// attestation private key (a proof-of-possession), so the node signer knows the requester actually
/// holds the attestation key it wants certified. It deliberately does NOT carry the future `cert_id`
/// (assigned by the signer). Transport-level authentication of the requesting gateway (mTLS + node
/// instance allowlist) is an integration concern, not part of this pure type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayCertificateRequest {
    pub schema: String,
    pub version: u32,
    pub request_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub attestation_public_key: String,
    pub attestation_key_id: String,
    pub not_before: u64,
    pub not_after: u64,
    pub requested_at: u64,
    pub request_nonce: String,
    pub request_signature: String,
}

/// A revocation record binding a specific issued certificate by all of its identity fields. Applying
/// it stamps `revoked_at` on the certificate, after which the certificate fails closed. Persistent
/// CRL storage and distribution are out of scope (integration concern).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayCertificateRevocation {
    pub cert_id: String,
    pub attestation_key_id: String,
    pub node_id: String,
    pub gateway_instance_id: String,
    pub revoked_at: u64,
}

/// Trust status of a federated issuer node, mirroring the federation trust directory. Only `Active`
/// nodes may back new relay tokens.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedIssuerTrustStatus {
    Invited,
    Active,
    Suspended,
    Revoked,
    Migrated,
}

/// One pinned node-root public key for a federated issuer node, with its own validity window and
/// pin generation. During a root rotation the snapshot carries both the current and the previous
/// (overlapping) root so in-flight certificates signed by either remain verifiable until the older
/// root's window ends or it is retired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedNodeRootKey {
    pub node_id: String,
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    pub pin_epoch: u64,
    pub retired_at: Option<u64>,
}

/// A relay's federated trust snapshot for a single issuer node: the pinned node-root key(s), trust
/// status, revoked certificate ids, and a hard staleness deadline after which the snapshot must not
/// be used. This is the only source of node-root trust for v3 token verification — there is no bare
/// key or HMAC fallback. Keyring distribution, live rotation, and CRL propagation are runtime/
/// provider concerns; this type is the pure, already-fetched snapshot the relay verifies against.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedIssuerTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub node_id: String,
    pub generation: u64,
    pub pin_epoch: u64,
    pub trust_status: FederatedIssuerTrustStatus,
    pub roots: Vec<TrustedNodeRootKey>,
    pub revoked_cert_ids: BTreeSet<String>,
    pub hard_stale_at: u64,
}

pub const FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA: &str =
    "ramflux.federated_trust_snapshot_envelope.v3";

/// Signed transport envelope for a federated trust snapshot. The cache must only receive an
/// envelope after [`verify_federated_trust_snapshot_envelope`] succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedTrustSnapshotEnvelope {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// Returns the canonical bytes signed by the federation trust provider.
///
/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
pub fn federated_trust_snapshot_envelope_signing_bytes(
    envelope: &FederatedTrustSnapshotEnvelope,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut unsigned = envelope.clone();
    unsigned.signature.clear();
    ramflux_protocol::canonical_json_bytes(&unsigned)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a signed trust snapshot envelope before it enters the runtime cache.
///
/// # Errors
/// Returns an error when schema/version, signer binding, validity, signature, or snapshot
/// freshness is invalid.
pub fn verify_federated_trust_snapshot_envelope(
    envelope: &FederatedTrustSnapshotEnvelope,
    expected_node_id: &str,
    expected_signer_key_id: &str,
    expected_signer_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if envelope.schema != FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA
        || envelope.version != OBJECT_RELAY_V3_PROOF_VERSION
    {
        return Err(NodeCoreError::ItestJson(
            "federated trust snapshot envelope schema/version rejected".to_owned(),
        ));
    }
    if envelope.signer_key_id != expected_signer_key_id
        || envelope.signer_public_key != expected_signer_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "federated trust snapshot signer binding mismatch".to_owned(),
        ));
    }
    if envelope.issued_at >= envelope.expires_at
        || now < envelope.issued_at
        || now >= envelope.expires_at
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: envelope.snapshot.node_id.clone() });
    }
    let signing_bytes = federated_trust_snapshot_envelope_signing_bytes(envelope)?;
    ramflux_crypto::verify_canonical_signature(
        &signing_bytes,
        &envelope.signature,
        &envelope.signer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    verify_federated_issuer_trust_snapshot(&envelope.snapshot, expected_node_id, now)
}

/// All inputs the relay needs to authorize a single v3 invocation. Bundled so the matrix verifier
/// stays a single-argument pure function.
pub struct RelayInvocationV3<'a> {
    pub token: &'a RelayTokenV3,
    pub issuer_public_key: &'a str,
    pub grant: Option<&'a ObjectAccessGrant>,
    pub owner_proof: Option<&'a OwnerAuthorizationProof>,
    pub pop: &'a RequesterProofOfPossession,
    pub expected_audience_node_id: &'a str,
    pub expected_body_hash: &'a str,
    pub capability: ObjectRelayCapability,
    pub now: u64,
}

/// Every v3 grant/proof/PoP payload must carry this version; any other value fails closed.
pub const OBJECT_RELAY_V3_PROOF_VERSION: u32 = 3;

#[must_use]
fn is_grant_capability(capability: ObjectRelayCapability) -> bool {
    matches!(capability, ObjectRelayCapability::Get | ObjectRelayCapability::Ack)
}

#[must_use]
fn is_owner_session_capability(capability: ObjectRelayCapability) -> bool {
    matches!(capability, ObjectRelayCapability::Put | ObjectRelayCapability::Tombstone)
}

fn require_non_empty(value: &str, field: &str) -> Result<(), NodeCoreError> {
    if value.is_empty() {
        return Err(NodeCoreError::Unauthorized(format!("relay v3 {field} must not be empty")));
    }
    Ok(())
}

/// Returns `true` when the capability list has no duplicate entries.
#[must_use]
fn capabilities_have_no_duplicates(capabilities: &[ObjectRelayCapability]) -> bool {
    capabilities
        .iter()
        .enumerate()
        .all(|(index, capability)| !capabilities[index + 1..].contains(capability))
}

/// # Errors
/// Returns an error when the grant cannot be canonicalized.
pub fn object_access_grant_signing_bytes(
    grant: &ObjectAccessGrant,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = grant.clone();
    canonical.owner_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the grant cannot be canonicalized. Binds the exact signed grant.
pub fn object_access_grant_binding_hash(
    grant: &ObjectAccessGrant,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(grant)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(OBJECT_ACCESS_GRANT_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the proof cannot be canonicalized.
pub fn owner_authorization_proof_signing_bytes(
    proof: &OwnerAuthorizationProof,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = proof.clone();
    canonical.owner_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the proof cannot be canonicalized. Binds the exact signed proof.
pub fn owner_authorization_proof_binding_hash(
    proof: &OwnerAuthorizationProof,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(proof)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(OWNER_AUTHORIZATION_PROOF_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the `PoP` cannot be canonicalized.
pub fn requester_pop_signing_bytes(
    pop: &RequesterProofOfPossession,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = pop.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the token cannot be canonicalized.
pub fn relay_token_v3_signing_bytes(token: &RelayTokenV3) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = token.clone();
    canonical.issuer_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the certificate cannot be canonicalized.
pub fn gateway_issuer_certificate_signing_bytes(
    certificate: &GatewayIssuerCertificate,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = certificate.clone();
    canonical.node_root_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// # Errors
/// Returns an error when the certificate cannot be canonicalized. Binds the exact signed cert.
pub fn gateway_issuer_certificate_binding_hash(
    certificate: &GatewayIssuerCertificate,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(certificate)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(GATEWAY_ISSUER_CERTIFICATE_BINDING_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the certificate request cannot be canonicalized.
pub fn gateway_certificate_request_signing_bytes(
    request: &GatewayCertificateRequest,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = request.clone();
    canonical.request_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

fn within_ttl(
    issued_at: u64,
    expires_at: u64,
    now: u64,
    envelope_id: &str,
) -> Result<(), NodeCoreError> {
    if issued_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) || expires_at <= now {
        return Err(NodeCoreError::TtlExpired { envelope_id: envelope_id.to_owned() });
    }
    Ok(())
}

/// # Errors
/// Returns an error when the grant schema, capability set, TTL, or owner signature is invalid.
pub fn verify_object_access_grant(
    grant: &ObjectAccessGrant,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if grant.schema != OBJECT_ACCESS_GRANT_SCHEMA {
        return Err(NodeCoreError::ItestJson("object access grant schema rejected".to_owned()));
    }
    if grant.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson("object access grant version rejected".to_owned()));
    }
    if !is_grant_capability(capability) {
        return Err(NodeCoreError::Unauthorized(
            "object access grant only authorizes get/ack".to_owned(),
        ));
    }
    if grant.capabilities.is_empty()
        || grant.capabilities.iter().any(|cap| !is_grant_capability(*cap))
        || !capabilities_have_no_duplicates(&grant.capabilities)
    {
        return Err(NodeCoreError::Unauthorized(
            "object access grant capabilities must be a non-empty, duplicate-free subset of get/ack"
                .to_owned(),
        ));
    }
    if !grant.capabilities.contains(&capability) {
        return Err(NodeCoreError::Unauthorized(
            "object access grant does not cover requested capability".to_owned(),
        ));
    }
    require_non_empty(&grant.object_id, "grant object_id")?;
    require_non_empty(&grant.manifest_hash, "grant manifest_hash")?;
    require_non_empty(&grant.grantee_device_hash, "grant grantee_device_hash")?;
    require_non_empty(&grant.owner_signing_key_id, "grant owner_signing_key_id")?;
    require_non_empty(&grant.owner_public_key, "grant owner_public_key")?;
    require_non_empty(&grant.owner_signature, "grant owner_signature")?;
    within_ttl(grant.issued_at, grant.expires_at, now, &grant.object_id)?;
    ramflux_crypto::verify_canonical_signature(
        &object_access_grant_signing_bytes(grant)?,
        &grant.owner_signature,
        &grant.owner_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the proof schema, capability, TTL, or owner signature is invalid.
pub fn verify_owner_authorization_proof(
    proof: &OwnerAuthorizationProof,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if proof.schema != OWNER_AUTHORIZATION_PROOF_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "owner authorization proof schema rejected".to_owned(),
        ));
    }
    if proof.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "owner authorization proof version rejected".to_owned(),
        ));
    }
    if !is_owner_session_capability(capability) {
        return Err(NodeCoreError::Unauthorized(
            "owner authorization proof only authorizes put/tombstone".to_owned(),
        ));
    }
    if proof.capability != capability {
        return Err(NodeCoreError::Unauthorized(
            "owner authorization proof capability mismatch".to_owned(),
        ));
    }
    require_non_empty(&proof.object_id, "owner proof object_id")?;
    require_non_empty(&proof.owner_home_node_id, "owner proof owner_home_node_id")?;
    require_non_empty(&proof.owner_principal_id, "owner proof owner_principal_id")?;
    require_non_empty(&proof.request_nonce, "owner proof request_nonce")?;
    require_non_empty(&proof.body_hash, "owner proof body_hash")?;
    require_non_empty(&proof.owner_signing_key_id, "owner proof owner_signing_key_id")?;
    require_non_empty(&proof.owner_public_key, "owner proof owner_public_key")?;
    require_non_empty(&proof.owner_signature, "owner proof owner_signature")?;
    within_ttl(proof.issued_at, proof.expires_at, now, &proof.object_id)?;
    ramflux_crypto::verify_canonical_signature(
        &owner_authorization_proof_signing_bytes(proof)?,
        &proof.owner_signature,
        &proof.owner_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the `PoP` schema, TTL, or requester signature is invalid.
pub fn verify_requester_pop(
    pop: &RequesterProofOfPossession,
    signer_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if pop.schema != REQUESTER_POP_SCHEMA {
        return Err(NodeCoreError::ItestJson("requester pop schema rejected".to_owned()));
    }
    if pop.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson("requester pop version rejected".to_owned()));
    }
    require_non_empty(&pop.token_id, "pop token_id")?;
    require_non_empty(&pop.object_id, "pop object_id")?;
    require_non_empty(&pop.manifest_hash, "pop manifest_hash")?;
    require_non_empty(&pop.chunk_id, "pop chunk_id")?;
    require_non_empty(&pop.request_nonce, "pop request_nonce")?;
    require_non_empty(&pop.body_hash, "pop body_hash")?;
    require_non_empty(&pop.signer_device_id, "pop signer_device_id")?;
    require_non_empty(&pop.signer_public_key, "pop signer_public_key")?;
    require_non_empty(&pop.signature, "pop signature")?;
    within_ttl(pop.issued_at, pop.expires_at, now, &pop.token_id)?;
    ramflux_crypto::verify_canonical_signature(
        &requester_pop_signing_bytes(pop)?,
        &pop.signature,
        signer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// # Errors
/// Returns an error when the token version, audience, capability, authorization kind, TTL, or issuer
/// signature is invalid. Rejects any non-v3 token (there is no HMAC/shared-key path).
pub fn verify_relay_token_v3(
    token: &RelayTokenV3,
    issuer_public_key: &str,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if token.token_version != OBJECT_RELAY_TOKEN_V3_VERSION {
        return Err(NodeCoreError::Unauthorized(
            "relay token version rejected: v3 issuer-signed token required".to_owned(),
        ));
    }
    if token.audience_service != RELAY_TOKEN_V3_AUDIENCE_RELAY {
        return Err(NodeCoreError::Unauthorized(
            "relay token audience service rejected".to_owned(),
        ));
    }
    if token.audience_node_id != expected_audience_node_id {
        return Err(NodeCoreError::Unauthorized("relay token audience node rejected".to_owned()));
    }
    if token.capabilities.len() != 1
        || !token.capabilities.contains(&capability)
        || !capabilities_have_no_duplicates(&token.capabilities)
    {
        return Err(NodeCoreError::Unauthorized("relay token capability rejected".to_owned()));
    }
    let expected_kind = if is_grant_capability(capability) {
        RelayAuthorizationKind::OwnerGrant
    } else {
        RelayAuthorizationKind::OwnerSession
    };
    if token.authorization_kind != expected_kind {
        return Err(NodeCoreError::Unauthorized(
            "relay token authorization kind mismatch for capability".to_owned(),
        ));
    }
    // A destructive delete-on-ack policy may only ride on a Put token.
    if token.delete_after_ack && capability != ObjectRelayCapability::Put {
        return Err(NodeCoreError::Unauthorized(
            "relay token delete_after_ack is only permitted for put".to_owned(),
        ));
    }
    // Critical identity/key/hash/nonce fields must be present.
    require_non_empty(&token.token_id, "token token_id")?;
    require_non_empty(&token.requester_device_id, "token requester_device_id")?;
    require_non_empty(&token.requester_device_hash, "token requester_device_hash")?;
    require_non_empty(&token.requester_public_key, "token requester_public_key")?;
    require_non_empty(&token.owner_signing_key_id, "token owner_signing_key_id")?;
    require_non_empty(&token.owner_public_key, "token owner_public_key")?;
    require_non_empty(&token.owner_home_node_id, "token owner_home_node_id")?;
    require_non_empty(&token.owner_principal_id, "token owner_principal_id")?;
    require_non_empty(&token.issuer_node_id, "token issuer_node_id")?;
    require_non_empty(&token.gateway_instance_id, "token gateway_instance_id")?;
    require_non_empty(&token.issuer_certificate_id, "token issuer_certificate_id")?;
    require_non_empty(&token.attestation_key_id, "token attestation_key_id")?;
    require_non_empty(&token.audience_node_id, "token audience_node_id")?;
    require_non_empty(&token.object_id, "token object_id")?;
    require_non_empty(&token.manifest_hash, "token manifest_hash")?;
    require_non_empty(&token.chunk_id, "token chunk_id")?;
    require_non_empty(&token.authorization_binding_hash, "token authorization_binding_hash")?;
    require_non_empty(&token.nonce, "token nonce")?;
    if token.expires_at > token.issued_at.saturating_add(OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS) {
        return Err(NodeCoreError::TtlExpired { envelope_id: token.token_id.clone() });
    }
    within_ttl(token.issued_at, token.expires_at, now, &token.token_id)?;
    ramflux_crypto::verify_canonical_signature(
        &relay_token_v3_signing_bytes(token)?,
        &token.issuer_signature,
        issuer_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Verifies a gateway issuer certificate against a pinned node-root public key.
///
/// Checks schema/version, required non-empty fields, that the certificate names the expected node
/// and gateway instance, a well-formed and currently-valid validity window
/// (`not_before <= not_after`, `not_before <= now <= not_after` with clock-skew leeway on the lower
/// bound), that the certificate is not revoked (fails closed on `revoked_at`), and the node-root
/// signature. Root keyring/rotation/CRL distribution are out of scope (the root key is a pure
/// input).
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_gateway_issuer_certificate(
    certificate: &GatewayIssuerCertificate,
    node_root_public_key: &str,
    expected_node_id: &str,
    expected_gateway_instance_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if certificate.schema != GATEWAY_ISSUER_CERTIFICATE_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "gateway issuer certificate schema rejected".to_owned(),
        ));
    }
    if certificate.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "gateway issuer certificate version rejected".to_owned(),
        ));
    }
    require_non_empty(&certificate.cert_id, "certificate cert_id")?;
    require_non_empty(&certificate.node_id, "certificate node_id")?;
    require_non_empty(&certificate.gateway_instance_id, "certificate gateway_instance_id")?;
    require_non_empty(&certificate.attestation_public_key, "certificate attestation_public_key")?;
    require_non_empty(&certificate.attestation_key_id, "certificate attestation_key_id")?;
    require_non_empty(
        &certificate.node_root_signing_key_id,
        "certificate node_root_signing_key_id",
    )?;
    require_non_empty(&certificate.node_root_signature, "certificate node_root_signature")?;
    if certificate.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("certificate node id mismatch".to_owned()));
    }
    if certificate.gateway_instance_id != expected_gateway_instance_id {
        return Err(NodeCoreError::Unauthorized(
            "certificate gateway instance mismatch".to_owned(),
        ));
    }
    if certificate.not_before >= certificate.not_after {
        return Err(NodeCoreError::Unauthorized(
            "certificate validity window is empty or inverted".to_owned(),
        ));
    }
    // The certificate must have been issued within its own validity window.
    if certificate.issued_at < certificate.not_before
        || certificate.issued_at > certificate.not_after
    {
        return Err(NodeCoreError::Unauthorized(
            "certificate issued_at is outside its validity window".to_owned(),
        ));
    }
    if now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) < certificate.not_before
        || now >= certificate.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: certificate.cert_id.clone() });
    }
    if certificate.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
        return Err(NodeCoreError::Unauthorized("certificate is revoked".to_owned()));
    }
    ramflux_crypto::verify_canonical_signature(
        &gateway_issuer_certificate_signing_bytes(certificate)?,
        &certificate.node_root_signature,
        node_root_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Verifies a v3 relay token against the gateway issuer certificate carried inline with it and a
/// pinned node-root public key.
///
/// The token embeds its issuer certificate (`token.issuer_certificate`), which is covered by the
/// token's `issuer_signature`. The relay is also given the certificate it expects (`certificate`,
/// from its trusted provider in a later integration step) and requires the frame-carried certificate
/// to be identical — same canonical bytes and same `cert_id`/`attestation_key_id`/node/instance — so a
/// frame cannot substitute a different (even if separately root-valid) certificate. The embedded
/// certificate is then verified against the pinned node root, its `cert_id`/`attestation_key_id`
/// must match the token's declared references, and finally its attestation key verifies the token's
/// issuer signature.
///
/// # Errors
/// Returns an error when the frame/expected certificate mismatch, the certificate chain, the
/// token/certificate binding, or the token itself fails to verify.
pub fn verify_relay_token_v3_with_certificate(
    token: &RelayTokenV3,
    certificate: &GatewayIssuerCertificate,
    node_root_public_key: &str,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    let embedded = &token.issuer_certificate;
    // The frame-carried certificate must be exactly the certificate the relay expects.
    if embedded.cert_id != certificate.cert_id
        || embedded.attestation_key_id != certificate.attestation_key_id
        || embedded.node_id != certificate.node_id
        || embedded.gateway_instance_id != certificate.gateway_instance_id
        || gateway_issuer_certificate_binding_hash(embedded)?
            != gateway_issuer_certificate_binding_hash(certificate)?
    {
        return Err(NodeCoreError::Unauthorized(
            "token issuer certificate does not match the expected certificate".to_owned(),
        ));
    }
    // Verify the embedded certificate against the pinned node root, bound to the token's issuer.
    verify_gateway_issuer_certificate(
        embedded,
        node_root_public_key,
        &token.issuer_node_id,
        &token.gateway_instance_id,
        now,
    )?;
    // The token's declared certificate references must match the embedded certificate.
    if embedded.cert_id != token.issuer_certificate_id {
        return Err(NodeCoreError::Unauthorized(
            "token issuer certificate id does not match embedded certificate".to_owned(),
        ));
    }
    if embedded.attestation_key_id != token.attestation_key_id {
        return Err(NodeCoreError::Unauthorized(
            "token attestation key id does not match embedded certificate".to_owned(),
        ));
    }
    // Finally verify the token issuer signature with the embedded certificate's attestation key.
    verify_relay_token_v3(
        token,
        &embedded.attestation_public_key,
        capability,
        expected_audience_node_id,
        now,
    )
}

/// Verifies a gateway certificate request: schema/version, required non-empty fields, that it names
/// the expected node and gateway instance, a well-formed and not-yet-expired requested validity
/// window, a fresh `requested_at` (neither in the future beyond clock skew nor older than
/// [`GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS`]), and the attestation-key self-signature (proof of
/// possession of the attestation private key). The age bound is a freshness check only; a persistent
/// per-`request_nonce` replay guard, plus node/instance authentication of the requesting gateway
/// (mTLS + allowlist), are integration concerns handled by the signer/caller.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_gateway_certificate_request(
    request: &GatewayCertificateRequest,
    expected_node_id: &str,
    expected_gateway_instance_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if request.schema != GATEWAY_CERTIFICATE_REQUEST_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "gateway certificate request schema rejected".to_owned(),
        ));
    }
    if request.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "gateway certificate request version rejected".to_owned(),
        ));
    }
    require_non_empty(&request.request_id, "certificate request request_id")?;
    require_non_empty(&request.node_id, "certificate request node_id")?;
    require_non_empty(&request.gateway_instance_id, "certificate request gateway_instance_id")?;
    require_non_empty(
        &request.attestation_public_key,
        "certificate request attestation_public_key",
    )?;
    require_non_empty(&request.attestation_key_id, "certificate request attestation_key_id")?;
    require_non_empty(&request.request_nonce, "certificate request request_nonce")?;
    require_non_empty(&request.request_signature, "certificate request request_signature")?;
    if request.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("certificate request node id mismatch".to_owned()));
    }
    if request.gateway_instance_id != expected_gateway_instance_id {
        return Err(NodeCoreError::Unauthorized(
            "certificate request gateway instance mismatch".to_owned(),
        ));
    }
    if request.not_before >= request.not_after {
        return Err(NodeCoreError::Unauthorized(
            "certificate request validity window is empty or inverted".to_owned(),
        ));
    }
    if request.not_after <= now {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    // `requested_at` must be neither in the future (beyond clock skew) nor too old. The age bound
    // limits the window in which a captured, validly-signed request stays acceptable; it is a
    // freshness check, not a persistent per-nonce replay guard (that is a signer-integration
    // concern).
    if request.requested_at > now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
        || request.requested_at.saturating_add(GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS) < now
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    ramflux_crypto::verify_canonical_signature(
        &gateway_certificate_request_signing_bytes(request)?,
        &request.request_signature,
        &request.attestation_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

/// Issues a node-root-signed `GatewayIssuerCertificate` from a verified certificate request.
///
/// Verifies the request (proof of possession + window) against its own declared node/instance, then
/// enforces the issuance policy: the certificate must be immediately active (`not_before <= now`),
/// currently within its window (`now < not_after`), and bounded by the hard maximum TTL
/// (`not_after <= now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS`). The issued certificate takes
/// `issued_at = now` (which is inside the window by construction) and is signed by the node root.
/// The resulting certificate verifies under [`verify_gateway_issuer_certificate`].
///
/// # Errors
/// Returns an error when the request fails verification, the issuance-window policy is violated, or
/// signing fails.
pub fn issue_gateway_issuer_certificate(
    request: &GatewayCertificateRequest,
    node_root_signing_key_id: &str,
    node_root_seed: [u8; 32],
    cert_id: &str,
    now: u64,
) -> Result<GatewayIssuerCertificate, NodeCoreError> {
    verify_gateway_certificate_request(
        request,
        &request.node_id,
        &request.gateway_instance_id,
        now,
    )?;
    require_non_empty(cert_id, "issued certificate cert_id")?;
    require_non_empty(node_root_signing_key_id, "issued certificate node_root_signing_key_id")?;
    // The issued certificate must be active now, so `issued_at = now` falls inside the window.
    if request.not_before > now {
        return Err(NodeCoreError::Unauthorized(
            "certificate request not_before is in the future; certificate would not be active"
                .to_owned(),
        ));
    }
    if now >= request.not_after {
        return Err(NodeCoreError::TtlExpired { envelope_id: request.request_id.clone() });
    }
    if request.not_after > now.saturating_add(GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS) {
        return Err(NodeCoreError::Unauthorized(
            "certificate request validity window exceeds the maximum allowed TTL".to_owned(),
        ));
    }
    let mut certificate = GatewayIssuerCertificate {
        schema: GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: cert_id.to_owned(),
        node_id: request.node_id.clone(),
        gateway_instance_id: request.gateway_instance_id.clone(),
        attestation_public_key: request.attestation_public_key.clone(),
        attestation_key_id: request.attestation_key_id.clone(),
        not_before: request.not_before,
        not_after: request.not_after,
        issued_at: now,
        node_root_signing_key_id: node_root_signing_key_id.to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &gateway_issuer_certificate_signing_bytes(&certificate)?,
        node_root_seed,
    );
    Ok(certificate)
}

/// Returns `true` when `next` is a valid renewal of `previous`: the same gateway (node id and
/// instance) with a fresh certificate id whose validity does not end earlier than the previous one.
/// The attestation key may be rotated or retained. This is the binding contract only; issuing the
/// renewal still goes through [`issue_gateway_issuer_certificate`].
#[must_use]
pub fn gateway_certificate_is_renewal_of(
    previous: &GatewayIssuerCertificate,
    next: &GatewayIssuerCertificate,
) -> bool {
    next.node_id == previous.node_id
        && next.gateway_instance_id == previous.gateway_instance_id
        && next.cert_id != previous.cert_id
        && next.not_after >= previous.not_after
}

/// Returns `true` when a revocation targets exactly the given certificate (bound by cert id,
/// attestation key id, node id, and gateway instance).
#[must_use]
pub fn gateway_certificate_matches_revocation(
    certificate: &GatewayIssuerCertificate,
    revocation: &GatewayCertificateRevocation,
) -> bool {
    certificate.cert_id == revocation.cert_id
        && certificate.attestation_key_id == revocation.attestation_key_id
        && certificate.node_id == revocation.node_id
        && certificate.gateway_instance_id == revocation.gateway_instance_id
}

/// Applies a revocation to the certificate it targets, returning a copy stamped with `revoked_at`.
/// The revoked certificate then fails closed under [`verify_gateway_issuer_certificate`]. Persistent
/// CRL storage/distribution is an integration concern and is not implemented here.
///
/// # Errors
/// Returns an error when the revocation does not bind to the certificate.
pub fn apply_gateway_certificate_revocation(
    certificate: &GatewayIssuerCertificate,
    revocation: &GatewayCertificateRevocation,
) -> Result<GatewayIssuerCertificate, NodeCoreError> {
    if !gateway_certificate_matches_revocation(certificate, revocation) {
        return Err(NodeCoreError::Unauthorized(
            "revocation does not target this certificate".to_owned(),
        ));
    }
    let mut revoked = certificate.clone();
    revoked.revoked_at = Some(revocation.revoked_at);
    Ok(revoked)
}

/// Returns `true` when a pinned root key is usable at `now`: within its validity window and not yet
/// retired. A `retired_at` in the future still permits use until then (rotation grace).
#[must_use]
pub fn trusted_node_root_key_is_valid(root: &TrustedNodeRootKey, now: u64) -> bool {
    root.not_before <= now
        && now < root.not_after
        && root.retired_at.is_none_or(|retired_at| now < retired_at)
}

/// Verifies a federated issuer trust snapshot's structural validity and that it currently permits
/// backing new relay tokens.
///
/// Checks schema/version, that it is for the expected issuer node, a non-zero generation, that it is
/// not past its hard staleness deadline, and the trust status. Only `Active` permits new tokens.
/// `Invited`/`Suspended`/`Revoked` fail closed. `Migrated` also fails closed here; the grace period
/// for already-issued tokens from a migrated node is a runtime/integration concern not modeled by
/// this pure snapshot.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_federated_issuer_trust_snapshot(
    snapshot: &FederatedIssuerTrustSnapshot,
    expected_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    // Admission (structural + freshness) is a strict prerequisite of authorization, but not
    // sufficient: a structurally-valid non-Active snapshot is admissible to the cache yet must not
    // authorize requests.
    verify_federated_issuer_trust_snapshot_admission(snapshot, expected_node_id, now)?;
    match snapshot.trust_status {
        FederatedIssuerTrustStatus::Active => Ok(()),
        FederatedIssuerTrustStatus::Migrated => Err(NodeCoreError::Unauthorized(
            "trust snapshot node is migrated; new tokens fail closed (old-token grace is deferred to integration)"
                .to_owned(),
        )),
        FederatedIssuerTrustStatus::Invited
        | FederatedIssuerTrustStatus::Suspended
        | FederatedIssuerTrustStatus::Revoked => Err(NodeCoreError::Unauthorized(
            "trust snapshot node is not active".to_owned(),
        )),
    }
}

/// Admission check for a federated issuer trust snapshot: structural validity (schema/version/node
/// identity/non-zero generation) and freshness (`now < hard_stale_at`). This is the check a snapshot
/// must pass to *enter the relay's trust cache*, and it is deliberately independent of
/// `trust_status`: a validly-signed `Suspended`/`Revoked`/`Invited`/`Migrated` snapshot is admissible
/// so that a node-status transition propagates to the relay and replaces a stale `Active` snapshot.
///
/// Admission is NOT authorization. Every v3 request re-checks the cached snapshot with the Active-only
/// [`verify_federated_issuer_trust_snapshot`], so an admitted non-Active snapshot fails requests
/// closed. A hard-stale snapshot is rejected here too and can neither be installed nor authorize.
///
/// # Errors
/// Returns an error when the snapshot is structurally invalid, for the wrong node, has a zero
/// generation, or is past its hard staleness deadline.
pub fn verify_federated_issuer_trust_snapshot_admission(
    snapshot: &FederatedIssuerTrustSnapshot,
    expected_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if snapshot.schema != FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "federated issuer trust snapshot schema rejected".to_owned(),
        ));
    }
    if snapshot.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "federated issuer trust snapshot version rejected".to_owned(),
        ));
    }
    require_non_empty(&snapshot.node_id, "trust snapshot node_id")?;
    if snapshot.node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized("trust snapshot node id mismatch".to_owned()));
    }
    if snapshot.generation == 0 {
        return Err(NodeCoreError::Unauthorized("trust snapshot generation is zero".to_owned()));
    }
    if now >= snapshot.hard_stale_at {
        return Err(NodeCoreError::TtlExpired { envelope_id: snapshot.node_id.clone() });
    }
    Ok(())
}

/// Selects the pinned root key for `key_id` from a snapshot, requiring it to belong to the
/// snapshot's node and to be currently valid (window + not retired). This is where current/previous
/// rotation overlap is resolved: whichever root matches the certificate's signing key id and is
/// still valid is returned.
///
/// # Errors
/// Returns an error when no matching, currently-valid root exists.
pub fn select_trusted_node_root_key<'a>(
    snapshot: &'a FederatedIssuerTrustSnapshot,
    key_id: &str,
    now: u64,
) -> Result<&'a TrustedNodeRootKey, NodeCoreError> {
    snapshot
        .roots
        .iter()
        .find(|root| {
            root.key_id == key_id
                && root.node_id == snapshot.node_id
                && trusted_node_root_key_is_valid(root, now)
        })
        .ok_or_else(|| {
            NodeCoreError::Unauthorized(
                "no valid trusted node root key for the certificate signer".to_owned(),
            )
        })
}

/// Verifies a v3 relay token using a federated trust snapshot as the only source of node-root trust.
///
/// The snapshot is verified first (it must be `Active`, fresh, and for the token's issuer node), the
/// embedded certificate must not be listed as revoked, the pinned root is selected by the embedded
/// certificate's `node_root_signing_key_id` (resolving rotation overlap), and finally the token is
/// verified against that root via [`verify_relay_token_v3_with_certificate`] (which also enforces the
/// frame/expected certificate match and the token issuer signature). There is no bare-key or HMAC
/// fallback.
///
/// # Errors
/// Returns an error when the snapshot, revocation, root selection, or certificate/token chain fails.
pub fn verify_relay_token_v3_with_trust_snapshot(
    token: &RelayTokenV3,
    certificate: &GatewayIssuerCertificate,
    snapshot: &FederatedIssuerTrustSnapshot,
    capability: ObjectRelayCapability,
    expected_audience_node_id: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    verify_federated_issuer_trust_snapshot(snapshot, &token.issuer_node_id, now)?;
    if snapshot.revoked_cert_ids.contains(&token.issuer_certificate.cert_id)
        || snapshot.revoked_cert_ids.contains(&certificate.cert_id)
    {
        return Err(NodeCoreError::Unauthorized(
            "issuer certificate is revoked by the trust snapshot".to_owned(),
        ));
    }
    let root = select_trusted_node_root_key(
        snapshot,
        &token.issuer_certificate.node_root_signing_key_id,
        now,
    )?;
    verify_relay_token_v3_with_certificate(
        token,
        certificate,
        &root.public_key,
        capability,
        expected_audience_node_id,
        now,
    )
}

/// Enforces that a successor snapshot does not roll back trust: it must be for the same node and its
/// `generation` and `pin_epoch` must be monotonically non-decreasing. A decrease is a rollback and is
/// rejected.
///
/// # Errors
/// Returns an error when the successor is for a different node or rolls back the generation or
/// `pin_epoch`.
pub fn verify_federated_issuer_trust_snapshot_successor(
    previous: &FederatedIssuerTrustSnapshot,
    next: &FederatedIssuerTrustSnapshot,
) -> Result<(), NodeCoreError> {
    if next.node_id != previous.node_id {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor is for a different node".to_owned(),
        ));
    }
    if next.generation < previous.generation || next.pin_epoch < previous.pin_epoch {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor rolls back generation or pin epoch".to_owned(),
        ));
    }
    if next.generation == previous.generation
        && next.pin_epoch == previous.pin_epoch
        && next != previous
    {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor changed at the same generation and pin epoch".to_owned(),
        ));
    }
    // The certificate revocation list is monotonic: a successor may add revocations but must not drop
    // any. Without a signed revocation-withdrawal protocol, silently shrinking the CRL (even at a
    // higher generation) would resurrect a revoked issuer certificate; recovery of a revoked
    // certificate requires a new certificate / rotation (deferred to a later card).
    if !next.revoked_cert_ids.is_superset(&previous.revoked_cert_ids) {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot successor shrinks the certificate revocation list".to_owned(),
        ));
    }
    Ok(())
}

/// A provider-signed envelope carrying a `FederatedIssuerTrustSnapshot`. The signing key is the
/// trusted provider / node-root key that distributes trust snapshots to relays; the relay pins that
/// public key out of band. The envelope binds the snapshot plus an issuance/expiry window, so an
/// unsigned or tampered snapshot cannot enter the relay's trust cache.
///
/// T23-A2b2b: this is the LEGACY single-pinned-key envelope. It is gated to the
/// `itest-provider-single-key` compatibility path; the production/default relay uses only the
/// offline-root-signed keyring envelope [`ProviderSignedTrustSnapshot`].
#[cfg(any(test, feature = "itest-provider-single-key"))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedFederatedIssuerTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub provider_signing_key_id: String,
    pub provider_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub fn signed_federated_issuer_trust_snapshot_signing_bytes(
    envelope: &SignedFederatedIssuerTrustSnapshot,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = envelope.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a signed trust-snapshot envelope against a pinned provider/node-root public key.
///
/// Checks schema/version, required non-empty fields, that the envelope names the expected pinned
/// provider key, a fresh issuance/expiry window, and the provider signature over the canonical
/// envelope (which covers the inner snapshot, so tampering breaks the signature). This authenticates
/// the snapshot's source; the inner snapshot's structural validity and successor rules are enforced
/// separately when it is installed via [`RelayTrustSnapshotCache::update_from_signed`].
///
/// # Errors
/// Returns an error when any of the above checks fail.
#[cfg(any(test, feature = "itest-provider-single-key"))]
pub fn verify_signed_federated_issuer_trust_snapshot(
    envelope: &SignedFederatedIssuerTrustSnapshot,
    expected_provider_public_key: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if envelope.schema != FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA {
        return Err(NodeCoreError::ItestJson("trust snapshot envelope schema rejected".to_owned()));
    }
    if envelope.version != OBJECT_RELAY_V3_PROOF_VERSION {
        return Err(NodeCoreError::ItestJson(
            "trust snapshot envelope version rejected".to_owned(),
        ));
    }
    require_non_empty(&envelope.provider_signing_key_id, "envelope provider_signing_key_id")?;
    require_non_empty(&envelope.provider_public_key, "envelope provider_public_key")?;
    require_non_empty(&envelope.signature, "envelope signature")?;
    if envelope.provider_public_key != expected_provider_public_key {
        return Err(NodeCoreError::Unauthorized(
            "trust snapshot envelope provider key is not the pinned provider".to_owned(),
        ));
    }
    within_ttl(envelope.issued_at, envelope.expires_at, now, &envelope.provider_signing_key_id)?;
    ramflux_crypto::verify_canonical_signature(
        &signed_federated_issuer_trust_snapshot_signing_bytes(envelope)?,
        &envelope.signature,
        &envelope.provider_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))
}

// ─── T23-A2b2: provider signing-key keyring rotation (production keyring era) ──────────────────────

/// One provider signing key in the out-of-band keyring. `authorized_provider_epoch` is the EXACT
/// provider epoch this key may sign — a key can never advance the provider epoch beyond its own, so a
/// compromised overlapping key cannot forge a higher-epoch (seizing) envelope. `retired_at` is the
/// absolute unix second (offline-root-attested, not a locally-observed time) from which the key may no
/// longer sign or authorize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderKeyEntry {
    pub key_id: String,
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    pub retired_at: Option<u64>,
    pub authorized_provider_epoch: u64,
}

/// The out-of-band provider keyring, authorized by a single independent offline signing root whose
/// public key the relay pins separately (never by the provider/snapshot/node-root key). `keyring_epoch`
/// is monotonic and anchors file-level anti-rollback. This is the wire/at-rest form; only a
/// [`ValidatedProviderKeyring`] (produced by [`verify_provider_keyring`]) may select a signing key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderKeyring {
    pub schema: String,
    pub version: u32,
    pub issuer_node_id: String,
    pub keyring_epoch: u64,
    pub keys: Vec<ProviderKeyEntry>,
    pub keyring_signature: String,
}

/// A [`ProviderKeyring`] that has passed offline-root signature + structural validation. It cannot be
/// deserialized directly — only [`verify_provider_keyring`] constructs it — so an unvalidated keyring
/// can never select a provider key. `fingerprint` is a canonical content hash used to reject a
/// same-`keyring_epoch` content replacement (only a higher epoch may change content).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProviderKeyring {
    inner: ProviderKeyring,
    fingerprint: String,
}

impl ValidatedProviderKeyring {
    #[must_use]
    pub fn keyring_epoch(&self) -> u64 {
        self.inner.keyring_epoch
    }

    #[must_use]
    pub fn issuer_node_id(&self) -> &str {
        &self.inner.issuer_node_id
    }

    /// The canonical content fingerprint (blake3 over the signing bytes) — same content re-signed
    /// yields the same fingerprint; any content change yields a different one.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Selects the unique keyring entry for `key_id` (uniqueness is enforced at validation).
    #[must_use]
    pub fn select(&self, key_id: &str) -> Option<&ProviderKeyEntry> {
        self.inner.keys.iter().find(|entry| entry.key_id == key_id)
    }
}

/// # Errors
/// Returns an error when the keyring cannot be canonicalized.
pub fn provider_keyring_signing_bytes(keyring: &ProviderKeyring) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = keyring.clone();
    canonical.keyring_signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Validates a provider keyring against the pinned offline-root public key and structural rules, then
/// returns a [`ValidatedProviderKeyring`]. Checks schema/version, node identity, non-empty fields, per
/// entry validity window (`not_before < not_after`), `key_id` uniqueness, `authorized_provider_epoch`
/// uniqueness (no two keys share an exact epoch — exact-epoch authorization would otherwise be
/// ambiguous), and the offline-root signature over the canonical keyring. The offline root is an
/// anchor independent of every provider key.
///
/// # Errors
/// Returns an error when any structural rule or the offline-root signature fails.
pub fn verify_provider_keyring(
    keyring: &ProviderKeyring,
    offline_root_public_key: &str,
    expected_node_id: &str,
) -> Result<ValidatedProviderKeyring, NodeCoreError> {
    if keyring.schema != PROVIDER_KEYRING_SCHEMA {
        return Err(NodeCoreError::ItestJson("provider keyring schema rejected".to_owned()));
    }
    if keyring.version != PROVIDER_KEYRING_VERSION {
        return Err(NodeCoreError::ItestJson("provider keyring version rejected".to_owned()));
    }
    require_non_empty(&keyring.issuer_node_id, "keyring issuer_node_id")?;
    if keyring.issuer_node_id != expected_node_id {
        return Err(NodeCoreError::Unauthorized(
            "provider keyring issuer node mismatch".to_owned(),
        ));
    }
    require_non_empty(&keyring.keyring_signature, "keyring signature")?;
    if keyring.keys.is_empty() {
        return Err(NodeCoreError::Unauthorized("provider keyring has no keys".to_owned()));
    }
    let mut seen_key_ids = std::collections::BTreeSet::new();
    let mut seen_epochs = std::collections::BTreeSet::new();
    for entry in &keyring.keys {
        require_non_empty(&entry.key_id, "keyring entry key_id")?;
        require_non_empty(&entry.public_key, "keyring entry public_key")?;
        if entry.not_before >= entry.not_after {
            return Err(NodeCoreError::Unauthorized(
                "keyring entry validity window is empty".to_owned(),
            ));
        }
        if !seen_key_ids.insert(entry.key_id.clone()) {
            return Err(NodeCoreError::Unauthorized("keyring has a duplicate key_id".to_owned()));
        }
        if !seen_epochs.insert(entry.authorized_provider_epoch) {
            return Err(NodeCoreError::Unauthorized(
                "keyring has a duplicate authorized_provider_epoch".to_owned(),
            ));
        }
    }
    let signing_bytes = provider_keyring_signing_bytes(keyring)?;
    ramflux_crypto::verify_canonical_signature(
        &signing_bytes,
        &keyring.keyring_signature,
        offline_root_public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    let fingerprint =
        ramflux_crypto::blake3_256_base64url(PROVIDER_KEYRING_FINGERPRINT_DOMAIN, &signing_bytes);
    Ok(ValidatedProviderKeyring { inner: keyring.clone(), fingerprint })
}

/// The versioned provider-signed trust-snapshot envelope (keyring era). Adds `provider_epoch` (bound
/// by the signature via the canonical bytes) so the relay can enforce that only the key authorized for
/// that exact epoch may sign it. `provider_public_key` is retained only as a redundant field that MUST
/// equal the selected keyring entry's public key — it is never a self-declared trust input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderSignedTrustSnapshot {
    pub schema: String,
    pub version: u32,
    pub snapshot: FederatedIssuerTrustSnapshot,
    pub provider_signing_key_id: String,
    pub provider_public_key: String,
    pub provider_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// # Errors
/// Returns an error when the envelope cannot be canonicalized.
pub fn provider_signed_trust_snapshot_signing_bytes(
    envelope: &ProviderSignedTrustSnapshot,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut canonical = envelope.clone();
    canonical.signature.clear();
    ramflux_protocol::canonical_json_bytes(&canonical)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))
}

/// Verifies a versioned provider-signed trust-snapshot envelope against a validated keyring and
/// returns the selected keyring entry. Hard-rejects the legacy `..._envelope.v3` schema (only the
/// keyring-era `..._envelope.v4` is accepted in production). Selects the unique entry by
/// `provider_signing_key_id`; rejects a retired key, a key outside its validity window (with clock
/// skew), an envelope whose `provider_epoch` is not the entry's exact `authorized_provider_epoch`, or
/// an envelope whose `provider_public_key` differs from the entry's key; then verifies the provider
/// signature over the canonical envelope with the entry's key.
///
/// # Errors
/// Returns an error when any of the above checks fail.
pub fn verify_provider_signed_trust_snapshot<'a>(
    envelope: &ProviderSignedTrustSnapshot,
    keyring: &'a ValidatedProviderKeyring,
    now: u64,
) -> Result<&'a ProviderKeyEntry, NodeCoreError> {
    if envelope.schema != PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA {
        return Err(NodeCoreError::ItestJson(
            "provider trust snapshot envelope schema rejected".to_owned(),
        ));
    }
    if envelope.version != PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION {
        return Err(NodeCoreError::ItestJson(
            "provider trust snapshot envelope version rejected".to_owned(),
        ));
    }
    require_non_empty(&envelope.provider_signing_key_id, "envelope provider_signing_key_id")?;
    require_non_empty(&envelope.provider_public_key, "envelope provider_public_key")?;
    require_non_empty(&envelope.signature, "envelope signature")?;
    let entry = keyring.select(&envelope.provider_signing_key_id).ok_or_else(|| {
        NodeCoreError::Unauthorized(
            "envelope provider_signing_key_id is not in the pinned keyring".to_owned(),
        )
    })?;
    if let Some(retired_at) = entry.retired_at
        && now >= retired_at
    {
        return Err(NodeCoreError::Unauthorized("envelope provider key is retired".to_owned()));
    }
    if now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS) < entry.not_before
        || now >= entry.not_after
    {
        return Err(NodeCoreError::TtlExpired { envelope_id: entry.key_id.clone() });
    }
    if envelope.provider_epoch != entry.authorized_provider_epoch {
        return Err(NodeCoreError::Unauthorized(
            "envelope provider_epoch is not authorized for this provider key".to_owned(),
        ));
    }
    if envelope.provider_public_key != entry.public_key {
        return Err(NodeCoreError::Unauthorized(
            "envelope provider public key does not match the keyring entry".to_owned(),
        ));
    }
    within_ttl(envelope.issued_at, envelope.expires_at, now, &entry.key_id)?;
    ramflux_crypto::verify_canonical_signature(
        &provider_signed_trust_snapshot_signing_bytes(envelope)?,
        &envelope.signature,
        &entry.public_key,
    )
    .map_err(|source| NodeCoreError::Unauthorized(source.to_string()))?;
    Ok(entry)
}

/// A pure, cloneable in-memory holder for the relay's current federated issuer trust snapshot.
///
/// It has no interior mutability (no lock): callers own the cache and clone it for sharing, so
/// concurrency is the caller's responsibility. Admission (entering the cache) is deliberately
/// separated from authorization (Active-only, enforced at read time), so a node-status transition
/// (e.g. Active -> Suspended) propagates instead of leaving a stale Active in force:
/// - [`RelayTrustSnapshotCache::update`] admits a snapshot that is structurally valid and fresh
///   ([`verify_federated_issuer_trust_snapshot_admission`], which does NOT check `trust_status`) and
///   that does not roll back the cached generation/pin epoch, switch node, or shrink the certificate
///   revocation list ([`verify_federated_issuer_trust_snapshot_successor`]). A validly-signed
///   non-`Active` snapshot is therefore admissible.
/// - [`RelayTrustSnapshotCache::current`] performs authorization at read time with the Active-only
///   [`verify_federated_issuer_trust_snapshot`] and errors when the cache is empty or the cached
///   snapshot is not currently usable (past its hard staleness deadline, non-`Active`, ...). So an
///   admitted non-`Active` snapshot fails requests closed rather than being silently ignored.
///
/// This is a runtime skeleton only. It does NOT authenticate a snapshot's origin (that is the future
/// federation provider's job) and it never authorizes a relay token by itself — token verification is
/// done separately by [`verify_relay_token_v3_with_trust_snapshot`], which re-validates the snapshot.
/// There is no v2/HMAC path here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayTrustSnapshotCache {
    current: Option<FederatedIssuerTrustSnapshot>,
    /// T23-A2b2: the keyring `key_id` that signed the currently-cached snapshot. Used to fail the
    /// cache closed when a later keyring retires/removes that signer.
    accepted_signer_key_id: Option<String>,
    /// T23-A2b2: monotonic high-water of the accepted `provider_epoch`. A compromised overlapping key
    /// authorized for an older epoch can never re-take or advance past this.
    provider_epoch_high_water: u64,
    /// T23-A2b2: monotonic high-water of the adopted `keyring_epoch` (file-level anti-rollback). This
    /// defends only against replacing the keyring *file* with an older one; whole-persist-volume
    /// rollback is out of scope for v1 (its trust boundary is the persisted volume's integrity).
    keyring_epoch_high_water: u64,
    /// T23-A2b2: canonical fingerprint of the adopted keyring at `keyring_epoch_high_water`. A keyring
    /// presenting the same epoch but a different fingerprint is a content replacement and is rejected;
    /// only a strictly higher epoch may change content.
    keyring_fingerprint_high_water: Option<String>,
}

impl RelayTrustSnapshotCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached snapshot's generation, or `None` when the cache is empty. Does not imply
    /// the snapshot is still usable — use [`RelayTrustSnapshotCache::current`] for a fail-closed read.
    #[must_use]
    pub fn generation(&self) -> Option<u64> {
        self.current.as_ref().map(|snapshot| snapshot.generation)
    }

    /// Admits `snapshot` as the current trust snapshot for `expected_node_id` at `now`.
    ///
    /// This is admission, not authorization: it rejects a snapshot that is not structurally valid or
    /// is hard-stale ([`verify_federated_issuer_trust_snapshot_admission`], which does NOT check
    /// `trust_status`) and — when a snapshot is already cached — one for a different node, one that
    /// rolls back the generation or pin epoch, or one that shrinks the certificate revocation list.
    /// A validly-signed non-`Active` snapshot is admitted so a node-status transition replaces the
    /// cached snapshot; requests are then gated Active-only by [`RelayTrustSnapshotCache::current`],
    /// so an admitted non-`Active` snapshot fails requests closed.
    ///
    /// # Errors
    /// Returns an error when the incoming snapshot fails admission or is not a valid successor of the
    /// cached snapshot.
    pub fn update(
        &mut self,
        snapshot: FederatedIssuerTrustSnapshot,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        // Admission, not authorization: a structurally-valid, fresh, monotonic non-Active snapshot is
        // admitted so a node-status transition (e.g. Active -> Suspended) replaces the cached
        // snapshot. Requests are gated separately by the Active-only `current`, so an admitted
        // non-Active snapshot fails requests closed rather than leaving the stale Active in force.
        verify_federated_issuer_trust_snapshot_admission(&snapshot, expected_node_id, now)?;
        if let Some(existing) = &self.current {
            verify_federated_issuer_trust_snapshot_successor(existing, &snapshot)?;
        }
        self.current = Some(snapshot);
        Ok(())
    }

    /// Returns the current usable trust snapshot for `expected_node_id` at `now`.
    ///
    /// Fail-closed: errors when the cache is empty or the cached snapshot is no longer usable (wrong
    /// node, non-`Active`, past its hard staleness deadline, ...). Never returns an unusable snapshot.
    ///
    /// # Errors
    /// Returns an error when the cache is empty or the cached snapshot fails verification.
    pub fn current(
        &self,
        expected_node_id: &str,
        now: u64,
    ) -> Result<&FederatedIssuerTrustSnapshot, NodeCoreError> {
        let snapshot = self.current.as_ref().ok_or_else(|| {
            NodeCoreError::Unauthorized("relay trust snapshot cache is empty".to_owned())
        })?;
        verify_federated_issuer_trust_snapshot(snapshot, expected_node_id, now)?;
        Ok(snapshot)
    }

    /// Authenticated ingress: verifies the provider signature on `envelope` against the pinned
    /// provider public key first, and only then installs the inner snapshot via
    /// [`RelayTrustSnapshotCache::update`]. This is the required path for admitting a snapshot from an
    /// external provider — an unsigned or tampered envelope never reaches the cache.
    ///
    /// # Errors
    /// Returns an error when the envelope signature/window fails verification, or when the inner
    /// snapshot fails the structural/successor checks in [`RelayTrustSnapshotCache::update`].
    #[cfg(any(test, feature = "itest-provider-single-key"))]
    pub fn update_from_signed(
        &mut self,
        envelope: &SignedFederatedIssuerTrustSnapshot,
        expected_provider_public_key: &str,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        verify_signed_federated_issuer_trust_snapshot(envelope, expected_provider_public_key, now)?;
        self.update(envelope.snapshot.clone(), expected_node_id, now)
    }

    /// T23-A2b2 accessors for persistence / anti-rollback bookkeeping.
    #[must_use]
    pub fn provider_epoch_high_water(&self) -> u64 {
        self.provider_epoch_high_water
    }

    #[must_use]
    pub fn keyring_epoch_high_water(&self) -> u64 {
        self.keyring_epoch_high_water
    }

    #[must_use]
    pub fn accepted_signer_key_id(&self) -> Option<&str> {
        self.accepted_signer_key_id.as_deref()
    }

    #[must_use]
    pub fn keyring_fingerprint_high_water(&self) -> Option<&str> {
        self.keyring_fingerprint_high_water.as_deref()
    }

    /// Restores the persisted anti-rollback high-waters (and accepted signer/fingerprint) after a relay
    /// restart, so a cold start cannot be tricked into accepting an already-superseded keyring/epoch or
    /// a same-epoch content replacement. The caller is responsible for having independently
    /// re-validated the persisted snapshot/keyring.
    pub fn restore_high_water(
        &mut self,
        accepted_signer_key_id: Option<String>,
        provider_epoch_high_water: u64,
        keyring_epoch_high_water: u64,
        keyring_fingerprint_high_water: Option<String>,
    ) {
        self.accepted_signer_key_id = accepted_signer_key_id;
        self.provider_epoch_high_water = provider_epoch_high_water;
        self.keyring_epoch_high_water = keyring_epoch_high_water;
        self.keyring_fingerprint_high_water = keyring_fingerprint_high_water;
    }

    /// Enforces keyring-level anti-rollback: the `keyring_epoch` must never regress, and at the same
    /// epoch the canonical content (fingerprint) must be identical — only a strictly higher epoch may
    /// change content. A pure check that makes no mutation, so callers can reject a rolled-back or
    /// same-epoch-replaced keyring while leaving the cache completely inert.
    ///
    /// # Errors
    /// Returns an error when the keyring epoch rolls back or its content changed at the same epoch.
    fn check_keyring_adoptable(
        &self,
        keyring: &ValidatedProviderKeyring,
    ) -> Result<(), NodeCoreError> {
        if keyring.keyring_epoch() < self.keyring_epoch_high_water {
            return Err(NodeCoreError::Unauthorized(
                "provider keyring epoch rolls back below the accepted high-water".to_owned(),
            ));
        }
        if keyring.keyring_epoch() == self.keyring_epoch_high_water
            && let Some(fingerprint) = &self.keyring_fingerprint_high_water
            && fingerprint != keyring.fingerprint()
        {
            return Err(NodeCoreError::Unauthorized(
                "provider keyring content changed without advancing keyring_epoch".to_owned(),
            ));
        }
        Ok(())
    }

    /// T23-A2b2 keyring-era authenticated ingress. Verifies the versioned provider-signed envelope
    /// against the validated keyring, enforces keyring/provider-epoch anti-rollback, then installs the
    /// inner snapshot via the same admission + successor rules as the legacy path — all in one
    /// transaction. On any failure the cache is left completely unchanged (inert), so a rejected update
    /// never partially advances a high-water or displaces the cached snapshot.
    ///
    /// Anti-seizure: [`verify_provider_signed_trust_snapshot`] pins `provider_epoch` to the signing
    /// key's exact `authorized_provider_epoch`, so a compromised overlapping key can neither forge a
    /// higher (seizing) epoch nor re-sign an epoch already advanced past by another key.
    ///
    /// # Errors
    /// Returns an error when the keyring epoch rolls back, the envelope fails verification, the
    /// provider epoch rolls back or is re-signed by a different key, or the inner snapshot fails
    /// admission/successor.
    pub fn update_from_keyring_signed(
        &mut self,
        envelope: &ProviderSignedTrustSnapshot,
        keyring: &ValidatedProviderKeyring,
        expected_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.check_keyring_adoptable(keyring)?;
        let entry = verify_provider_signed_trust_snapshot(envelope, keyring, now)?;
        if envelope.provider_epoch < self.provider_epoch_high_water {
            return Err(NodeCoreError::Unauthorized(
                "envelope provider_epoch rolls back below the accepted high-water".to_owned(),
            ));
        }
        if envelope.provider_epoch == self.provider_epoch_high_water
            && let Some(signer) = &self.accepted_signer_key_id
            && signer != &entry.key_id
        {
            return Err(NodeCoreError::Unauthorized(
                "a different provider key may not re-sign the current provider_epoch".to_owned(),
            ));
        }
        verify_federated_issuer_trust_snapshot_admission(
            &envelope.snapshot,
            expected_node_id,
            now,
        )?;
        if let Some(existing) = &self.current {
            verify_federated_issuer_trust_snapshot_successor(existing, &envelope.snapshot)?;
        }
        let signer_key_id = entry.key_id.clone();
        self.current = Some(envelope.snapshot.clone());
        self.accepted_signer_key_id = Some(signer_key_id);
        self.provider_epoch_high_water = envelope.provider_epoch;
        self.keyring_epoch_high_water = keyring.keyring_epoch();
        self.keyring_fingerprint_high_water = Some(keyring.fingerprint().to_owned());
        Ok(())
    }

    /// T23-A2b2: reconcile the cached snapshot against a freshly-validated keyring WITHOUT a new
    /// envelope. Enforces keyring-level anti-rollback (epoch + same-epoch fingerprint), advances the
    /// keyring high-water/fingerprint, and — critically — drops the cached snapshot if the signer that
    /// authorized it is no longer usable in this keyring (removed, retired, or outside its window), so
    /// a retirement fails the cache closed immediately rather than continuing on a retired signer.
    ///
    /// On a non-adoptable keyring (epoch rollback or same-epoch content change) it returns an error and
    /// leaves the cache completely unchanged, so a rolled-back or forged same-epoch keyring never
    /// triggers signer reconciliation or clears an existing valid cache.
    ///
    /// # Errors
    /// Returns an error when the keyring is not adoptable (epoch rollback or same-epoch content change).
    pub fn reconcile_keyring(
        &mut self,
        keyring: &ValidatedProviderKeyring,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.check_keyring_adoptable(keyring)?;
        self.keyring_epoch_high_water = keyring.keyring_epoch();
        self.keyring_fingerprint_high_water = Some(keyring.fingerprint().to_owned());
        if let Some(signer) = self.accepted_signer_key_id.clone() {
            let still_valid = keyring.select(&signer).is_some_and(|entry| {
                entry.retired_at.is_none_or(|retired_at| now < retired_at)
                    && now.saturating_add(OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS)
                        >= entry.not_before
                    && now < entry.not_after
            });
            if !still_valid {
                self.current = None;
            }
        }
        Ok(())
    }
}

fn verify_grant_invocation(
    token: &RelayTokenV3,
    grant: Option<&ObjectAccessGrant>,
    owner_proof: Option<&OwnerAuthorizationProof>,
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if owner_proof.is_some() {
        return Err(NodeCoreError::Unauthorized(
            "get/ack must not carry an owner authorization proof".to_owned(),
        ));
    }
    let grant = grant.ok_or_else(|| {
        NodeCoreError::Unauthorized("get/ack requires an object access grant".to_owned())
    })?;
    verify_object_access_grant(grant, capability, now)?;
    if grant.owner_signing_key_id != token.owner_signing_key_id
        || grant.owner_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "grant owner does not match token owner".to_owned(),
        ));
    }
    if grant.grantee_device_hash != token.requester_device_hash {
        return Err(NodeCoreError::Unauthorized(
            "grant grantee does not match token requester".to_owned(),
        ));
    }
    if grant.object_id != token.object_id || grant.manifest_hash != token.manifest_hash {
        return Err(NodeCoreError::Unauthorized("grant object binding mismatch".to_owned()));
    }
    if token.authorization_binding_hash != object_access_grant_binding_hash(grant)? {
        return Err(NodeCoreError::Unauthorized(
            "token authorization binding hash does not match grant".to_owned(),
        ));
    }
    Ok(())
}

fn verify_owner_session_invocation(
    token: &RelayTokenV3,
    grant: Option<&ObjectAccessGrant>,
    owner_proof: Option<&OwnerAuthorizationProof>,
    capability: ObjectRelayCapability,
    expected_body_hash: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    if grant.is_some() {
        return Err(NodeCoreError::Unauthorized(
            "put/tombstone must not carry an object access grant".to_owned(),
        ));
    }
    let proof = owner_proof.ok_or_else(|| {
        NodeCoreError::Unauthorized(
            "put/tombstone requires an owner authorization proof".to_owned(),
        )
    })?;
    verify_owner_authorization_proof(proof, capability, now)?;
    if proof.owner_signing_key_id != token.owner_signing_key_id
        || proof.owner_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "proof owner does not match token owner".to_owned(),
        ));
    }
    // For owner-session operations the requester is the owner itself.
    if token.requester_device_id != token.owner_signing_key_id
        || token.requester_public_key != token.owner_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "put/tombstone requester must be the owner device".to_owned(),
        ));
    }
    if proof.object_id != token.object_id
        || proof.owner_home_node_id != token.owner_home_node_id
        || proof.owner_principal_id != token.owner_principal_id
        || proof.owner_device_epoch != token.owner_device_epoch
    {
        return Err(NodeCoreError::Unauthorized("proof owner/object binding mismatch".to_owned()));
    }
    // The proof's manifest must match the token.
    if proof.manifest_hash.as_deref() != Some(token.manifest_hash.as_str()) {
        return Err(NodeCoreError::Unauthorized("proof manifest binding mismatch".to_owned()));
    }
    // Put must bind the exact chunk; Tombstone may be whole-object (None) but a present chunk id
    // must match the token.
    match capability {
        ObjectRelayCapability::Put => {
            if proof.chunk_id.as_deref() != Some(token.chunk_id.as_str()) {
                return Err(NodeCoreError::Unauthorized(
                    "put owner proof must bind the token chunk".to_owned(),
                ));
            }
        }
        ObjectRelayCapability::Tombstone => {
            if let Some(chunk_id) = proof.chunk_id.as_deref()
                && chunk_id != token.chunk_id
            {
                return Err(NodeCoreError::Unauthorized(
                    "tombstone owner proof chunk mismatch".to_owned(),
                ));
            }
        }
        ObjectRelayCapability::Get | ObjectRelayCapability::Ack => {
            return Err(NodeCoreError::Unauthorized(
                "owner authorization proof cannot back get/ack".to_owned(),
            ));
        }
    }
    // The proof binds the request body, mirroring the per-invocation PoP.
    if proof.body_hash != expected_body_hash {
        return Err(NodeCoreError::Unauthorized("proof body hash mismatch".to_owned()));
    }
    if token.authorization_binding_hash != owner_authorization_proof_binding_hash(proof)? {
        return Err(NodeCoreError::Unauthorized(
            "token authorization binding hash does not match owner proof".to_owned(),
        ));
    }
    Ok(())
}

fn verify_pop_binding(
    token: &RelayTokenV3,
    pop: &RequesterProofOfPossession,
    capability: ObjectRelayCapability,
    expected_body_hash: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    // The PoP signature is verified against the gateway-attested requester key on the token, not the
    // PoP's self-declared key; the self-declared key must match to avoid confusion.
    verify_requester_pop(pop, &token.requester_public_key, now)?;
    if pop.signer_device_id != token.requester_device_id
        || pop.signer_public_key != token.requester_public_key
    {
        return Err(NodeCoreError::Unauthorized(
            "pop signer is not the token requester".to_owned(),
        ));
    }
    if pop.token_id != token.token_id {
        return Err(NodeCoreError::Unauthorized("pop is not bound to this token".to_owned()));
    }
    if pop.capability != capability {
        return Err(NodeCoreError::Unauthorized("pop capability mismatch".to_owned()));
    }
    if pop.object_id != token.object_id
        || pop.manifest_hash != token.manifest_hash
        || pop.chunk_id != token.chunk_id
    {
        return Err(NodeCoreError::Unauthorized("pop object binding mismatch".to_owned()));
    }
    if pop.body_hash != expected_body_hash {
        return Err(NodeCoreError::Unauthorized("pop body hash mismatch".to_owned()));
    }
    Ok(())
}

/// Capability/proof matrix verifier for a single v3 invocation. Fails closed on any missing, extra,
/// or wrong-kind proof.
///
/// - Get/Ack require `OwnerGrant` + an `ObjectAccessGrant` (no owner proof) + `RequesterPoP`.
/// - Put/Tombstone require `OwnerSession` + an `OwnerAuthorizationProof` (no grant) + `RequesterPoP`.
/// - Grants may never carry Put/Tombstone; tokens must be v3 (no HMAC/shared-key fallback).
///
/// # Errors
/// Returns an error when the token, the capability/proof matrix, the authorization binding, or the
/// requester proof-of-possession fails to verify.
pub fn verify_relay_invocation_v3(ctx: &RelayInvocationV3<'_>) -> Result<(), NodeCoreError> {
    verify_relay_token_v3(
        ctx.token,
        ctx.issuer_public_key,
        ctx.capability,
        ctx.expected_audience_node_id,
        ctx.now,
    )?;
    if is_grant_capability(ctx.capability) {
        verify_grant_invocation(ctx.token, ctx.grant, ctx.owner_proof, ctx.capability, ctx.now)?;
    } else if is_owner_session_capability(ctx.capability) {
        verify_owner_session_invocation(
            ctx.token,
            ctx.grant,
            ctx.owner_proof,
            ctx.capability,
            ctx.expected_body_hash,
            ctx.now,
        )?;
    } else {
        return Err(NodeCoreError::Unauthorized("unsupported relay capability".to_owned()));
    }
    verify_pop_binding(ctx.token, ctx.pop, ctx.capability, ctx.expected_body_hash, ctx.now)
}

pub struct RelayRedbStore {
    db: std::sync::Arc<redb::Database>,
    commit_writer: RelayCommitWriter,
}

struct RelayCommitWriter {
    sender: Option<mpsc::SyncSender<RelayCommitRequest>>,
    thread: Option<thread::JoinHandle<()>>,
}

struct RelayCommitRequest {
    op: RelayCommitOp,
    reply: mpsc::SyncSender<Result<(), NodeCoreError>>,
}

enum RelayCommitOp {
    ChunkEntry { entry: Box<RelayChunkEntry> },
    TombstoneMutation { mutation: Box<ObjectRelayTombstoneMutation> },
    ExpiryMutation { mutation: Box<RelayExpiryMutation> },
}

impl RelayCommitWriter {
    fn start(db: std::sync::Arc<redb::Database>) -> Result<Self, NodeCoreError> {
        let batch_max =
            relay_usize_env(RELAY_COMMIT_BATCH_MAX_ENV, RELAY_COMMIT_BATCH_MAX_DEFAULT).max(1);
        let queue_capacity =
            relay_usize_env(RELAY_COMMIT_QUEUE_CAPACITY_ENV, RELAY_COMMIT_QUEUE_CAPACITY_DEFAULT)
                .max(batch_max);
        let window = Duration::from_micros(relay_u64_env(
            RELAY_COMMIT_WINDOW_US_ENV,
            RELAY_COMMIT_WINDOW_US_DEFAULT,
        ));
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let thread = thread::Builder::new()
            .name("ramflux-relay-commit-writer".to_owned())
            .spawn(move || relay_commit_writer_loop(&db, &receiver, batch_max, window))
            .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn commit(&self, op: RelayCommitOp) -> Result<(), NodeCoreError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestJson("relay commit writer stopped".to_owned()))?
            .send(RelayCommitRequest { op, reply })
            .map_err(|source| {
                NodeCoreError::ItestJson(format!("relay commit writer stopped: {source}"))
            })?;
        response.recv().map_err(|source| {
            NodeCoreError::ItestJson(format!("relay commit response closed: {source}"))
        })?
    }
}

impl Drop for RelayCommitWriter {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}

fn relay_commit_writer_loop(
    db: &redb::Database,
    receiver: &mpsc::Receiver<RelayCommitRequest>,
    batch_max: usize,
    window: Duration,
) {
    while let Ok(first) = receiver.recv() {
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = Instant::now() + window;
        while batch.len() < batch_max {
            match receiver.try_recv() {
                Ok(request) => batch.push(request),
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match receiver.recv_timeout(deadline.saturating_duration_since(now)) {
                        Ok(request) => batch.push(request),
                        Err(
                            mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected,
                        ) => break,
                    }
                }
            }
        }
        let result = relay_commit_batch(db, batch.iter().map(|request| &request.op));
        match result {
            Ok(()) => {
                for request in batch {
                    let _sent = request.reply.send(Ok(()));
                }
            }
            Err(error) => {
                let message = error.to_string();
                for request in batch {
                    let _sent = request.reply.send(Err(NodeCoreError::Redb(message.clone())));
                }
            }
        }
    }
}

fn relay_commit_batch<'a>(
    db: &redb::Database,
    ops: impl Iterator<Item = &'a RelayCommitOp>,
) -> Result<(), NodeCoreError> {
    let write_txn = db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    {
        for op in ops {
            relay_apply_commit_op(&write_txn, op)?;
        }
    }
    write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

fn relay_apply_commit_op(
    write_txn: &redb::WriteTransaction,
    op: &RelayCommitOp,
) -> Result<(), NodeCoreError> {
    match op {
        RelayCommitOp::ChunkEntry { entry } => record_relay_chunk_entry_in_txn(write_txn, entry),
        RelayCommitOp::TombstoneMutation { mutation } => {
            record_relay_tombstone_mutation_in_txn(write_txn, mutation)
        }
        RelayCommitOp::ExpiryMutation { mutation } => {
            record_relay_expiry_mutation_in_txn(write_txn, mutation)
        }
    }
}

fn record_relay_chunk_entry_in_txn(
    write_txn: &redb::WriteTransaction,
    entry: &RelayChunkEntry,
) -> Result<(), NodeCoreError> {
    let entry_bytes = serialize_relay_value(entry)?;
    let mut table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    table
        .insert(entry.chunk_id.as_str(), entry_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    remove_relay_legacy_snapshot(write_txn)
}

fn record_relay_tombstone_mutation_in_txn(
    write_txn: &redb::WriteTransaction,
    mutation: &ObjectRelayTombstoneMutation,
) -> Result<(), NodeCoreError> {
    let tombstone_bytes = serialize_relay_value(&mutation.tombstone)?;
    let mut tombstone_table = write_txn
        .open_table(RELAY_TOMBSTONE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    tombstone_table
        .insert(mutation.tombstone.object_id.as_str(), tombstone_bytes.as_slice())
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let mut chunk_table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for entry in &mutation.affected_chunks {
        let entry_bytes = serialize_relay_value(entry)?;
        chunk_table
            .insert(entry.chunk_id.as_str(), entry_bytes.as_slice())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    remove_relay_legacy_snapshot(write_txn)
}

fn record_relay_expiry_mutation_in_txn(
    write_txn: &redb::WriteTransaction,
    mutation: &RelayExpiryMutation,
) -> Result<(), NodeCoreError> {
    let mut chunk_table = write_txn
        .open_table(RELAY_CHUNK_ENTRY_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for chunk_id in &mutation.expired_chunk_ids {
        let _removed = chunk_table
            .remove(chunk_id.as_str())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    let mut tombstone_table = write_txn
        .open_table(RELAY_TOMBSTONE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    for object_id in &mutation.expired_tombstone_object_ids {
        let _removed = tombstone_table
            .remove(object_id.as_str())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    remove_relay_legacy_snapshot(write_txn)
}

fn relay_usize_env(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn relay_u64_env(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

impl RelayRedbStore {
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| NodeCoreError::StoreDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let db = std::sync::Arc::new(
            redb::Database::create(path)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?,
        );
        let write_txn =
            db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let _table = write_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(RELAY_CHUNK_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let _table = write_txn
                .open_table(RELAY_TOMBSTONE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let commit_writer = RelayCommitWriter::start(std::sync::Arc::clone(&db))?;
        Ok(Self { db, commit_writer })
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn save_state(&self, state: &RelayCacheState) -> Result<(), NodeCoreError> {
        let snapshot = serde_json::to_vec(state)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        let chunk_entries = state
            .chunks_by_id
            .values()
            .map(|entry| serialize_relay_value(entry).map(|bytes| (entry.chunk_id.clone(), bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let tombstone_entries = state
            .tombstones_by_object_id
            .values()
            .map(|tombstone| {
                serialize_relay_value(tombstone).map(|bytes| (tombstone.object_id.clone(), bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(RELAY_CACHE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            replace_relay_table_values(&write_txn, RELAY_CHUNK_ENTRY_TABLE, &chunk_entries)?;
            replace_relay_table_values(&write_txn, RELAY_TOMBSTONE_TABLE, &tombstone_entries)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn load_state(&self) -> Result<Option<RelayCacheState>, NodeCoreError> {
        let (incremental, has_incremental_rows) = self.load_incremental_state()?;
        if has_incremental_rows {
            return Ok(Some(incremental));
        }
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(RELAY_CACHE_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let Some(snapshot) =
            table.get(RELAY_CACHE_KEY).map_err(|source| NodeCoreError::Redb(source.to_string()))?
        else {
            return Ok(None);
        };
        let state = serde_json::from_slice(snapshot.value())
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        Ok(Some(state))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn put_chunk(&self, entry: &RelayChunkEntry) -> Result<(), NodeCoreError> {
        self.record_relay_chunk_entry(entry)
    }

    #[cfg(test)]
    pub(crate) fn save_legacy_state_only(
        &self,
        state: &RelayCacheState,
    ) -> Result<(), NodeCoreError> {
        let snapshot = serde_json::to_vec(state)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut legacy_table = write_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            legacy_table
                .insert(RELAY_CACHE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            replace_relay_table_values(&write_txn, RELAY_CHUNK_ENTRY_TABLE, &[])?;
            replace_relay_table_values(&write_txn, RELAY_TOMBSTONE_TABLE, &[])?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the chunk entry cannot be durably recorded.
    pub fn record_relay_chunk_entry(&self, entry: &RelayChunkEntry) -> Result<(), NodeCoreError> {
        self.commit_writer.commit(RelayCommitOp::ChunkEntry { entry: Box::new(entry.clone()) })
    }

    /// # Errors
    /// Returns an error when the tombstone mutation cannot be durably recorded.
    pub fn record_relay_tombstone_mutation(
        &self,
        mutation: &ObjectRelayTombstoneMutation,
    ) -> Result<(), NodeCoreError> {
        // A stable idempotent replay carries no durable change; skip the write entirely so the
        // redb tombstone/chunk rows are never rewritten.
        if !mutation.changed {
            return Ok(());
        }
        self.commit_writer
            .commit(RelayCommitOp::TombstoneMutation { mutation: Box::new(mutation.clone()) })
    }

    /// # Errors
    /// Returns an error when the expired relay rows cannot be removed.
    pub fn record_relay_expiry_mutation(
        &self,
        mutation: &RelayExpiryMutation,
    ) -> Result<(), NodeCoreError> {
        if mutation.is_empty() {
            return Ok(());
        }
        self.commit_writer
            .commit(RelayCommitOp::ExpiryMutation { mutation: Box::new(mutation.clone()) })
    }

    fn load_incremental_state(&self) -> Result<(RelayCacheState, bool), NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let mut state = RelayCacheState::new();
        let mut has_rows = false;
        {
            let table = read_txn
                .open_table(RELAY_CHUNK_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_rows = true;
                let (_key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let chunk: RelayChunkEntry = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                state.chunks_by_id.insert(chunk.chunk_id.clone(), chunk);
            }
        }
        {
            let table = read_txn
                .open_table(RELAY_TOMBSTONE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for entry in table.iter().map_err(|source| NodeCoreError::Redb(source.to_string()))? {
                has_rows = true;
                let (_key, value) =
                    entry.map_err(|source| NodeCoreError::Redb(source.to_string()))?;
                let tombstone: ObjectRelayTombstone = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                state.tombstones_by_object_id.insert(tombstone.object_id.clone(), tombstone);
            }
        }
        Ok((state, has_rows))
    }
}

fn serialize_relay_value<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn replace_relay_table_values(
    write_txn: &redb::WriteTransaction,
    table: TableDefinition<&str, &[u8]>,
    entries: &[(String, Vec<u8>)],
) -> Result<(), NodeCoreError> {
    let mut table =
        write_txn.open_table(table).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let keys = table
        .iter()
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?
        .map(|entry| {
            entry
                .map(|(key, _value)| key.value().to_owned())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for key in keys {
        let _removed =
            table.remove(key.as_str()).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    for (key, value) in entries {
        table
            .insert(key.as_str(), value.as_slice())
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    }
    Ok(())
}

fn remove_relay_legacy_snapshot(write_txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    let mut table = write_txn
        .open_table(RELAY_CACHE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let _removed =
        table.remove(RELAY_CACHE_KEY).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn shared_relay_store_handles_concurrent_save_and_expiry_without_reopen() -> Result<(), String>
    {
        let store_path = std::env::temp_dir().join(format!(
            "ramflux-relay-shared-store-{}-{}.redb",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|source| source.to_string())?
                .as_nanos()
        ));
        let store =
            Arc::new(RelayRedbStore::open(&store_path).map_err(|source| source.to_string())?);
        let state = Arc::new(Mutex::new(RelayCacheState::new()));
        {
            let state = state.lock().map_err(|source| source.to_string())?;
            store.save_state(&state).map_err(|source| source.to_string())?;
        }

        let mut workers = Vec::new();
        for index in 0..4 {
            let store = Arc::clone(&store);
            let state = Arc::clone(&state);
            workers.push(thread::spawn(move || -> Result<(), String> {
                let mut state = state.lock().map_err(|source| source.to_string())?;
                state.put_chunk(RelayChunkEntry {
                    chunk_id: format!("chunk-{index}"),
                    object_id: "object-shared-store".to_owned(),
                    manifest_hash: "manifest-shared-store".to_owned(),
                    chunk_index: index,
                    chunk_cipher_hash: format!("cipher-hash-{index}"),
                    owner_signing_key_id: "owner-shared-store".to_owned(),
                    owner_public_key: "owner-public-shared-store".to_owned(),
                    encrypted_chunk: vec![
                        u8::try_from(index).map_err(|source| source.to_string())?;
                        8
                    ],
                    stored_at: 0,
                    expires_at: 1,
                    delete_after_ack: false,
                    acked_by: BTreeSet::new(),
                    status: RelayChunkStatus::Available,
                });
                store.save_state(&state).map_err(|source| source.to_string())
            }));
        }
        for worker in workers {
            worker.join().map_err(|_source| "relay worker panicked".to_owned())??;
        }

        {
            let mut state = state.lock().map_err(|source| source.to_string())?;
            let expired = state.expire_chunks(u64::MAX);
            assert_eq!(expired, 4);
            store.save_state(&state).map_err(|source| source.to_string())?;
        }
        let loaded = store
            .load_state()
            .map_err(|source| source.to_string())?
            .ok_or_else(|| "relay state should exist".to_owned())?;
        assert_eq!(loaded.available_count(u64::MAX), 0);

        drop(state);
        drop(store);
        let _ = std::fs::remove_file(store_path);
        Ok(())
    }

    #[test]
    fn relay_token_and_permission_allow_bounded_future_issued_at() -> Result<(), String> {
        let service_key = b"relay-clock-skew-test-key";
        let now = 1_000;
        let issued_at = now + 30;
        let expires_at = now + 300;
        let token =
            test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
        let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

        validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now)
            .map_err(|source| source.to_string())?;
        validate_object_permission(&permission, ObjectRelayCapability::Get, now)
            .map_err(|source| source.to_string())?;
        Ok(())
    }

    #[test]
    fn relay_token_and_permission_reject_future_issued_at_beyond_leeway() -> Result<(), String> {
        let service_key = b"relay-clock-skew-test-key";
        let now = 1_000;
        let issued_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
        let expires_at = issued_at + 300;
        let token =
            test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
        let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

        assert!(
            validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now).is_err()
        );
        assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
        Ok(())
    }

    #[test]
    fn relay_token_and_permission_reject_expired_without_leeway() -> Result<(), String> {
        let service_key = b"relay-clock-skew-test-key";
        let now = 1_000;
        let issued_at = now - 30;
        let expires_at = now;
        let token =
            test_relay_token(service_key, ObjectRelayCapability::Get, issued_at, expires_at)?;
        let permission = test_object_permission(ObjectRelayCapability::Get, issued_at, expires_at)?;

        assert!(
            validate_relay_token(&token, service_key, ObjectRelayCapability::Get, now).is_err()
        );
        assert!(validate_object_permission(&permission, ObjectRelayCapability::Get, now).is_err());
        Ok(())
    }

    #[test]
    fn relay_token_v2_rejects_wrong_issuer_audience_and_capability() -> Result<(), String> {
        let service_key = b"relay-token-v2-key";
        let now = 1_000;
        let token = test_relay_token(service_key, ObjectRelayCapability::Get, now, now + 300)?;

        let mut wrong_issuer = token.clone();
        wrong_issuer.issuer_service = "router".to_owned();
        wrong_issuer.mac =
            relay_token_mac(service_key, &wrong_issuer).map_err(|source| source.to_string())?;
        assert!(
            validate_relay_token(&wrong_issuer, service_key, ObjectRelayCapability::Get, now)
                .is_err()
        );

        let mut wrong_audience = token.clone();
        wrong_audience.audience_service = "ramflux-router".to_owned();
        wrong_audience.mac =
            relay_token_mac(service_key, &wrong_audience).map_err(|source| source.to_string())?;
        assert!(
            validate_relay_token(&wrong_audience, service_key, ObjectRelayCapability::Get, now)
                .is_err()
        );

        let mut multi_capability = token;
        multi_capability.capabilities.push(ObjectRelayCapability::Ack);
        multi_capability.mac =
            relay_token_mac(service_key, &multi_capability).map_err(|source| source.to_string())?;
        assert!(
            validate_relay_token(&multi_capability, service_key, ObjectRelayCapability::Get, now)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn relay_token_v2_rejects_forged_and_expired_tokens() -> Result<(), String> {
        let service_key = b"relay-token-v2-key";
        let now = 1_000;
        let mut forged = test_relay_token(service_key, ObjectRelayCapability::Get, now, now + 300)?;
        forged.object_id = "forged-object".to_owned();
        assert!(
            validate_relay_token(&forged, service_key, ObjectRelayCapability::Get, now).is_err()
        );

        let expired =
            test_relay_token(service_key, ObjectRelayCapability::Get, now - 600, now - 1)?;
        assert!(
            validate_relay_token(&expired, service_key, ObjectRelayCapability::Get, now).is_err()
        );
        Ok(())
    }

    #[test]
    fn relay_token_issue_body_enforces_ttl_and_permission_binding() -> Result<(), String> {
        let now = 1_000;
        let permission = test_object_permission(ObjectRelayCapability::Get, now, now + 300)?;
        let body = RelayTokenIssueBody {
            object_id: permission.object_id.clone(),
            manifest_hash: permission.manifest_hash.clone(),
            chunk_id: "chunk_relay_clock_skew".to_owned(),
            recipient_device_hash: permission.grantee_device_hash.clone(),
            owner_signing_key_id: permission.owner_signing_key_id.clone(),
            owner_public_key: permission.owner_public_key.clone(),
            capability: ObjectRelayCapability::Get,
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS,
            object_permission_envelope: permission.clone(),
        };
        validate_relay_token_issue_body(&body, now).map_err(|source| source.to_string())?;

        let mut long_ttl = body.clone();
        long_ttl.expires_at = now + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS + 1;
        assert!(validate_relay_token_issue_body(&long_ttl, now).is_err());

        let mut mismatched = body;
        mismatched.recipient_device_hash = "other_recipient".to_owned();
        assert!(validate_relay_token_issue_body(&mismatched, now).is_err());
        Ok(())
    }

    fn test_relay_token(
        service_key: &[u8],
        capability: ObjectRelayCapability,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<RelayToken, String> {
        let mut token = RelayToken {
            token_version: OBJECT_RELAY_TOKEN_VERSION,
            token_id: format!("token_clock_skew_{capability:?}_{issued_at}"),
            object_id: "object_relay_clock_skew".to_owned(),
            manifest_hash: "manifest_relay_clock_skew".to_owned(),
            chunk_id: "chunk_relay_clock_skew".to_owned(),
            recipient_device_hash: "recipient_clock_skew".to_owned(),
            owner_signing_key_id: "owner_fixture_key".to_owned(),
            owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
            issuer_service: OBJECT_RELAY_TOKEN_ISSUER_GATEWAY.to_owned(),
            audience_service: OBJECT_RELAY_TOKEN_AUDIENCE_RELAY.to_owned(),
            capabilities: vec![capability],
            delete_after_ack: false,
            issued_at,
            expires_at,
            nonce: format!("nonce_clock_skew_{issued_at}"),
            mac: String::new(),
        };
        token.mac = relay_token_mac(service_key, &token).map_err(|source| source.to_string())?;
        Ok(token)
    }

    fn test_object_permission(
        capability: ObjectRelayCapability,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<ObjectPermissionEnvelope, String> {
        let mut permission = ObjectPermissionEnvelope {
            object_id: "object_relay_clock_skew".to_owned(),
            manifest_hash: "manifest_relay_clock_skew".to_owned(),
            grantee_device_hash: "recipient_clock_skew".to_owned(),
            capability,
            issued_at,
            expires_at,
            owner_signing_key_id: "owner_fixture_key".to_owned(),
            owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
            owner_signature: String::new(),
        };
        permission.owner_signature = ramflux_crypto::sign_canonical_bytes(
            &object_permission_canonical_bytes(&permission).map_err(|source| source.to_string())?,
        );
        Ok(permission)
    }

    // ---- RQ-03-V3-T1 pure-verification tests ----

    const V3_OWNER_SEED: [u8; 32] = [0x11; 32];
    const V3_REQUESTER_SEED: [u8; 32] = [0x22; 32];
    const V3_ISSUER_SEED: [u8; 32] = [0x33; 32];
    const V3_OWNER_ID: &str = "device_a_owner";
    const V3_REQUESTER_ID: &str = "device_b_requester";
    const V3_OBJECT: &str = "object_v3";
    const V3_MANIFEST: &str = "manifest_v3";
    const V3_CHUNK: &str = "chunk_v3";
    const V3_BODY_HASH: &str = "body_hash_v3";
    const V3_AUDIENCE_NODE: &str = "node-a";

    fn v3_pk(seed: [u8; 32]) -> String {
        ramflux_crypto::public_key_base64url_from_seed(seed)
    }

    fn v3_requester_hash() -> String {
        ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            V3_REQUESTER_ID.as_bytes(),
        )
    }

    fn v3_sign(bytes: &[u8], seed: [u8; 32]) -> String {
        ramflux_crypto::sign_canonical_bytes_with_seed(bytes, seed)
    }

    fn v3_signed_grant(
        now: u64,
        capabilities: Vec<ObjectRelayCapability>,
    ) -> Result<ObjectAccessGrant, String> {
        let mut grant = ObjectAccessGrant {
            schema: OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            grantee_device_hash: v3_requester_hash(),
            capabilities,
            issued_at: now,
            expires_at: now + 300,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_signature: String::new(),
        };
        grant.owner_signature = v3_sign(
            &object_access_grant_signing_bytes(&grant).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        Ok(grant)
    }

    fn v3_signed_owner_proof(
        now: u64,
        capability: ObjectRelayCapability,
    ) -> Result<OwnerAuthorizationProof, String> {
        let mut proof = OwnerAuthorizationProof {
            schema: OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            capability,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: Some(V3_MANIFEST.to_owned()),
            chunk_id: Some(V3_CHUNK.to_owned()),
            owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
            owner_principal_id: "principal_a".to_owned(),
            owner_device_epoch: 3,
            request_nonce: "owner_proof_nonce_v3".to_owned(),
            body_hash: V3_BODY_HASH.to_owned(),
            issued_at: now,
            expires_at: now + 120,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_signature: String::new(),
        };
        proof.owner_signature = v3_sign(
            &owner_authorization_proof_signing_bytes(&proof).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        Ok(proof)
    }

    fn v3_resign_token(token: &mut RelayTokenV3) -> Result<(), String> {
        token.issuer_signature = v3_sign(
            &relay_token_v3_signing_bytes(token).map_err(|e| e.to_string())?,
            V3_ISSUER_SEED,
        );
        Ok(())
    }

    fn v3_grant_token(
        now: u64,
        capability: ObjectRelayCapability,
        binding_hash: String,
    ) -> Result<RelayTokenV3, String> {
        let mut token = RelayTokenV3 {
            token_version: OBJECT_RELAY_TOKEN_V3_VERSION,
            token_id: "tok_v3_grant".to_owned(),
            requester_device_id: V3_REQUESTER_ID.to_owned(),
            requester_device_hash: v3_requester_hash(),
            requester_public_key: v3_pk(V3_REQUESTER_SEED),
            requester_device_epoch: 7,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
            owner_home_node_id: V3_AUDIENCE_NODE.to_owned(),
            owner_principal_id: "principal_a".to_owned(),
            owner_device_epoch: 3,
            issuer_node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
            issuer_certificate_id: V3_CERT_ID.to_owned(),
            attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
            issuer_certificate: v3_certificate(now, |_cert| {})?,
            audience_service: RELAY_TOKEN_V3_AUDIENCE_RELAY.to_owned(),
            audience_node_id: V3_AUDIENCE_NODE.to_owned(),
            relay_instance_id: None,
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            chunk_id: V3_CHUNK.to_owned(),
            capabilities: vec![capability],
            authorization_kind: RelayAuthorizationKind::OwnerGrant,
            authorization_binding_hash: binding_hash,
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + 120,
            nonce: "nonce_tok_v3".to_owned(),
            issuer_signature: String::new(),
        };
        v3_resign_token(&mut token)?;
        Ok(token)
    }

    fn v3_owner_session_token(
        now: u64,
        capability: ObjectRelayCapability,
        binding_hash: String,
    ) -> Result<RelayTokenV3, String> {
        // Owner-session operations: the requester is the owner device itself.
        let mut token = v3_grant_token(now, capability, binding_hash)?;
        token.authorization_kind = RelayAuthorizationKind::OwnerSession;
        token.requester_device_id = V3_OWNER_ID.to_owned();
        token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            V3_OWNER_ID.as_bytes(),
        );
        token.requester_public_key = v3_pk(V3_OWNER_SEED);
        v3_resign_token(&mut token)?;
        Ok(token)
    }

    fn v3_signed_pop(
        token: &RelayTokenV3,
        capability: ObjectRelayCapability,
        signer_seed: [u8; 32],
        now: u64,
    ) -> Result<RequesterProofOfPossession, String> {
        let mut pop = RequesterProofOfPossession {
            schema: REQUESTER_POP_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            token_id: token.token_id.clone(),
            capability,
            object_id: token.object_id.clone(),
            manifest_hash: token.manifest_hash.clone(),
            chunk_id: token.chunk_id.clone(),
            request_nonce: "req_nonce_v3".to_owned(),
            body_hash: V3_BODY_HASH.to_owned(),
            issued_at: now,
            expires_at: now + 60,
            signer_device_id: token.requester_device_id.clone(),
            signer_public_key: token.requester_public_key.clone(),
            signature: String::new(),
        };
        pop.signature =
            v3_sign(&requester_pop_signing_bytes(&pop).map_err(|e| e.to_string())?, signer_seed);
        Ok(pop)
    }

    #[test]
    fn v3_get_and_ack_invocation_accepts_valid() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        for capability in [ObjectRelayCapability::Get, ObjectRelayCapability::Ack] {
            let grant =
                v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Ack])?;
            let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
            let token = v3_grant_token(now, capability, binding)?;
            let pop = v3_signed_pop(&token, capability, V3_REQUESTER_SEED, now)?;
            let ctx = RelayInvocationV3 {
                token: &token,
                issuer_public_key: &issuer_pk,
                grant: Some(&grant),
                owner_proof: None,
                pop: &pop,
                expected_audience_node_id: V3_AUDIENCE_NODE,
                expected_body_hash: V3_BODY_HASH,
                capability,
                now,
            };
            verify_relay_invocation_v3(&ctx).map_err(|e| format!("{capability:?}: {e}"))?;
        }
        Ok(())
    }

    #[test]
    fn v3_put_and_tombstone_invocation_accepts_valid() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        for capability in [ObjectRelayCapability::Put, ObjectRelayCapability::Tombstone] {
            let proof = v3_signed_owner_proof(now, capability)?;
            let binding =
                owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?;
            let token = v3_owner_session_token(now, capability, binding)?;
            let pop = v3_signed_pop(&token, capability, V3_OWNER_SEED, now)?;
            let ctx = RelayInvocationV3 {
                token: &token,
                issuer_public_key: &issuer_pk,
                grant: None,
                owner_proof: Some(&proof),
                pop: &pop,
                expected_audience_node_id: V3_AUDIENCE_NODE,
                expected_body_hash: V3_BODY_HASH,
                capability,
                now,
            };
            verify_relay_invocation_v3(&ctx).map_err(|e| format!("{capability:?}: {e}"))?;
        }
        Ok(())
    }

    #[test]
    fn v3_rejects_v2_token_version() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let mut token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        token.token_version = 2;
        v3_resign_token(&mut token)?;
        assert!(matches!(
            verify_relay_token_v3(
                &token,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_canonical_tamper() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;

        // Tamper token without re-signing -> issuer signature invalid.
        let mut tampered_token = token.clone();
        tampered_token.object_id = "object_forged".to_owned();
        assert!(
            verify_relay_token_v3(
                &tampered_token,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            )
            .is_err()
        );

        // Tamper grant without re-signing -> owner signature invalid.
        let mut tampered_grant = grant.clone();
        tampered_grant.grantee_device_hash = "forged_grantee".to_owned();
        assert!(
            verify_object_access_grant(&tampered_grant, ObjectRelayCapability::Get, now).is_err()
        );

        // Tamper pop without re-signing -> requester signature invalid.
        let mut pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        pop.request_nonce = "forged_nonce".to_owned();
        assert!(verify_requester_pop(&pop, &token.requester_public_key, now).is_err());
        Ok(())
    }

    #[test]
    fn v3_rejects_wrong_owner_or_grantee() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

        // Token owner differs from grant owner.
        let mut wrong_owner = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
        wrong_owner.owner_public_key = v3_pk(V3_REQUESTER_SEED);
        v3_resign_token(&mut wrong_owner)?;
        let pop = v3_signed_pop(&wrong_owner, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        let ctx = RelayInvocationV3 {
            token: &wrong_owner,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: None,
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Get,
            now,
        };
        assert!(matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_))));

        // Grant grantee differs from token requester.
        let mut wrong_grantee_grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        wrong_grantee_grant.grantee_device_hash = "other_grantee".to_owned();
        wrong_grantee_grant.owner_signature = v3_sign(
            &object_access_grant_signing_bytes(&wrong_grantee_grant).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        let binding2 =
            object_access_grant_binding_hash(&wrong_grantee_grant).map_err(|e| e.to_string())?;
        let token2 = v3_grant_token(now, ObjectRelayCapability::Get, binding2)?;
        let pop2 = v3_signed_pop(&token2, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        let ctx2 = RelayInvocationV3 {
            token: &token2,
            issuer_public_key: &issuer_pk,
            grant: Some(&wrong_grantee_grant),
            owner_proof: None,
            pop: &pop2,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Get,
            now,
        };
        assert!(matches!(verify_relay_invocation_v3(&ctx2), Err(NodeCoreError::Unauthorized(_))));
        Ok(())
    }

    #[test]
    fn v3_rejects_expired_future_ttl_and_over_max() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

        let mut expired = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
        expired.issued_at = now - 600;
        expired.expires_at = now;
        v3_resign_token(&mut expired)?;
        assert!(matches!(
            verify_relay_token_v3(
                &expired,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let mut future = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
        future.issued_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
        future.expires_at = future.issued_at + 120;
        v3_resign_token(&mut future)?;
        assert!(matches!(
            verify_relay_token_v3(
                &future,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let mut over_max = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        over_max.expires_at = over_max.issued_at + OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS + 1;
        v3_resign_token(&mut over_max)?;
        assert!(matches!(
            verify_relay_token_v3(
                &over_max,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_wrong_audience() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        assert!(matches!(
            verify_relay_token_v3(&token, &issuer_pk, ObjectRelayCapability::Get, "node-z", now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_proof_kind_mix() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        let pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        let proof = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;

        // Get carrying an owner proof (extra proof) -> reject.
        let ctx_extra = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: Some(&proof),
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Get,
            now,
        };
        assert!(matches!(
            verify_relay_invocation_v3(&ctx_extra),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Get with no grant -> reject.
        let ctx_missing = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: None,
            owner_proof: None,
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Get,
            now,
        };
        assert!(matches!(
            verify_relay_invocation_v3(&ctx_missing),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Token with wrong authorization_kind for the capability -> reject at token verify.
        let mut wrong_kind = token.clone();
        wrong_kind.authorization_kind = RelayAuthorizationKind::OwnerSession;
        v3_resign_token(&mut wrong_kind)?;
        assert!(matches!(
            verify_relay_token_v3(
                &wrong_kind,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Put carrying a grant (wrong instrument) -> reject.
        let owner_token = v3_owner_session_token(
            now,
            ObjectRelayCapability::Put,
            owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?,
        )?;
        let owner_pop =
            v3_signed_pop(&owner_token, ObjectRelayCapability::Put, V3_OWNER_SEED, now)?;
        let ctx_put_grant = RelayInvocationV3 {
            token: &owner_token,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: Some(&proof),
            pop: &owner_pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Put,
            now,
        };
        assert!(matches!(
            verify_relay_invocation_v3(&ctx_put_grant),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_grant_with_put_or_tombstone_capability() -> Result<(), String> {
        let now = 1_000_000;
        // A grant carrying Put is invalid for any get/ack verification.
        let bad_grant =
            v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Put])?;
        assert!(matches!(
            verify_object_access_grant(&bad_grant, ObjectRelayCapability::Get, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        // Asking a grant to authorize Tombstone is rejected.
        let grant =
            v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Ack])?;
        assert!(matches!(
            verify_object_access_grant(&grant, ObjectRelayCapability::Tombstone, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_wrong_requester_key_nonce_body() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;

        let base_ctx = |pop: &RequesterProofOfPossession, body: &str| -> bool {
            let ctx = RelayInvocationV3 {
                token: &token,
                issuer_public_key: &issuer_pk,
                grant: Some(&grant),
                owner_proof: None,
                pop,
                expected_audience_node_id: V3_AUDIENCE_NODE,
                expected_body_hash: body,
                capability: ObjectRelayCapability::Get,
                now,
            };
            matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_)))
        };

        // PoP signed with a key that is not the requester's -> signature fails.
        let wrong_key_pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_ISSUER_SEED, now)?;
        assert!(base_ctx(&wrong_key_pop, V3_BODY_HASH));

        // Body hash mismatch.
        let good_pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        assert!(base_ctx(&good_pop, "different_body_hash"));

        // Tampered nonce after signing -> signature fails.
        let mut nonce_pop = good_pop.clone();
        nonce_pop.request_nonce = "tampered_nonce".to_owned();
        assert!(base_ctx(&nonce_pop, V3_BODY_HASH));

        // PoP bound to a different token id.
        let mut other_token_pop = good_pop.clone();
        other_token_pop.token_id = "other_token".to_owned();
        other_token_pop.signature = v3_sign(
            &requester_pop_signing_bytes(&other_token_pop).map_err(|e| e.to_string())?,
            V3_REQUESTER_SEED,
        );
        assert!(base_ctx(&other_token_pop, V3_BODY_HASH));
        Ok(())
    }

    #[test]
    fn v3_rejects_authorization_binding_hash_mismatch() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        // Token carries a bogus binding hash but is re-signed, so the issuer signature is valid and
        // only the grant-binding comparison fails.
        let token =
            v3_grant_token(now, ObjectRelayCapability::Get, "bogus_binding_hash".to_owned())?;
        let pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        let ctx = RelayInvocationV3 {
            token: &token,
            issuer_public_key: &issuer_pk,
            grant: Some(&grant),
            owner_proof: None,
            pop: &pop,
            expected_audience_node_id: V3_AUDIENCE_NODE,
            expected_body_hash: V3_BODY_HASH,
            capability: ObjectRelayCapability::Get,
            now,
        };
        assert!(matches!(verify_relay_invocation_v3(&ctx), Err(NodeCoreError::Unauthorized(_))));
        Ok(())
    }

    fn v3_resign_owner_proof(
        mut proof: OwnerAuthorizationProof,
    ) -> Result<OwnerAuthorizationProof, String> {
        proof.owner_signature = v3_sign(
            &owner_authorization_proof_signing_bytes(&proof).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        Ok(proof)
    }

    #[test]
    fn v3_rejects_owner_proof_tampered_fields() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);

        // Build a consistent Put invocation for a given (already-signed) owner proof and verify.
        let run = |proof: &OwnerAuthorizationProof| -> Result<Result<(), NodeCoreError>, String> {
            let binding =
                owner_authorization_proof_binding_hash(proof).map_err(|e| e.to_string())?;
            let token = v3_owner_session_token(now, ObjectRelayCapability::Put, binding)?;
            let pop = v3_signed_pop(&token, ObjectRelayCapability::Put, V3_OWNER_SEED, now)?;
            let ctx = RelayInvocationV3 {
                token: &token,
                issuer_public_key: &issuer_pk,
                grant: None,
                owner_proof: Some(proof),
                pop: &pop,
                expected_audience_node_id: V3_AUDIENCE_NODE,
                expected_body_hash: V3_BODY_HASH,
                capability: ObjectRelayCapability::Put,
                now,
            };
            Ok(verify_relay_invocation_v3(&ctx))
        };

        let valid = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;
        assert!(run(&valid)?.is_ok(), "baseline put owner proof must verify");

        // Re-signed semantic mismatches (signature + binding valid; a cross-check fails).
        let mut bad_body = valid.clone();
        bad_body.body_hash = "wrong_body".to_owned();
        assert!(matches!(
            run(&v3_resign_owner_proof(bad_body)?)?,
            Err(NodeCoreError::Unauthorized(_))
        ));

        let mut bad_manifest = valid.clone();
        bad_manifest.manifest_hash = Some("wrong_manifest".to_owned());
        assert!(matches!(
            run(&v3_resign_owner_proof(bad_manifest)?)?,
            Err(NodeCoreError::Unauthorized(_))
        ));

        let mut none_chunk = valid.clone();
        none_chunk.chunk_id = None;
        assert!(matches!(
            run(&v3_resign_owner_proof(none_chunk)?)?,
            Err(NodeCoreError::Unauthorized(_))
        ));

        let mut wrong_chunk = valid.clone();
        wrong_chunk.chunk_id = Some("wrong_chunk".to_owned());
        assert!(matches!(
            run(&v3_resign_owner_proof(wrong_chunk)?)?,
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Tamper the request_nonce without re-signing: the owner signature no longer verifies
        // (confirms request_nonce is part of the signed canonical bytes).
        let mut tampered_nonce = valid;
        tampered_nonce.request_nonce = "tampered_nonce".to_owned();
        assert!(run(&tampered_nonce)?.is_err());
        Ok(())
    }

    #[test]
    fn v3_rejects_tombstone_delete_after_ack() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);
        let proof = v3_signed_owner_proof(now, ObjectRelayCapability::Tombstone)?;
        let binding = owner_authorization_proof_binding_hash(&proof).map_err(|e| e.to_string())?;
        let mut token = v3_owner_session_token(now, ObjectRelayCapability::Tombstone, binding)?;
        token.delete_after_ack = true;
        v3_resign_token(&mut token)?;
        assert!(matches!(
            verify_relay_token_v3(
                &token,
                &issuer_pk,
                ObjectRelayCapability::Tombstone,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_wrong_proof_version() -> Result<(), String> {
        let now = 1_000_000;

        let mut grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        grant.version = 2;
        grant.owner_signature = v3_sign(
            &object_access_grant_signing_bytes(&grant).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        assert!(matches!(
            verify_object_access_grant(&grant, ObjectRelayCapability::Get, now),
            Err(NodeCoreError::ItestJson(_))
        ));

        let mut proof = v3_signed_owner_proof(now, ObjectRelayCapability::Put)?;
        proof.version = 2;
        let proof = v3_resign_owner_proof(proof)?;
        assert!(matches!(
            verify_owner_authorization_proof(&proof, ObjectRelayCapability::Put, now),
            Err(NodeCoreError::ItestJson(_))
        ));

        let grant2 = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant2).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        let mut pop = v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        pop.version = 2;
        pop.signature = v3_sign(
            &requester_pop_signing_bytes(&pop).map_err(|e| e.to_string())?,
            V3_REQUESTER_SEED,
        );
        assert!(matches!(
            verify_requester_pop(&pop, &token.requester_public_key, now),
            Err(NodeCoreError::ItestJson(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_rejects_duplicate_capability_and_empty_fields() -> Result<(), String> {
        let now = 1_000_000;
        let issuer_pk = v3_pk(V3_ISSUER_SEED);

        // Duplicate capability in a grant.
        let dup_grant =
            v3_signed_grant(now, vec![ObjectRelayCapability::Get, ObjectRelayCapability::Get])?;
        assert!(matches!(
            verify_object_access_grant(&dup_grant, ObjectRelayCapability::Get, now),
            Err(NodeCoreError::Unauthorized(_))
        ));

        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;

        // Empty token nonce.
        let mut empty_nonce = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
        empty_nonce.nonce = String::new();
        v3_resign_token(&mut empty_nonce)?;
        assert!(matches!(
            verify_relay_token_v3(
                &empty_nonce,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Empty owner public key on token.
        let mut empty_key = v3_grant_token(now, ObjectRelayCapability::Get, binding.clone())?;
        empty_key.owner_public_key = String::new();
        v3_resign_token(&mut empty_key)?;
        assert!(matches!(
            verify_relay_token_v3(
                &empty_key,
                &issuer_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Empty PoP request nonce (re-signed so only the non-empty guard fires).
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        let mut empty_pop_nonce =
            v3_signed_pop(&token, ObjectRelayCapability::Get, V3_REQUESTER_SEED, now)?;
        empty_pop_nonce.request_nonce = String::new();
        empty_pop_nonce.signature = v3_sign(
            &requester_pop_signing_bytes(&empty_pop_nonce).map_err(|e| e.to_string())?,
            V3_REQUESTER_SEED,
        );
        assert!(matches!(
            verify_requester_pop(&empty_pop_nonce, &token.requester_public_key, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    // ---- RQ-03-V3-T2 certificate-chain tests ----

    const V3_ROOT_SEED: [u8; 32] = [0x44; 32];
    const V3_ISSUER_NODE: &str = "node-b";
    const V3_GATEWAY_INSTANCE: &str = "gw-b-1";
    const V3_CERT_ID: &str = "cert-b-1";
    const V3_ATTESTATION_KEY_ID: &str = "att-b-1";

    // Builds a node-root-signed certificate whose attestation key is the issuer key used to sign the
    // v3 token fixtures, then applies `apply` and (re)signs so overrides yield a valid root
    // signature (for semantic-mismatch tests). Fields match the token fixture's issuer identity.
    fn v3_certificate(
        now: u64,
        apply: impl FnOnce(&mut GatewayIssuerCertificate),
    ) -> Result<GatewayIssuerCertificate, String> {
        let mut cert = GatewayIssuerCertificate {
            schema: GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            cert_id: V3_CERT_ID.to_owned(),
            node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
            attestation_public_key: v3_pk(V3_ISSUER_SEED),
            attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
            not_before: now - 10,
            not_after: now + 3_600,
            issued_at: now - 10,
            node_root_signing_key_id: "node-b#root".to_owned(),
            node_root_signature: String::new(),
            revoked_at: None,
        };
        apply(&mut cert);
        cert.node_root_signature = v3_sign(
            &gateway_issuer_certificate_signing_bytes(&cert).map_err(|e| e.to_string())?,
            V3_ROOT_SEED,
        );
        Ok(cert)
    }

    fn v3_get_token_for_cert(now: u64) -> Result<(RelayTokenV3, ObjectAccessGrant), String> {
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        Ok((token, grant))
    }

    #[test]
    fn v3_certificate_valid_chain_accepts() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let cert = v3_certificate(now, |_cert| {})?;
        verify_gateway_issuer_certificate(
            &cert,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_certificate_rejects_wrong_node_or_instance() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let wrong_node = v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &wrong_node,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        let wrong_instance =
            v3_certificate(now, |cert| cert.gateway_instance_id = "gw-z".to_owned())?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &wrong_instance,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_certificate_rejects_expired_not_yet_valid_and_revoked() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);

        let expired = v3_certificate(now, |cert| {
            cert.not_before = now - 100;
            cert.not_after = now - 1;
        })?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &expired,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let not_yet = v3_certificate(now, |cert| {
            cert.not_before = now + 1_000;
            cert.not_after = now + 2_000;
            cert.issued_at = now + 1_000;
        })?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &not_yet,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let inverted = v3_certificate(now, |cert| {
            cert.not_before = now + 100;
            cert.not_after = now + 10;
            cert.issued_at = now + 10;
        })?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &inverted,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // issued_at outside the validity window (below not_before and above not_after).
        let issued_before = v3_certificate(now, |cert| {
            cert.not_before = now - 50;
            cert.not_after = now + 50;
            cert.issued_at = now - 100;
        })?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &issued_before,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        let issued_after = v3_certificate(now, |cert| {
            cert.not_before = now - 50;
            cert.not_after = now + 50;
            cert.issued_at = now + 100;
        })?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &issued_after,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        let revoked = v3_certificate(now, |cert| cert.revoked_at = Some(now - 1))?;
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &revoked,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_certificate_rejects_root_signature_tamper() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);

        // Tamper a signed field without re-signing -> root signature invalid.
        let mut tampered = v3_certificate(now, |_cert| {})?;
        tampered.attestation_public_key = v3_pk(V3_OWNER_SEED);
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &tampered,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Certificate signed by a key that is not the pinned node root -> rejected.
        let mut wrong_root = v3_certificate(now, |_cert| {})?;
        wrong_root.node_root_signature = v3_sign(
            &gateway_issuer_certificate_signing_bytes(&wrong_root).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &wrong_root,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_token_with_certificate_accepts_valid_chain() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let (token, _grant) = v3_get_token_for_cert(now)?;
        let cert = v3_certificate(now, |_cert| {})?;
        verify_relay_token_v3_with_certificate(
            &token,
            &cert,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_token_with_certificate_rejects_wrong_cert_key_id_or_issuer() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let (token, _grant) = v3_get_token_for_cert(now)?;

        // Certificate id does not match the token's issuer_certificate_id.
        let wrong_cert_id = v3_certificate(now, |cert| cert.cert_id = "cert-z".to_owned())?;
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &token,
                &wrong_cert_id,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Attestation key id does not match the token.
        let wrong_key_id =
            v3_certificate(now, |cert| cert.attestation_key_id = "att-z".to_owned())?;
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &token,
                &wrong_key_id,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Certificate for a different node than the token's issuer node.
        let wrong_node = v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &token,
                &wrong_node,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Certificate whose attestation key does not match the key that actually signed the token.
        let wrong_attestation_key = v3_certificate(now, |cert| {
            cert.attestation_public_key = v3_pk(V3_OWNER_SEED);
        })?;
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &token,
                &wrong_attestation_key,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_token_certificate_rejects_frame_replacement_and_tamper() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let (token, _grant) = v3_get_token_for_cert(now)?;
        let expected = token.issuer_certificate.clone();

        // Sanity: the embedded certificate equals the expected certificate -> valid chain.
        verify_relay_token_v3_with_certificate(
            &token,
            &expected,
            &root_pk,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;

        // Frame replacement: a different (still root-valid) certificate is presented as expected.
        let other = v3_certificate(now, |cert| cert.cert_id = "cert-other".to_owned())?;
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &token,
                &other,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Embedded certificate tampered without re-signing the token: the embedded/expected
        // comparison fails (canonical differs).
        let mut tampered = token.clone();
        tampered.issuer_certificate.attestation_public_key = v3_pk(V3_OWNER_SEED);
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &tampered,
                &expected,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Even if the caller passes the tampered embedded certificate as expected (comparison
        // matches), the tampered certificate no longer verifies against the pinned node root.
        let expected_tampered = tampered.issuer_certificate.clone();
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &tampered,
                &expected_tampered,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Embedded certificate names a different node than the token's issuer_node_id (embedded ==
        // expected, token re-signed), caught by the root-bound certificate verification.
        let mut mismatched = v3_get_token_for_cert(now)?.0;
        mismatched.issuer_certificate =
            v3_certificate(now, |cert| cert.node_id = "node-z".to_owned())?;
        v3_resign_token(&mut mismatched)?;
        let mismatched_expected = mismatched.issuer_certificate.clone();
        assert!(matches!(
            verify_relay_token_v3_with_certificate(
                &mismatched,
                &mismatched_expected,
                &root_pk,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    // ---- RQ-03-V3-T3 certificate issuance (request PoP + node-root issuance) tests ----

    const V3_ROOT_KEY_ID: &str = "node-b#root";

    fn v3_certificate_request(
        now: u64,
        apply: impl FnOnce(&mut GatewayCertificateRequest),
    ) -> Result<GatewayCertificateRequest, String> {
        let mut request = GatewayCertificateRequest {
            schema: GATEWAY_CERTIFICATE_REQUEST_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            request_id: "req-v3-1".to_owned(),
            node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
            attestation_public_key: v3_pk(V3_ISSUER_SEED),
            attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
            not_before: now - 10,
            not_after: now + 3_600,
            requested_at: now,
            request_nonce: "req-nonce-v3".to_owned(),
            request_signature: String::new(),
        };
        apply(&mut request);
        request.request_signature = v3_sign(
            &gateway_certificate_request_signing_bytes(&request).map_err(|e| e.to_string())?,
            V3_ISSUER_SEED,
        );
        Ok(request)
    }

    #[test]
    fn v3_certificate_request_and_issue_valid_chain() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let request = v3_certificate_request(now, |_r| {})?;
        verify_gateway_certificate_request(&request, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
            .map_err(|e| e.to_string())?;

        let cert = issue_gateway_issuer_certificate(
            &request,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-issued-1",
            now,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(cert.cert_id, "cert-issued-1");
        assert_eq!(cert.issued_at, now);
        assert_eq!(cert.node_id, V3_ISSUER_NODE);
        assert_eq!(cert.gateway_instance_id, V3_GATEWAY_INSTANCE);
        assert_eq!(cert.attestation_public_key, v3_pk(V3_ISSUER_SEED));
        assert_eq!(cert.attestation_key_id, V3_ATTESTATION_KEY_ID);
        assert_eq!(cert.node_root_signing_key_id, V3_ROOT_KEY_ID);
        assert!(cert.revoked_at.is_none());

        // The issued certificate verifies under the T2 verifier against the node root.
        verify_gateway_issuer_certificate(
            &cert,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_certificate_request_rejects_wrong_attestation_key_and_tamper() -> Result<(), String> {
        let now = 1_000_000;

        // Request signed by a key other than its declared attestation key.
        let mut wrong_key = v3_certificate_request(now, |_r| {})?;
        wrong_key.request_signature = v3_sign(
            &gateway_certificate_request_signing_bytes(&wrong_key).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        assert!(matches!(
            verify_gateway_certificate_request(
                &wrong_key,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Tamper a field / nonce without re-signing -> attestation signature invalid.
        let mut tampered = v3_certificate_request(now, |_r| {})?;
        tampered.request_nonce = "forged_nonce".to_owned();
        assert!(
            verify_gateway_certificate_request(&tampered, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn v3_certificate_request_rejects_wrong_node_instance_and_window() -> Result<(), String> {
        let now = 1_000_000;
        let request = v3_certificate_request(now, |_r| {})?;
        assert!(matches!(
            verify_gateway_certificate_request(&request, "node-z", V3_GATEWAY_INSTANCE, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        assert!(matches!(
            verify_gateway_certificate_request(&request, V3_ISSUER_NODE, "gw-z", now),
            Err(NodeCoreError::Unauthorized(_))
        ));

        let inverted = v3_certificate_request(now, |r| {
            r.not_before = now + 100;
            r.not_after = now + 10;
        })?;
        assert!(matches!(
            verify_gateway_certificate_request(&inverted, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
            Err(NodeCoreError::Unauthorized(_))
        ));

        let expired = v3_certificate_request(now, |r| {
            r.not_before = now - 100;
            r.not_after = now - 1;
        })?;
        assert!(matches!(
            verify_gateway_certificate_request(&expired, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let future_requested_at = v3_certificate_request(now, |r| {
            r.requested_at = now + OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS + 1;
        })?;
        assert!(matches!(
            verify_gateway_certificate_request(
                &future_requested_at,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        // Stale request: requested_at older than the max age is rejected and is not issued.
        let stale = v3_certificate_request(now, |r| {
            r.requested_at = now - GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS - 1;
        })?;
        assert!(matches!(
            verify_gateway_certificate_request(&stale, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        assert!(matches!(
            issue_gateway_issuer_certificate(
                &stale,
                V3_ROOT_KEY_ID,
                V3_ROOT_SEED,
                "cert-stale",
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        // Boundary: requested_at exactly at the max age is still accepted.
        let at_max_age = v3_certificate_request(now, |r| {
            r.requested_at = now - GATEWAY_CERTIFICATE_REQUEST_MAX_AGE_SECONDS;
        })?;
        verify_gateway_certificate_request(&at_max_age, V3_ISSUER_NODE, V3_GATEWAY_INSTANCE, now)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_issue_rejects_future_not_before_and_over_max_window() -> Result<(), String> {
        let now = 1_000_000;

        // not_before in the future: the certificate would not be active at issuance (issued_at=now
        // outside window).
        let future_not_before = v3_certificate_request(now, |r| {
            r.not_before = now + 100;
            r.not_after = now + 200;
        })?;
        assert!(matches!(
            issue_gateway_issuer_certificate(
                &future_not_before,
                V3_ROOT_KEY_ID,
                V3_ROOT_SEED,
                "cert-x",
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // not_after beyond the hard maximum TTL.
        let over_max = v3_certificate_request(now, |r| {
            r.not_before = now - 10;
            r.not_after = now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS + 1;
        })?;
        assert!(matches!(
            issue_gateway_issuer_certificate(
                &over_max,
                V3_ROOT_KEY_ID,
                V3_ROOT_SEED,
                "cert-x",
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Boundary: exactly the maximum TTL is accepted and the issued cert verifies.
        let root_pk = v3_pk(V3_ROOT_SEED);
        let at_max = v3_certificate_request(now, |r| {
            r.not_before = now - 10;
            r.not_after = now + GATEWAY_ISSUER_CERTIFICATE_MAX_TTL_SECONDS;
        })?;
        let cert = issue_gateway_issuer_certificate(
            &at_max,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-max",
            now,
        )
        .map_err(|e| e.to_string())?;
        verify_gateway_issuer_certificate(
            &cert,
            &root_pk,
            V3_ISSUER_NODE,
            V3_GATEWAY_INSTANCE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_issued_certificate_root_tamper_and_revocation() -> Result<(), String> {
        let now = 1_000_000;
        let root_pk = v3_pk(V3_ROOT_SEED);
        let request = v3_certificate_request(now, |_r| {})?;
        let cert = issue_gateway_issuer_certificate(
            &request,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-rev-1",
            now,
        )
        .map_err(|e| e.to_string())?;

        // Root signature tamper: mutate a signed field without re-signing.
        let mut tampered = cert.clone();
        tampered.attestation_public_key = v3_pk(V3_OWNER_SEED);
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &tampered,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Certificate signed by a non-root key is rejected.
        let mut wrong_root = cert.clone();
        wrong_root.node_root_signature = v3_sign(
            &gateway_issuer_certificate_signing_bytes(&wrong_root).map_err(|e| e.to_string())?,
            V3_OWNER_SEED,
        );
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &wrong_root,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Revocation binds by all identity fields; a mismatch does not apply.
        let mismatched = GatewayCertificateRevocation {
            cert_id: "cert-other".to_owned(),
            attestation_key_id: V3_ATTESTATION_KEY_ID.to_owned(),
            node_id: V3_ISSUER_NODE.to_owned(),
            gateway_instance_id: V3_GATEWAY_INSTANCE.to_owned(),
            revoked_at: now,
        };
        assert!(!gateway_certificate_matches_revocation(&cert, &mismatched));
        assert!(apply_gateway_certificate_revocation(&cert, &mismatched).is_err());

        // A matching revocation stamps revoked_at and the certificate then fails closed.
        let revocation = GatewayCertificateRevocation {
            cert_id: cert.cert_id.clone(),
            attestation_key_id: cert.attestation_key_id.clone(),
            node_id: cert.node_id.clone(),
            gateway_instance_id: cert.gateway_instance_id.clone(),
            revoked_at: now,
        };
        assert!(gateway_certificate_matches_revocation(&cert, &revocation));
        let revoked =
            apply_gateway_certificate_revocation(&cert, &revocation).map_err(|e| e.to_string())?;
        assert_eq!(revoked.revoked_at, Some(now));
        assert!(matches!(
            verify_gateway_issuer_certificate(
                &revoked,
                &root_pk,
                V3_ISSUER_NODE,
                V3_GATEWAY_INSTANCE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_certificate_renewal_binding() -> Result<(), String> {
        let now = 1_000_000;
        let request = v3_certificate_request(now, |_r| {})?;
        let previous = issue_gateway_issuer_certificate(
            &request,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-prev",
            now,
        )
        .map_err(|e| e.to_string())?;

        // A fresh cert id for the same gateway with a not-earlier not_after is a renewal.
        let renew_request = v3_certificate_request(now, |r| {
            r.not_before = now - 5;
            r.not_after = now + 7_200;
        })?;
        let next = issue_gateway_issuer_certificate(
            &renew_request,
            V3_ROOT_KEY_ID,
            V3_ROOT_SEED,
            "cert-next",
            now,
        )
        .map_err(|e| e.to_string())?;
        assert!(gateway_certificate_is_renewal_of(&previous, &next));

        // Same cert id is not a renewal.
        let mut same_id = next.clone();
        same_id.cert_id = previous.cert_id.clone();
        assert!(!gateway_certificate_is_renewal_of(&previous, &same_id));

        // A different node/instance is not a renewal.
        let mut other_node = next.clone();
        other_node.node_id = "node-z".to_owned();
        assert!(!gateway_certificate_is_renewal_of(&previous, &other_node));
        Ok(())
    }

    // ---- RQ-03-V3-T4 federated root trust snapshot tests ----

    const V3_ROOT_PREV_SEED: [u8; 32] = [0x55; 32];
    const V3_ROOT_PREV_KEY_ID: &str = "node-b#root-prev";

    fn v3_trust_snapshot(
        now: u64,
        apply: impl FnOnce(&mut FederatedIssuerTrustSnapshot),
    ) -> FederatedIssuerTrustSnapshot {
        let mut snapshot = FederatedIssuerTrustSnapshot {
            schema: FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: V3_ISSUER_NODE.to_owned(),
            generation: 5,
            pin_epoch: 3,
            trust_status: FederatedIssuerTrustStatus::Active,
            roots: vec![TrustedNodeRootKey {
                node_id: V3_ISSUER_NODE.to_owned(),
                key_id: V3_ROOT_KEY_ID.to_owned(),
                public_key: v3_pk(V3_ROOT_SEED),
                not_before: now - 100,
                not_after: now + 3_600,
                pin_epoch: 3,
                retired_at: None,
            }],
            revoked_cert_ids: BTreeSet::new(),
            hard_stale_at: now + 300,
        };
        apply(&mut snapshot);
        snapshot
    }

    #[test]
    fn relay_trust_snapshot_cache_update_and_current_happy_path() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        // Empty cache is fail-closed.
        assert!(cache.current(V3_ISSUER_NODE, now).is_err());

        cache
            .update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(5));
        let snapshot = cache.current(V3_ISSUER_NODE, now).map_err(|e| e.to_string())?;
        assert_eq!(snapshot.generation, 5);

        // A monotonically newer snapshot is accepted.
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 6;
                    s.pin_epoch = 4;
                }),
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(6));
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_cache_rejects_rollback_and_wrong_node() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 5;
                    s.pin_epoch = 3;
                }),
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;

        // Generation rollback.
        assert!(
            cache
                .update(
                    v3_trust_snapshot(now, |s| {
                        s.generation = 4;
                        s.pin_epoch = 3;
                    }),
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        // Pin epoch rollback.
        assert!(
            cache
                .update(
                    v3_trust_snapshot(now, |s| {
                        s.generation = 5;
                        s.pin_epoch = 2;
                    }),
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        // Different node id.
        assert!(
            cache
                .update(
                    v3_trust_snapshot(now, |s| s.node_id = "node-z".to_owned()),
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        // The cached snapshot is unchanged after every rejected update.
        assert_eq!(cache.generation(), Some(5));
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_cache_current_fail_closed_when_empty_or_stale() -> Result<(), String> {
        let now = 1_000_000;
        let empty = RelayTrustSnapshotCache::new();
        assert!(empty.current(V3_ISSUER_NODE, now).is_err());

        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        // Usable within the staleness window.
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        // Fail-closed past the hard staleness deadline (hard_stale_at = now + 300).
        assert!(cache.current(V3_ISSUER_NODE, now + 301).is_err());
        // An already-stale incoming snapshot is rejected on update.
        assert!(
            cache
                .update(
                    v3_trust_snapshot(now, |s| {
                        s.generation = 6;
                        s.hard_stale_at = now - 1;
                    }),
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_cache_clone_is_value_independent() -> Result<(), String> {
        // The cache has no interior mutability: sharing is by clone, so updates to one copy never
        // affect another.
        let now = 1_000_000;
        let mut base = RelayTrustSnapshotCache::new();
        base.update(v3_trust_snapshot(now, |_s| {}), V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        let mut cloned = base.clone();
        cloned
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 6;
                    s.pin_epoch = 4;
                }),
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(base.generation(), Some(5));
        assert_eq!(cloned.generation(), Some(6));
        Ok(())
    }

    const V3_PROVIDER_SEED: [u8; 32] = [0x66; 32];

    fn v3_signed_snapshot_envelope(
        now: u64,
        apply: impl FnOnce(&mut SignedFederatedIssuerTrustSnapshot),
    ) -> Result<SignedFederatedIssuerTrustSnapshot, String> {
        let mut envelope = SignedFederatedIssuerTrustSnapshot {
            schema: FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            snapshot: v3_trust_snapshot(now, |_s| {}),
            provider_signing_key_id: "node-b#trust-provider".to_owned(),
            provider_public_key: v3_pk(V3_PROVIDER_SEED),
            issued_at: now,
            expires_at: now + 300,
            signature: String::new(),
        };
        apply(&mut envelope);
        envelope.signature = v3_sign(
            &signed_federated_issuer_trust_snapshot_signing_bytes(&envelope)
                .map_err(|e| e.to_string())?,
            V3_PROVIDER_SEED,
        );
        Ok(envelope)
    }

    #[test]
    fn relay_trust_snapshot_envelope_valid_admits_to_cache() -> Result<(), String> {
        let now = 1_000_000;
        let provider_pk = v3_pk(V3_PROVIDER_SEED);
        let envelope = v3_signed_snapshot_envelope(now, |_e| {})?;
        verify_signed_federated_issuer_trust_snapshot(&envelope, &provider_pk, now)
            .map_err(|e| e.to_string())?;

        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update_from_signed(&envelope, &provider_pk, V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(5));
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_envelope_rejects_tamper() -> Result<(), String> {
        let now = 1_000_000;
        let provider_pk = v3_pk(V3_PROVIDER_SEED);
        // Tamper the inner snapshot after signing: the provider signature no longer verifies.
        let mut tampered = v3_signed_snapshot_envelope(now, |_e| {})?;
        tampered.snapshot.generation = 999;
        assert!(
            verify_signed_federated_issuer_trust_snapshot(&tampered, &provider_pk, now).is_err()
        );

        let mut cache = RelayTrustSnapshotCache::new();
        assert!(
            cache.update_from_signed(&tampered, &provider_pk, V3_ISSUER_NODE, now).is_err(),
            "a tampered envelope must never reach the cache"
        );
        assert_eq!(cache.generation(), None);
        Ok(())
    }

    // T23-A1a closure: a provider-signed non-Active snapshot must be admissible over the full signed
    // ingress path (update_from_signed), replacing a stale Active, yet fail requests closed; and a
    // wrong-provider signature over the same body must be rejected without mutating the cache.
    #[test]
    fn t23a1a_signed_suspended_admits_but_rejects_requests_and_forged_is_inert()
    -> Result<(), String> {
        let now = 1_000_000;
        let provider_pk = v3_pk(V3_PROVIDER_SEED);
        let mut cache = RelayTrustSnapshotCache::new();

        // G1 Active installs and authorizes over the signed path.
        let g1 = v3_signed_snapshot_envelope(now, |e| e.snapshot.generation = 1)?;
        cache
            .update_from_signed(&g1, &provider_pk, V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());

        // A provider-signed Suspended G2 is admitted (generation replaced to 2)...
        let g2 = v3_signed_snapshot_envelope(now, |e| {
            e.snapshot.generation = 2;
            e.snapshot.trust_status = FederatedIssuerTrustStatus::Suspended;
        })?;
        cache
            .update_from_signed(&g2, &provider_pk, V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(2));
        // ...but the read path is Active-only: requests fail closed; the stale Active is not retained.
        assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));

        // A wrong-provider signature over a would-be successor (still declaring the pinned provider
        // key) is rejected and leaves the installed Suspended G2 in force.
        let mut forged = v3_signed_snapshot_envelope(now, |e| {
            e.snapshot.generation = 3;
            e.snapshot.trust_status = FederatedIssuerTrustStatus::Suspended;
        })?;
        forged.signature = v3_sign(
            &signed_federated_issuer_trust_snapshot_signing_bytes(&forged)
                .map_err(|e| e.to_string())?,
            [0x99; 32],
        );
        assert!(cache.update_from_signed(&forged, &provider_pk, V3_ISSUER_NODE, now).is_err());
        assert_eq!(
            cache.generation(),
            Some(2),
            "wrong-provider envelope must not mutate the cache"
        );
        assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_envelope_rejects_wrong_root() -> Result<(), String> {
        let now = 1_000_000;
        let envelope = v3_signed_snapshot_envelope(now, |_e| {})?;

        // Expected provider key differs from the envelope's declared provider key.
        assert!(
            verify_signed_federated_issuer_trust_snapshot(&envelope, &v3_pk(V3_ROOT_SEED), now)
                .is_err()
        );

        // Envelope signed by a non-provider key (declared provider key kept, signature forged).
        let mut forged = v3_signed_snapshot_envelope(now, |_e| {})?;
        forged.signature = v3_sign(
            &signed_federated_issuer_trust_snapshot_signing_bytes(&forged)
                .map_err(|e| e.to_string())?,
            V3_ROOT_SEED,
        );
        assert!(
            verify_signed_federated_issuer_trust_snapshot(&forged, &v3_pk(V3_PROVIDER_SEED), now)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn relay_trust_snapshot_envelope_rejects_expired() -> Result<(), String> {
        let now = 1_000_000;
        let provider_pk = v3_pk(V3_PROVIDER_SEED);
        // Signature covers the (past) window, so this is a validly-signed but expired envelope.
        let expired = v3_signed_snapshot_envelope(now, |e| {
            e.issued_at = now - 600;
            e.expires_at = now;
        })?;
        assert!(matches!(
            verify_signed_federated_issuer_trust_snapshot(&expired, &provider_pk, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let mut cache = RelayTrustSnapshotCache::new();
        assert!(cache.update_from_signed(&expired, &provider_pk, V3_ISSUER_NODE, now).is_err());
        assert_eq!(cache.generation(), None);
        Ok(())
    }

    // Builds a Get token whose embedded certificate is signed by `root_seed` under `root_key_id`.
    fn v3_token_signed_by_root(
        now: u64,
        root_seed: [u8; 32],
        root_key_id: &str,
    ) -> Result<(RelayTokenV3, GatewayIssuerCertificate), String> {
        let grant = v3_signed_grant(now, vec![ObjectRelayCapability::Get])?;
        let binding = object_access_grant_binding_hash(&grant).map_err(|e| e.to_string())?;
        let mut token = v3_grant_token(now, ObjectRelayCapability::Get, binding)?;
        let mut cert = token.issuer_certificate.clone();
        cert.node_root_signing_key_id = root_key_id.to_owned();
        cert.node_root_signature = v3_sign(
            &gateway_issuer_certificate_signing_bytes(&cert).map_err(|e| e.to_string())?,
            root_seed,
        );
        token.issuer_certificate = cert.clone();
        v3_resign_token(&mut token)?;
        Ok((token, cert))
    }

    fn v3_previous_root(now: u64, retired_at: Option<u64>) -> TrustedNodeRootKey {
        TrustedNodeRootKey {
            node_id: V3_ISSUER_NODE.to_owned(),
            key_id: V3_ROOT_PREV_KEY_ID.to_owned(),
            public_key: v3_pk(V3_ROOT_PREV_SEED),
            not_before: now - 200,
            not_after: now + 3_600,
            pin_epoch: 2,
            retired_at,
        }
    }

    #[test]
    fn v3_trust_snapshot_active_current_root_accepts() -> Result<(), String> {
        let now = 1_000_000;
        let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;
        let snapshot = v3_trust_snapshot(now, |_s| {});
        verify_federated_issuer_trust_snapshot(&snapshot, V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &snapshot,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_trust_snapshot_previous_overlap_root_accepts() -> Result<(), String> {
        let now = 1_000_000;
        let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_PREV_SEED, V3_ROOT_PREV_KEY_ID)?;
        // Snapshot carries both current and previous (overlapping) roots.
        let snapshot = v3_trust_snapshot(now, |s| {
            s.roots.push(v3_previous_root(now, Some(now + 120)));
        });
        verify_relay_token_v3_with_trust_snapshot(
            &token,
            &cert,
            &snapshot,
            ObjectRelayCapability::Get,
            V3_AUDIENCE_NODE,
            now,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn v3_trust_snapshot_rejects_unknown_expired_retired_root() -> Result<(), String> {
        let now = 1_000_000;
        // Unknown signer key id: token signed by the previous root, snapshot has only the current.
        let (prev_token, prev_cert) =
            v3_token_signed_by_root(now, V3_ROOT_PREV_SEED, V3_ROOT_PREV_KEY_ID)?;
        let current_only = v3_trust_snapshot(now, |_s| {});
        assert!(matches!(
            verify_relay_token_v3_with_trust_snapshot(
                &prev_token,
                &prev_cert,
                &current_only,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;

        // Expired root: current root's window is in the past.
        let expired_root = v3_trust_snapshot(now, |s| {
            s.roots[0].not_before = now - 200;
            s.roots[0].not_after = now - 1;
        });
        assert!(matches!(
            verify_relay_token_v3_with_trust_snapshot(
                &token,
                &cert,
                &expired_root,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Retired root: retired_at is in the past.
        let retired_root = v3_trust_snapshot(now, |s| {
            s.roots[0].retired_at = Some(now - 1);
        });
        assert!(matches!(
            verify_relay_token_v3_with_trust_snapshot(
                &token,
                &cert,
                &retired_root,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_trust_snapshot_rejects_revoked_certificate() -> Result<(), String> {
        let now = 1_000_000;
        let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;
        let snapshot = v3_trust_snapshot(now, |s| {
            s.revoked_cert_ids.insert(V3_CERT_ID.to_owned());
        });
        assert!(matches!(
            verify_relay_token_v3_with_trust_snapshot(
                &token,
                &cert,
                &snapshot,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_trust_snapshot_rejects_stale_status_generation_and_identity() -> Result<(), String> {
        let now = 1_000_000;
        let (token, cert) = v3_token_signed_by_root(now, V3_ROOT_SEED, V3_ROOT_KEY_ID)?;

        // Past the hard staleness deadline.
        let stale = v3_trust_snapshot(now, |s| s.hard_stale_at = now - 1);
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&stale, V3_ISSUER_NODE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        let boundary = v3_trust_snapshot(now, |s| s.hard_stale_at = now);
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&boundary, V3_ISSUER_NODE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        assert!(matches!(
            verify_relay_token_v3_with_trust_snapshot(
                &token,
                &cert,
                &stale,
                ObjectRelayCapability::Get,
                V3_AUDIENCE_NODE,
                now
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        // Non-Active statuses fail closed (Migrated included).
        for status in [
            FederatedIssuerTrustStatus::Invited,
            FederatedIssuerTrustStatus::Suspended,
            FederatedIssuerTrustStatus::Revoked,
            FederatedIssuerTrustStatus::Migrated,
        ] {
            let snap = v3_trust_snapshot(now, |s| s.trust_status = status);
            assert!(
                matches!(
                    verify_federated_issuer_trust_snapshot(&snap, V3_ISSUER_NODE, now),
                    Err(NodeCoreError::Unauthorized(_))
                ),
                "status {status:?} must fail closed"
            );
        }

        // Zero generation and identity mismatch.
        let zero_gen = v3_trust_snapshot(now, |s| s.generation = 0);
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&zero_gen, V3_ISSUER_NODE, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        let good = v3_trust_snapshot(now, |_s| {});
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&good, "node-z", now),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Wrong schema / version.
        let bad_schema = v3_trust_snapshot(now, |s| s.schema = "wrong".to_owned());
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&bad_schema, V3_ISSUER_NODE, now),
            Err(NodeCoreError::ItestJson(_))
        ));
        let bad_version = v3_trust_snapshot(now, |s| s.version = 2);
        assert!(matches!(
            verify_federated_issuer_trust_snapshot(&bad_version, V3_ISSUER_NODE, now),
            Err(NodeCoreError::ItestJson(_))
        ));
        Ok(())
    }

    #[test]
    fn v3_trust_snapshot_successor_rollback_rejected() -> Result<(), String> {
        let now = 1_000_000;
        let previous = v3_trust_snapshot(now, |s| {
            s.generation = 5;
            s.pin_epoch = 3;
        });

        // Monotonic non-decreasing successor is accepted.
        let ok_next = v3_trust_snapshot(now, |s| {
            s.generation = 6;
            s.pin_epoch = 4;
        });
        verify_federated_issuer_trust_snapshot_successor(&previous, &ok_next)
            .map_err(|e| e.to_string())?;

        let same_epoch_changed = v3_trust_snapshot(now, |s| {
            s.generation = previous.generation;
            s.pin_epoch = previous.pin_epoch;
            s.hard_stale_at += 1;
        });
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_successor(&previous, &same_epoch_changed),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Generation rollback.
        let gen_rollback = v3_trust_snapshot(now, |s| {
            s.generation = 4;
            s.pin_epoch = 3;
        });
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_successor(&previous, &gen_rollback),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Pin epoch rollback.
        let pin_rollback = v3_trust_snapshot(now, |s| {
            s.generation = 5;
            s.pin_epoch = 2;
        });
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_successor(&previous, &pin_rollback),
            Err(NodeCoreError::Unauthorized(_))
        ));

        // Different node.
        let other_node = v3_trust_snapshot(now, |s| s.node_id = "node-z".to_owned());
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_successor(&previous, &other_node),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn trust_snapshot_cache_requires_valid_monotonic_state() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));

        cache
            .update(v3_trust_snapshot(now, |_snapshot| {}), V3_ISSUER_NODE, now)
            .map_err(|error| error.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());

        let rollback = v3_trust_snapshot(now, |snapshot| snapshot.generation = 4);
        assert!(matches!(
            cache.update(rollback, V3_ISSUER_NODE, now),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    // T23-A1a: snapshot admission (entering the cache) is separated from request authorization
    // (Active-only). A validly-signed non-Active snapshot is admissible so a node-status transition
    // propagates and replaces a stale Active; requests are then gated Active-only.
    #[test]
    fn t23a1a_admission_accepts_nonactive_but_authorization_rejects() -> Result<(), String> {
        let now = 1_000_000;
        for status in [
            FederatedIssuerTrustStatus::Suspended,
            FederatedIssuerTrustStatus::Revoked,
            FederatedIssuerTrustStatus::Invited,
            FederatedIssuerTrustStatus::Migrated,
        ] {
            let snap = v3_trust_snapshot(now, |s| s.trust_status = status);
            verify_federated_issuer_trust_snapshot_admission(&snap, V3_ISSUER_NODE, now)
                .map_err(|e| format!("admission must accept {status:?}: {e}"))?;
            assert!(
                matches!(
                    verify_federated_issuer_trust_snapshot(&snap, V3_ISSUER_NODE, now),
                    Err(NodeCoreError::Unauthorized(_))
                ),
                "authorization must reject {status:?}"
            );
        }
        // A hard-stale snapshot is inadmissible even though it is Active (cannot install or authorize).
        let stale = v3_trust_snapshot(now, |s| s.hard_stale_at = now);
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_admission(&stale, V3_ISSUER_NODE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        Ok(())
    }

    #[test]
    fn t23a1a_suspended_replaces_active_and_fails_requests_closed() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update(v3_trust_snapshot(now, |s| s.generation = 1), V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        // A validly-signed Suspended successor is admitted and advances the cached generation...
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 2;
                    s.trust_status = FederatedIssuerTrustStatus::Suspended;
                }),
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(2), "suspended snapshot must be installed");
        // ...but the stale Active is NOT retained: node-level suspension takes effect, requests 403.
        assert!(matches!(cache.current(V3_ISSUER_NODE, now), Err(NodeCoreError::Unauthorized(_))));
        // A later Active successor recovers the node status (generation advances again).
        cache
            .update(v3_trust_snapshot(now, |s| s.generation = 3), V3_ISSUER_NODE, now)
            .map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        Ok(())
    }

    #[test]
    fn t23a1a_successor_crl_must_not_shrink() -> Result<(), String> {
        let now = 1_000_000;
        let revoked =
            |ids: &[&str]| ids.iter().map(|id| (*id).to_owned()).collect::<BTreeSet<String>>();
        let previous = v3_trust_snapshot(now, |s| {
            s.generation = 5;
            s.revoked_cert_ids = revoked(&["cert-a"]);
        });
        // Adding revocations (superset) is a valid successor.
        let grows = v3_trust_snapshot(now, |s| {
            s.generation = 6;
            s.revoked_cert_ids = revoked(&["cert-a", "cert-b"]);
        });
        verify_federated_issuer_trust_snapshot_successor(&previous, &grows)
            .map_err(|e| e.to_string())?;
        // Dropping a revocation (even at a higher generation) is rejected — the CRL is monotonic.
        let shrinks = v3_trust_snapshot(now, |s| {
            s.generation = 7;
            s.revoked_cert_ids = revoked(&[]);
        });
        assert!(matches!(
            verify_federated_issuer_trust_snapshot_successor(&previous, &shrinks),
            Err(NodeCoreError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn t23a1a_rejected_successor_leaves_cache_unchanged() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update(
                v3_trust_snapshot(now, |s| {
                    s.generation = 5;
                    s.revoked_cert_ids = ["cert-a".to_owned()].into_iter().collect();
                }),
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(5));

        // generation rollback / CRL shrink / hard-stale / wrong-node — each rejected, cache unchanged.
        let attempts = [
            v3_trust_snapshot(now, |s| s.generation = 4),
            v3_trust_snapshot(now, |s| {
                s.generation = 6;
                s.revoked_cert_ids = BTreeSet::new();
            }),
            v3_trust_snapshot(now, |s| {
                s.generation = 6;
                s.hard_stale_at = now;
            }),
            v3_trust_snapshot(now, |s| {
                s.generation = 6;
                s.node_id = "node-z".to_owned();
            }),
        ];
        for attempt in attempts {
            assert!(cache.update(attempt, V3_ISSUER_NODE, now).is_err());
            assert_eq!(cache.generation(), Some(5), "rejected update must not mutate the cache");
        }
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        Ok(())
    }

    #[test]
    fn trust_snapshot_cache_rejects_stale_replacement_and_reads() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        cache
            .update(v3_trust_snapshot(now, |_snapshot| {}), V3_ISSUER_NODE, now)
            .map_err(|error| error.to_string())?;

        let stale = v3_trust_snapshot(now, |snapshot| snapshot.hard_stale_at = now);
        assert!(matches!(
            cache.update(stale, V3_ISSUER_NODE, now),
            Err(NodeCoreError::TtlExpired { .. })
        ));
        assert!(cache.current(V3_ISSUER_NODE, now + 301).is_err());
        Ok(())
    }

    fn signed_trust_snapshot_envelope(
        now: u64,
        seed: [u8; 32],
    ) -> Result<FederatedTrustSnapshotEnvelope, String> {
        let mut envelope = FederatedTrustSnapshotEnvelope {
            schema: FEDERATED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: OBJECT_RELAY_V3_PROOF_VERSION,
            snapshot: v3_trust_snapshot(now, |_snapshot| {}),
            signer_key_id: V3_ROOT_KEY_ID.to_owned(),
            signer_public_key: v3_pk(seed),
            issued_at: now - 1,
            expires_at: now + 300,
            signature: String::new(),
        };
        envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &federated_trust_snapshot_envelope_signing_bytes(&envelope)
                .map_err(|error| error.to_string())?,
            seed,
        );
        Ok(envelope)
    }

    #[test]
    fn trust_snapshot_envelope_accepts_valid_and_rejects_tamper_or_wrong_signer()
    -> Result<(), String> {
        let now = 1_000_000;
        let envelope = signed_trust_snapshot_envelope(now, V3_ROOT_SEED)?;
        verify_federated_trust_snapshot_envelope(
            &envelope,
            V3_ISSUER_NODE,
            V3_ROOT_KEY_ID,
            &v3_pk(V3_ROOT_SEED),
            now,
        )
        .map_err(|error| error.to_string())?;

        let mut tampered = envelope.clone();
        tampered.snapshot.generation += 1;
        assert!(
            verify_federated_trust_snapshot_envelope(
                &tampered,
                V3_ISSUER_NODE,
                V3_ROOT_KEY_ID,
                &v3_pk(V3_ROOT_SEED),
                now,
            )
            .is_err()
        );
        assert!(
            verify_federated_trust_snapshot_envelope(
                &envelope,
                V3_ISSUER_NODE,
                "wrong-key",
                &v3_pk(V3_ROOT_SEED),
                now,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn trust_snapshot_envelope_rejects_expired_or_wrong_root_signature() -> Result<(), String> {
        let now = 1_000_000;
        let mut expired = signed_trust_snapshot_envelope(now, V3_ROOT_SEED)?;
        expired.expires_at = now;
        assert!(matches!(
            verify_federated_trust_snapshot_envelope(
                &expired,
                V3_ISSUER_NODE,
                V3_ROOT_KEY_ID,
                &v3_pk(V3_ROOT_SEED),
                now,
            ),
            Err(NodeCoreError::TtlExpired { .. })
        ));

        let wrong_root = signed_trust_snapshot_envelope(now, V3_ROOT_PREV_SEED)?;
        assert!(
            verify_federated_trust_snapshot_envelope(
                &wrong_root,
                V3_ISSUER_NODE,
                V3_ROOT_KEY_ID,
                &v3_pk(V3_ROOT_SEED),
                now,
            )
            .is_err()
        );
        Ok(())
    }

    // ---- RQ-03-V3-T14-D: owner-session tombstone core ----

    fn t14d_tombstone_chunk(owner_public_key: String) -> RelayChunkEntry {
        RelayChunkEntry {
            chunk_id: V3_CHUNK.to_owned(),
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: V3_MANIFEST.to_owned(),
            chunk_index: 0,
            chunk_cipher_hash: "t14d-cipher".to_owned(),
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key,
            encrypted_chunk: b"t14d-ct".to_vec(),
            stored_at: 0,
            expires_at: 2_000_000,
            delete_after_ack: false,
            acked_by: BTreeSet::new(),
            status: RelayChunkStatus::Available,
        }
    }

    fn t14d_tombstone_request() -> OwnerSessionTombstoneRequest {
        OwnerSessionTombstoneRequest {
            object_id: V3_OBJECT.to_owned(),
            manifest_hash: Some(V3_MANIFEST.to_owned()),
            tombstone_hash: "t14d-ts-hash".to_owned(),
            source_event_id: "t14d-evt".to_owned(),
            signed_at: 999_000,
            expires_at: 1_000_100,
            owner_signing_key_id: V3_OWNER_ID.to_owned(),
            owner_public_key: v3_pk(V3_OWNER_SEED),
        }
    }

    #[test]
    fn owner_session_tombstone_applies_and_replay_is_zero_mutation() -> Result<(), String> {
        let now = 1_000_000;
        let mut state = RelayCacheState::new();
        state.put_chunk(t14d_tombstone_chunk(v3_pk(V3_OWNER_SEED)));

        // A missing owner binding fails closed.
        let mut missing = t14d_tombstone_request();
        missing.owner_public_key = String::new();
        assert!(state.apply_owner_session_tombstone(missing, now).is_err());

        // A valid owner-session tombstone marks the owned chunk and records the object tombstone.
        let mutation = state
            .apply_owner_session_tombstone(t14d_tombstone_request(), now)
            .map_err(|error| error.to_string())?;
        assert!(mutation.changed);
        assert_eq!(mutation.affected_chunks.len(), 1);
        assert_eq!(
            state.chunk_entry(V3_CHUNK).map(|chunk| chunk.status),
            Some(RelayChunkStatus::Tombstoned)
        );
        assert!(state.tombstone(V3_OBJECT).is_some());

        // A byte-identical replay is idempotent with zero mutation.
        let replay = state
            .apply_owner_session_tombstone(t14d_tombstone_request(), now)
            .map_err(|error| error.to_string())?;
        assert!(!replay.changed);
        assert!(replay.affected_chunks.is_empty());
        Ok(())
    }

    #[test]
    fn owner_session_tombstone_rejects_empty_and_cross_owner_scope() {
        let now = 1_000_000;

        // Empty scope: no stored chunk proves ownership -> fail closed, nothing recorded.
        let mut empty = RelayCacheState::new();
        assert!(empty.apply_owner_session_tombstone(t14d_tombstone_request(), now).is_err());
        assert!(empty.tombstone(V3_OBJECT).is_none());

        // Cross-owner: a chunk in scope owned by a different device fails the whole request closed,
        // leaving that chunk untouched.
        let mut cross = RelayCacheState::new();
        cross.put_chunk(t14d_tombstone_chunk(v3_pk(V3_REQUESTER_SEED)));
        assert!(cross.apply_owner_session_tombstone(t14d_tombstone_request(), now).is_err());
        assert_eq!(
            cross.chunk_entry(V3_CHUNK).map(|chunk| chunk.status),
            Some(RelayChunkStatus::Available)
        );
        assert!(cross.tombstone(V3_OBJECT).is_none());
    }

    // ---- T23-A2b2: provider keyring rotation + provider_epoch envelope ----

    const A2B2_OFFLINE_ROOT_SEED: [u8; 32] = [0x71; 32];
    const A2B2_K1_SEED: [u8; 32] = [0x72; 32];
    const A2B2_K2_SEED: [u8; 32] = [0x73; 32];
    const A2B2_WRONG_SEED: [u8; 32] = [0x74; 32];
    const A2B2_K1: &str = "prov-k1";
    const A2B2_K2: &str = "prov-k2";

    fn a2b2_entry(
        key_id: &str,
        seed: [u8; 32],
        now: u64,
        retired_at: Option<u64>,
        epoch: u64,
    ) -> ProviderKeyEntry {
        ProviderKeyEntry {
            key_id: key_id.to_owned(),
            public_key: v3_pk(seed),
            not_before: now - 100,
            not_after: now + 3_600,
            retired_at,
            authorized_provider_epoch: epoch,
        }
    }

    #[allow(clippy::expect_used)]
    fn a2b2_keyring(
        keyring_epoch: u64,
        keys: Vec<ProviderKeyEntry>,
        apply: impl FnOnce(&mut ProviderKeyring),
    ) -> ProviderKeyring {
        let mut keyring = ProviderKeyring {
            schema: PROVIDER_KEYRING_SCHEMA.to_owned(),
            version: PROVIDER_KEYRING_VERSION,
            issuer_node_id: V3_ISSUER_NODE.to_owned(),
            keyring_epoch,
            keys,
            keyring_signature: String::new(),
        };
        apply(&mut keyring);
        keyring.keyring_signature = v3_sign(
            &provider_keyring_signing_bytes(&keyring).expect("keyring canonical"),
            A2B2_OFFLINE_ROOT_SEED,
        );
        keyring
    }

    fn a2b2_validate(keyring: &ProviderKeyring) -> Result<ValidatedProviderKeyring, NodeCoreError> {
        verify_provider_keyring(keyring, &v3_pk(A2B2_OFFLINE_ROOT_SEED), V3_ISSUER_NODE)
    }

    #[allow(clippy::expect_used)]
    fn a2b2_envelope(
        now: u64,
        signer_key_id: &str,
        signer_seed: [u8; 32],
        provider_epoch: u64,
        apply: impl FnOnce(&mut ProviderSignedTrustSnapshot),
    ) -> ProviderSignedTrustSnapshot {
        let mut envelope = ProviderSignedTrustSnapshot {
            schema: PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
            version: PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
            snapshot: v3_trust_snapshot(now, |_s| {}),
            provider_signing_key_id: signer_key_id.to_owned(),
            provider_public_key: v3_pk(signer_seed),
            provider_epoch,
            issued_at: now,
            expires_at: now + 300,
            signature: String::new(),
        };
        apply(&mut envelope);
        envelope.signature = v3_sign(
            &provider_signed_trust_snapshot_signing_bytes(&envelope).expect("envelope canonical"),
            signer_seed,
        );
        envelope
    }

    #[test]
    fn a2b2_keyring_valid_selection_and_structural_rejections() -> Result<(), String> {
        let now = 1_000_000;
        let keyring = a2b2_keyring(
            2,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
            ],
            |_k| {},
        );
        let validated = a2b2_validate(&keyring).map_err(|e| e.to_string())?;
        assert_eq!(validated.keyring_epoch(), 2);
        assert_eq!(validated.select(A2B2_K1).map(|e| e.authorized_provider_epoch), Some(1));
        assert_eq!(validated.select(A2B2_K2).map(|e| e.authorized_provider_epoch), Some(2));
        assert!(validated.select("prov-unknown").is_none());

        // Wrong schema / version.
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
                |k| k.schema = "x".to_owned()
            ))
            .is_err()
        );
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
                |k| k.version = 99
            ))
            .is_err()
        );
        // Wrong issuer node.
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
                |k| k.issuer_node_id = "node-z".to_owned()
            ))
            .is_err()
        );
        // Empty keys.
        assert!(a2b2_validate(&a2b2_keyring(1, vec![], |_k| {})).is_err());
        // Duplicate key_id.
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![
                    a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                    a2b2_entry(A2B2_K1, A2B2_K2_SEED, now, None, 2)
                ],
                |_k| {}
            ))
            .is_err()
        );
        // Duplicate authorized_provider_epoch.
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![
                    a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                    a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 1)
                ],
                |_k| {}
            ))
            .is_err()
        );
        // Empty validity window.
        assert!(
            a2b2_validate(&a2b2_keyring(
                1,
                vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
                |k| {
                    k.keys[0].not_before = now;
                    k.keys[0].not_after = now;
                }
            ))
            .is_err()
        );
        // Forged offline-root signature (re-signed by a non-root key).
        let mut forged =
            a2b2_keyring(1, vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)], |_k| {});
        forged.keyring_signature = v3_sign(
            &provider_keyring_signing_bytes(&forged).map_err(|e| e.to_string())?,
            A2B2_WRONG_SEED,
        );
        assert!(a2b2_validate(&forged).is_err());
        Ok(())
    }

    #[test]
    fn a2b2_envelope_binding_and_rejections() -> Result<(), String> {
        let now = 1_000_000;
        let validated = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;

        // Valid K1/e1.
        let entry = verify_provider_signed_trust_snapshot(
            &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
            &validated,
            now,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(entry.key_id, A2B2_K1);

        // Unknown signer key id.
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, "prov-unknown", A2B2_K1_SEED, 1, |_e| {}),
                &validated,
                now
            )
            .is_err()
        );
        // Wrong provider_epoch (not the entry's authorized epoch).
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 2, |_e| {}),
                &validated,
                now
            )
            .is_err()
        );
        // provider_public_key mismatch (signed by K1 but declares K2's key).
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |e| e.provider_public_key =
                    v3_pk(A2B2_K2_SEED)),
                &validated,
                now
            )
            .is_err()
        );
        // Legacy v3 schema hard-rejected.
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |e| e.schema =
                    FEDERATED_ISSUER_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned()),
                &validated,
                now
            )
            .is_err()
        );
        // Forged signature (tamper a signed field after signing).
        let mut tampered = a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {});
        tampered.snapshot.generation += 1;
        assert!(verify_provider_signed_trust_snapshot(&tampered, &validated, now).is_err());

        // Retired key.
        let retired = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, Some(now - 1), 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &retired,
                now
            )
            .is_err()
        );
        // Not-yet-valid key.
        let future = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| {
                k.keys[0].not_before = now + 10_000;
                k.keys[0].not_after = now + 20_000;
            },
        ))
        .map_err(|e| e.to_string())?;
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &future,
                now
            )
            .is_err()
        );
        // Expired key.
        let expired = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |k| {
                k.keys[0].not_before = now - 20_000;
                k.keys[0].not_after = now - 10_000;
            },
        ))
        .map_err(|e| e.to_string())?;
        assert!(
            verify_provider_signed_trust_snapshot(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &expired,
                now
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn a2b2_cache_transition_and_seizure_rejected() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        // K1 stage: install K1/e1 gen5.
        let kr1 = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr1,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(5));
        assert_eq!(cache.provider_epoch_high_water(), 1);
        assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K1));

        // Stage K2 and switch to K2/e2 gen6 → provider-epoch high-water advances to 2.
        let kr2 = a2b2_validate(&a2b2_keyring(
            2,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
            ],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
                &kr2,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(6));
        assert_eq!(cache.provider_epoch_high_water(), 2);
        assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K2));

        // Seizure attempt 1: compromised K1 signs a HIGHER generation (7) but only its own epoch (1),
        // which is now below the high-water → rejected; cache stays exactly at gen6/e2/K2.
        assert!(
            cache
                .update_from_keyring_signed(
                    &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 7),
                    &kr2,
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        // Seizure attempt 2: compromised K1 forges provider_epoch=2 → not its authorized epoch → rejected.
        assert!(
            cache
                .update_from_keyring_signed(
                    &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 2, |s| s.snapshot.generation = 7),
                    &kr2,
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        assert_eq!(cache.generation(), Some(6));
        assert_eq!(cache.provider_epoch_high_water(), 2);
        assert_eq!(cache.accepted_signer_key_id(), Some(A2B2_K2));

        // Legitimate K2 continues to advance at its own epoch.
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 7),
                &kr2,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.generation(), Some(7));
        Ok(())
    }

    #[test]
    fn a2b2_keyring_epoch_rollback_rejected() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        let kr2 = a2b2_validate(&a2b2_keyring(
            2,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr2,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert_eq!(cache.keyring_epoch_high_water(), 2);
        // A keyring whose epoch regressed below the accepted high-water is rejected.
        let kr1 = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        assert!(
            cache
                .update_from_keyring_signed(
                    &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 6),
                    &kr1,
                    V3_ISSUER_NODE,
                    now
                )
                .is_err()
        );
        assert_eq!(cache.generation(), Some(5));
        Ok(())
    }

    #[test]
    fn a2b2_retire_current_signer_fails_closed_or_installs_successor() -> Result<(), String> {
        let now = 1_000_000;
        // Case A: retiring the current signer with no successor clears the cache (fail-closed).
        let mut cache = RelayTrustSnapshotCache::new();
        let kr1 = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr1,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        let kr_retire = a2b2_validate(&a2b2_keyring(
            2,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, Some(now - 1), 1),
                a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
            ],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache.reconcile_keyring(&kr_retire, now).map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_err(), "retired signer must fail closed");

        // Case B: a valid successor installed by K2 before the retirement reconcile is retained.
        let mut cache2 = RelayTrustSnapshotCache::new();
        cache2
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr1,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        cache2
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
                &kr_retire,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        cache2.reconcile_keyring(&kr_retire, now).map_err(|e| e.to_string())?;
        assert!(cache2.current(V3_ISSUER_NODE, now).is_ok(), "valid K2 successor must be retained");
        assert_eq!(cache2.generation(), Some(6));
        Ok(())
    }

    #[test]
    fn a2b2_provider_outage_keeps_valid_cache_and_restart_roundtrip() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        let kr = a2b2_validate(&a2b2_keyring(
            3,
            vec![a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K2, A2B2_K2_SEED, 2, |s| s.snapshot.generation = 6),
                &kr,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;

        // Provider outage = no new envelope; reconciling against the same (still-valid) keyring keeps
        // the cached snapshot authorizing.
        cache.reconcile_keyring(&kr, now).map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        assert_eq!(cache.generation(), Some(6));

        // Restart roundtrip: a cold cache that restores the persisted high-waters rejects a replayed
        // lower-epoch envelope, so a restart cannot be tricked into accepting a superseded epoch.
        let mut restarted = RelayTrustSnapshotCache::new();
        restarted.restore_high_water(Some(A2B2_K2.to_owned()), 2, 3, None);
        let kr_replay = a2b2_validate(&a2b2_keyring(
            2,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        assert!(
            restarted
                .update_from_keyring_signed(
                    &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                    &kr_replay,
                    V3_ISSUER_NODE,
                    now
                )
                .is_err(),
            "restart must honor persisted epoch high-water"
        );
        Ok(())
    }

    #[test]
    fn a2b2_same_keyring_epoch_content_replacement_rejected() -> Result<(), String> {
        let now = 1_000_000;
        let mut cache = RelayTrustSnapshotCache::new();
        // Adopt keyring epoch 1 = {K1}.
        let kr1 = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        cache
            .update_from_keyring_signed(
                &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |_e| {}),
                &kr1,
                V3_ISSUER_NODE,
                now,
            )
            .map_err(|e| e.to_string())?;
        let fingerprint = cache.keyring_fingerprint_high_water().map(str::to_owned);
        assert!(fingerprint.is_some());

        // A different keyring at the SAME epoch (adds K2) is validly offline-root-signed but is a
        // content replacement — rejected by both ingress paths, leaving the cache/fingerprint inert.
        let kr1_alt = a2b2_validate(&a2b2_keyring(
            1,
            vec![
                a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1),
                a2b2_entry(A2B2_K2, A2B2_K2_SEED, now, None, 2),
            ],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        assert_ne!(kr1_alt.fingerprint(), kr1.fingerprint());
        assert!(
            cache
                .update_from_keyring_signed(
                    &a2b2_envelope(now, A2B2_K1, A2B2_K1_SEED, 1, |s| s.snapshot.generation = 6),
                    &kr1_alt,
                    V3_ISSUER_NODE,
                    now
                )
                .is_err(),
            "same-epoch content replacement must be rejected on the update path"
        );
        assert!(
            cache.reconcile_keyring(&kr1_alt, now).is_err(),
            "same-epoch content replacement must be rejected on the reconcile path"
        );
        assert_eq!(cache.generation(), Some(5));
        assert_eq!(cache.keyring_fingerprint_high_water().map(str::to_owned), fingerprint);

        // Re-adopting the SAME keyring content (same fingerprint) is idempotent, not a replacement.
        let kr1_same = a2b2_validate(&a2b2_keyring(
            1,
            vec![a2b2_entry(A2B2_K1, A2B2_K1_SEED, now, None, 1)],
            |_k| {},
        ))
        .map_err(|e| e.to_string())?;
        assert_eq!(kr1_same.fingerprint(), kr1.fingerprint());
        cache.reconcile_keyring(&kr1_same, now).map_err(|e| e.to_string())?;
        assert!(cache.current(V3_ISSUER_NODE, now).is_ok());
        Ok(())
    }
}
