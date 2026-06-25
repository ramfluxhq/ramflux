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
    pub token_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_id: String,
    pub recipient_device_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub issuer_service: String,
    pub capabilities: Vec<ObjectRelayCapability>,
    pub delete_after_ack: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub mac: String,
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
    pub encrypted_chunk: Vec<u8>,
    pub stored_at: u64,
    pub expires_at: u64,
    pub delete_after_ack: bool,
    pub acked_by: BTreeSet<String>,
    pub status: RelayChunkStatus,
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
        let expires_at = clamp_relay_chunk_expires_at(now, frame.expires_at);
        let entry = RelayChunkEntry {
            chunk_id: frame.chunk_id,
            object_id: frame.object_id,
            manifest_hash: frame.manifest_hash,
            chunk_index: frame.chunk_index,
            chunk_cipher_hash: frame.chunk_cipher_hash,
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
        chunk.acked_by.insert(ack.recipient_device_hash);
        if chunk.delete_after_ack || ack.relay_token.delete_after_ack {
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
        let mut retained = tombstone;
        retained.expires_at =
            retained.expires_at.min(now.saturating_add(OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS));
        if retained.expires_at <= now {
            retained.expires_at = now.saturating_add(OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS);
        }
        let mut affected_chunks = Vec::new();
        for chunk in self.chunks_by_id.values_mut() {
            if chunk.object_id == retained.object_id
                && retained
                    .manifest_hash
                    .as_ref()
                    .is_none_or(|manifest| manifest == &chunk.manifest_hash)
            {
                chunk.status = RelayChunkStatus::Tombstoned;
                chunk.encrypted_chunk.clear();
                affected_chunks.push(chunk.clone());
            }
        }
        self.tombstones_by_object_id.insert(retained.object_id.clone(), retained.clone());
        Ok(ObjectRelayTombstoneMutation { tombstone: retained, affected_chunks })
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
/// Returns an error when the token MAC, capability, issuer or TTL is invalid.
pub fn validate_relay_token(
    token: &RelayToken,
    service_key: &[u8],
    capability: ObjectRelayCapability,
    now: u64,
) -> Result<(), NodeCoreError> {
    if token.issuer_service != "router" {
        return Err(NodeCoreError::ItestHttp("object relay token issuer rejected".to_owned()));
    }
    if !token.capabilities.contains(&capability) {
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

    fn test_relay_token(
        service_key: &[u8],
        capability: ObjectRelayCapability,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<RelayToken, String> {
        let mut token = RelayToken {
            token_id: format!("token_clock_skew_{capability:?}_{issued_at}"),
            object_id: "object_relay_clock_skew".to_owned(),
            manifest_hash: "manifest_relay_clock_skew".to_owned(),
            chunk_id: "chunk_relay_clock_skew".to_owned(),
            recipient_device_hash: "recipient_clock_skew".to_owned(),
            owner_signing_key_id: "owner_fixture_key".to_owned(),
            owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
            issuer_service: "router".to_owned(),
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
}
