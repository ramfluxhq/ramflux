// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stored chunk metadata, response models, and retention/expiry limits.

use super::{
    BTreeSet, Deserialize, ObjectPermissionEnvelope, RELAY_CHUNK_META_CHARGE_OVERHEAD, RelayToken,
    Serialize, env,
};

pub const OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS: u64 = 15 * 60;
pub const OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const OBJECT_RELAY_CHUNK_HARD_MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const OBJECT_RELAY_CHUNK_MAX_TTL_ENV: &str = "RAMFLUX_RELAY_OBJECT_MAX_TTL_SECONDS";
pub const OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
pub const OBJECT_RELAY_TOMBSTONE_MAX_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RelayChunkStatus {
    Available,
    Expired,
    AckedDeleted,
    Tombstoned,
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
    /// Immutable uploader binding, required in every persisted row.
    pub owner_signing_key_id: String,
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
}

/// The resident, payload-free view of a stored relay chunk (RELAY-MEM-01-A1). Every field of
/// [`RelayChunkEntry`] EXCEPT `encrypted_chunk` lives here. This is what the in-memory index holds;
/// the ciphertext stays in redb and is read through on demand for a GET. The explicit
/// `From<&RelayChunkEntry>` conversion is the only way meta is derived, so the payload can never leak
/// back into the resident state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelayChunkMeta {
    pub chunk_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_cipher_hash: String,
    pub owner_signing_key_id: String,
    pub owner_public_key: String,
    pub stored_at: u64,
    pub expires_at: u64,
    pub delete_after_ack: bool,
    pub acked_by: BTreeSet<String>,
    pub status: RelayChunkStatus,
}

impl From<&RelayChunkEntry> for RelayChunkMeta {
    fn from(entry: &RelayChunkEntry) -> Self {
        // Deliberately field-by-field (never `..entry`) so `encrypted_chunk` is dropped, not carried.
        Self {
            chunk_id: entry.chunk_id.clone(),
            object_id: entry.object_id.clone(),
            manifest_hash: entry.manifest_hash.clone(),
            chunk_index: entry.chunk_index,
            chunk_cipher_hash: entry.chunk_cipher_hash.clone(),
            owner_signing_key_id: entry.owner_signing_key_id.clone(),
            owner_public_key: entry.owner_public_key.clone(),
            stored_at: entry.stored_at,
            expires_at: entry.expires_at,
            delete_after_ack: entry.delete_after_ack,
            acked_by: entry.acked_by.clone(),
            status: entry.status,
        }
    }
}

impl RelayChunkMeta {
    /// Applies an already-authorized recipient ACK under the owner's stored deletion policy.
    #[must_use]
    pub fn acknowledged_by(&self, recipient: &str) -> Self {
        let mut updated = self.clone();
        updated.acked_by.insert(recipient.to_owned());
        if updated.delete_after_ack {
            updated.status = RelayChunkStatus::AckedDeleted;
        }
        updated
    }

    /// Returns `true` only when the chunk carries a non-empty immutable owner binding.
    #[must_use]
    pub fn has_owner_binding(&self) -> bool {
        !self.owner_signing_key_id.is_empty() && !self.owner_public_key.is_empty()
    }

    /// Returns `true` when the chunk's persisted original owner matches the token's owner. A chunk
    /// missing its owner binding (legacy record) never matches.
    #[must_use]
    pub(super) fn owner_matches_token(&self, token: &RelayToken) -> bool {
        self.has_owner_binding()
            && self.owner_signing_key_id == token.owner_signing_key_id
            && self.owner_public_key == token.owner_public_key
    }

    /// Rebuilds a full [`RelayChunkEntry`] carrying this metadata and the supplied payload. Used by
    /// the store read-through path to reconstruct the wire GET response after a redb point-read, and
    /// by the store commit path when persisting a payload-cleared (tombstoned/acked-deleted) row.
    #[must_use]
    pub(super) fn to_entry(&self, encrypted_chunk: Vec<u8>) -> RelayChunkEntry {
        RelayChunkEntry {
            chunk_id: self.chunk_id.clone(),
            object_id: self.object_id.clone(),
            manifest_hash: self.manifest_hash.clone(),
            chunk_index: self.chunk_index,
            chunk_cipher_hash: self.chunk_cipher_hash.clone(),
            owner_signing_key_id: self.owner_signing_key_id.clone(),
            owner_public_key: self.owner_public_key.clone(),
            encrypted_chunk,
            stored_at: self.stored_at,
            expires_at: self.expires_at,
            delete_after_ack: self.delete_after_ack,
            acked_by: self.acked_by.clone(),
            status: self.status,
        }
    }

    /// Byte-aware resident charge for this metadata: the serialized JSON length plus a conservative
    /// fixed overhead. Uses checked arithmetic; `None` on the (practically impossible) overflow.
    #[must_use]
    pub(super) fn resident_charge(&self) -> Option<u64> {
        let body = serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len());
        u64::try_from(body).ok()?.checked_add(RELAY_CHUNK_META_CHARGE_OVERHEAD)
    }

    /// Test accessor for the resident charge.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn resident_charge_for_test(&self) -> Option<u64> {
        self.resident_charge()
    }
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
pub(super) fn object_relay_chunk_max_ttl_seconds_from_env(value: Option<&str>) -> u64 {
    env::parse_value::<u64>(OBJECT_RELAY_CHUNK_MAX_TTL_ENV, value)
        .filter(|ttl| *ttl > 0)
        .unwrap_or(OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS)
        .min(OBJECT_RELAY_CHUNK_HARD_MAX_TTL_SECONDS)
}

#[cfg(test)]
mod retention_budget_tests {
    use super::*;
    #[test]
    fn configured_object_ttl_cannot_exceed_seven_days() {
        for value in ["604800", "604801", "18446744073709551615"] {
            assert_eq!(object_relay_chunk_max_ttl_seconds_from_env(Some(value)), 604_800);
        }
        for value in [None, Some("0"), Some("invalid")] {
            assert_eq!(
                object_relay_chunk_max_ttl_seconds_from_env(value),
                OBJECT_RELAY_CHUNK_MAX_TTL_SECONDS
            );
        }
        assert_eq!(object_relay_chunk_max_ttl_seconds_from_env(Some("60")), 60);
    }
}

#[cfg(test)]
mod format_guards {
    use std::collections::BTreeSet;
    #[test]
    fn persisted_chunk_requires_its_owner_binding() -> Result<(), Box<dyn std::error::Error>> {
        let entry = super::RelayChunkEntry {
            chunk_id: "chunk".into(),
            object_id: "object".into(),
            manifest_hash: "manifest".into(),
            chunk_index: 0,
            chunk_cipher_hash: "hash".into(),
            owner_signing_key_id: "owner".into(),
            owner_public_key: "key".into(),
            encrypted_chunk: vec![1],
            stored_at: 100,
            expires_at: 200,
            delete_after_ack: false,
            acked_by: BTreeSet::default(),
            status: super::RelayChunkStatus::Available,
        };
        let current = serde_json::to_value(entry)?;
        assert!(serde_json::from_value::<super::RelayChunkEntry>(current.clone()).is_ok());
        for field in ["owner_signing_key_id", "owner_public_key"] {
            let mut old = current.clone();
            old.as_object_mut().ok_or("chunk fixture object")?.remove(field);
            assert!(serde_json::from_value::<super::RelayChunkEntry>(old).is_err());
        }
        Ok(())
    }
}
