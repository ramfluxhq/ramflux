// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable wake admission. One mapping is committed before ack or send and is never reminted.

use super::{GatewayRedbStore, NodeCoreError};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const WAKE_DEDUP: TableDefinition<&str, &[u8]> = TableDefinition::new("gateway_wake_dedup_v1");

pub(super) fn ensure_wake_dedup_table(db: &redb::Database) -> Result<(), NodeCoreError> {
    let tx = db.begin_write().map_err(redb_error)?;
    let table = tx.open_table(WAKE_DEDUP).map_err(redb_error)?;
    drop(table);
    tx.commit().map_err(redb_error)?;
    Ok(())
}
const MAX_ID_BYTES: usize = 512;

/// Closed terminal state of an admitted wake. Open is the only non-terminal value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeDedupTerminal {
    /// Admitted and still eligible to send.
    Open,
    /// A signed cancel or an accepted call end closed this wake.
    Cancelled,
    /// The original deadline passed.
    Expired,
    /// A newer wake replaced this one.
    Superseded,
}

/// Identity of one accepted target wake. The caller supplies authenticated values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WakeAdmitRequest {
    /// Authenticated source identity.
    pub source_identity: String,
    /// Source envelope id. It never reaches a provider.
    pub source_envelope_id: String,
    /// Authenticated target owner epoch. Zero is not invented by the caller.
    pub target_owner_epoch: u64,
    /// Target delivery id.
    pub target_delivery_id: String,
    /// Original absolute deadline, Unix seconds.
    pub deadline: u64,
    /// Immutable request digest.
    pub request_digest: String,
}

/// Stored result of one admission key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WakeDedupRecord {
    /// Opaque public wake id. Stable for the life of the key.
    pub wake_id: String,
    /// Original deadline. Replays do not move it.
    pub deadline: u64,
    /// Digest committed with the first admission.
    pub request_digest: String,
    /// Terminal state. A terminal row is never reopened.
    pub terminal: WakeDedupTerminal,
}

/// Whether this call inserted the row or returned the committed one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeAdmitOutcome {
    /// The mapping was absent and is now committed.
    Created(WakeDedupRecord),
    /// The same digest was already committed. The wake id is unchanged.
    Existing(WakeDedupRecord),
}

enum WakeAdmitDecision {
    Insert,
    Replay,
    Terminal,
    Conflict,
}

impl GatewayRedbStore {
    /// Commit a wake mapping, or return the existing row when the digest matches.
    ///
    /// A conflicting digest is rejected. A terminal row is returned and not reminted.
    ///
    /// # Errors
    /// Returns an error when an id is out of contract, the digest conflicts, randomness
    /// fails, or the commit fails. A failed commit leaves the previous row unchanged.
    pub fn admit_wake(
        &self,
        request: &WakeAdmitRequest,
    ) -> Result<WakeAdmitOutcome, NodeCoreError> {
        validate_admit(request)?;
        let key = dedup_key(request)?;
        let tx = self.db.begin_write().map_err(redb_error)?;
        let mut table = tx.open_table(WAKE_DEDUP).map_err(redb_error)?;
        if let Some(record) = load_record(&table, &key)? {
            match decide_wake_admit(Some(&record), &request.request_digest) {
                WakeAdmitDecision::Replay | WakeAdmitDecision::Terminal => {
                    return Ok(WakeAdmitOutcome::Existing(record));
                }
                WakeAdmitDecision::Conflict | WakeAdmitDecision::Insert => {
                    return Err(NodeCoreError::InvalidConfiguration(
                        "wake dedup conflict".to_owned(),
                    ));
                }
            }
        }
        let record = WakeDedupRecord {
            wake_id: mint_wake_id()?,
            deadline: request.deadline,
            request_digest: request.request_digest.clone(),
            terminal: WakeDedupTerminal::Open,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        table.insert(key.as_str(), bytes.as_slice()).map_err(redb_error)?;
        drop(table);
        tx.commit().map_err(redb_error)?;
        Ok(WakeAdmitOutcome::Created(record))
    }

    /// Read the committed mapping. A missing row is `Ok(None)`.
    ///
    /// # Errors
    /// Returns an error when an id is out of contract or the read fails.
    pub fn lookup_wake(
        &self,
        request: &WakeAdmitRequest,
    ) -> Result<Option<WakeDedupRecord>, NodeCoreError> {
        validate_key(request)?;
        let key = dedup_key(request)?;
        let tx = self.db.begin_read().map_err(redb_error)?;
        let table = tx.open_table(WAKE_DEDUP).map_err(redb_error)?;
        load_record(&table, &key)
    }

    /// Commit `wake_id` with the signed digest, or return the row already stored.
    ///
    /// The caller signs that exact id before this commit. A conflicting digest is rejected.
    ///
    /// # Errors
    /// Returns an error when an id is out of contract, the digest conflicts, or the commit fails.
    pub fn commit_signed_wake(
        &self,
        request: &WakeAdmitRequest,
        wake_id: &str,
    ) -> Result<WakeAdmitOutcome, NodeCoreError> {
        validate_admit(request)?;
        if !canonical_wake_id(wake_id) {
            return Err(NodeCoreError::InvalidConfiguration("wake dedup id".to_owned()));
        }
        let key = dedup_key(request)?;
        let tx = self.db.begin_write().map_err(redb_error)?;
        let mut table = tx.open_table(WAKE_DEDUP).map_err(redb_error)?;
        if let Some(record) = load_record(&table, &key)? {
            match decide_wake_admit(Some(&record), &request.request_digest) {
                WakeAdmitDecision::Replay | WakeAdmitDecision::Terminal => {
                    return Ok(WakeAdmitOutcome::Existing(record));
                }
                WakeAdmitDecision::Conflict | WakeAdmitDecision::Insert => {
                    return Err(NodeCoreError::InvalidConfiguration(
                        "wake dedup conflict".to_owned(),
                    ));
                }
            }
        }
        let record = WakeDedupRecord {
            wake_id: wake_id.to_owned(),
            deadline: request.deadline,
            request_digest: request.request_digest.clone(),
            terminal: WakeDedupTerminal::Open,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        table.insert(key.as_str(), bytes.as_slice()).map_err(redb_error)?;
        drop(table);
        tx.commit().map_err(redb_error)?;
        Ok(WakeAdmitOutcome::Created(record))
    }

    /// Move an open wake to a terminal state. A terminal row stays terminal.
    ///
    /// # Errors
    /// Returns an error when the row is absent, the commit fails, or the key is out of contract.
    pub fn terminate_wake(
        &self,
        request: &WakeAdmitRequest,
        terminal: WakeDedupTerminal,
    ) -> Result<WakeDedupRecord, NodeCoreError> {
        if matches!(terminal, WakeDedupTerminal::Open) {
            return Err(NodeCoreError::InvalidConfiguration("wake dedup terminal".to_owned()));
        }
        validate_admit(request)?;
        let key = dedup_key(request)?;
        let tx = self.db.begin_write().map_err(redb_error)?;
        let mut table = tx.open_table(WAKE_DEDUP).map_err(redb_error)?;
        let Some(mut record) = load_record(&table, &key)? else {
            return Err(NodeCoreError::InvalidConfiguration("wake dedup missing".to_owned()));
        };
        if record.request_digest != request.request_digest {
            return Err(NodeCoreError::InvalidConfiguration("wake dedup conflict".to_owned()));
        }
        if record.terminal == WakeDedupTerminal::Open {
            record.terminal = terminal;
            let bytes = serde_json::to_vec(&record)
                .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            table.insert(key.as_str(), bytes.as_slice()).map_err(redb_error)?;
        }
        drop(table);
        tx.commit().map_err(redb_error)?;
        Ok(record)
    }
}

fn decide_wake_admit(existing: Option<&WakeDedupRecord>, digest: &str) -> WakeAdmitDecision {
    let Some(record) = existing else {
        return WakeAdmitDecision::Insert;
    };
    if record.request_digest != digest {
        return WakeAdmitDecision::Conflict;
    }
    if record.terminal == WakeDedupTerminal::Open {
        WakeAdmitDecision::Replay
    } else {
        WakeAdmitDecision::Terminal
    }
}

fn mint_wake_id() -> Result<String, NodeCoreError> {
    let bytes = ramflux_crypto::random_32()
        .map_err(|_source| NodeCoreError::InvalidConfiguration("wake id rng".to_owned()))?;
    let prefix = bytes
        .get(..16)
        .ok_or_else(|| NodeCoreError::InvalidConfiguration("wake id rng".to_owned()))?;
    Ok(ramflux_protocol::encode_base64url(prefix))
}

fn validate_key(request: &WakeAdmitRequest) -> Result<(), NodeCoreError> {
    if valid_id(&request.source_identity)
        && valid_id(&request.source_envelope_id)
        && valid_id(&request.target_delivery_id)
    {
        Ok(())
    } else {
        Err(NodeCoreError::InvalidConfiguration("wake dedup id".to_owned()))
    }
}

fn validate_admit(request: &WakeAdmitRequest) -> Result<(), NodeCoreError> {
    validate_key(request)?;
    if valid_id(&request.request_digest) {
        Ok(())
    } else {
        Err(NodeCoreError::InvalidConfiguration("wake dedup id".to_owned()))
    }
}

fn canonical_wake_id(value: &str) -> bool {
    let Ok(decoded) = ramflux_protocol::decode_base64url(value) else {
        return false;
    };
    decoded.len() == 16 && ramflux_protocol::encode_base64url(&decoded) == value
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn dedup_key(request: &WakeAdmitRequest) -> Result<String, NodeCoreError> {
    let bytes = serde_json::to_vec(&(
        &request.source_identity,
        &request.source_envelope_id,
        request.target_owner_epoch,
        &request.target_delivery_id,
    ))
    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|_source| NodeCoreError::InvalidConfiguration("wake dedup key".to_owned()))
}

fn load_record<T>(table: &T, key: &str) -> Result<Option<WakeDedupRecord>, NodeCoreError>
where
    T: ReadableTable<&'static str, &'static [u8]>,
{
    match table.get(key).map_err(redb_error)? {
        Some(guard) => Ok(Some(decode_record(guard.value())?)),
        None => Ok(None),
    }
}

fn decode_record(bytes: &[u8]) -> Result<WakeDedupRecord, NodeCoreError> {
    serde_json::from_slice(bytes)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{WakeAdmitOutcome, WakeAdmitRequest, WakeDedupTerminal};
    use crate::GatewayRedbStore;

    fn request(delivery: &str, digest: &str) -> WakeAdmitRequest {
        WakeAdmitRequest {
            source_identity: "source-a".to_owned(),
            source_envelope_id: "envelope-1".to_owned(),
            target_owner_epoch: 4,
            target_delivery_id: delivery.to_owned(),
            deadline: 1_900,
            request_digest: digest.to_owned(),
        }
    }

    #[test]
    fn wake_dedup_mapping_survives_restart_and_never_remints() -> Result<(), crate::NodeCoreError> {
        let temp =
            tempfile::TempDir::new().map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
        let path = temp.path().join("gateway.redb");
        let created = {
            let store = GatewayRedbStore::open(&path)?;
            let first = store.admit_wake(&request("delivery-a", "digest-1"))?;
            let WakeAdmitOutcome::Created(record) = first else {
                return Err(crate::NodeCoreError::InvalidConfiguration(
                    "wake dedup created".into(),
                ));
            };
            let again = store.admit_wake(&request("delivery-a", "digest-1"))?;
            let WakeAdmitOutcome::Existing(existing) = again else {
                return Err(crate::NodeCoreError::InvalidConfiguration("wake dedup replay".into()));
            };
            assert_eq!(existing.wake_id, record.wake_id);
            assert_eq!(existing.deadline, 1_900);
            assert!(store.admit_wake(&request("delivery-a", "digest-2")).is_err());
            let other = store.admit_wake(&request("delivery-b", "digest-1"))?;
            let WakeAdmitOutcome::Created(other) = other else {
                return Err(crate::NodeCoreError::InvalidConfiguration("wake dedup other".into()));
            };
            assert_ne!(other.wake_id, record.wake_id);
            let closed = store
                .terminate_wake(&request("delivery-a", "digest-1"), WakeDedupTerminal::Cancelled)?;
            assert_eq!(closed.terminal, WakeDedupTerminal::Cancelled);
            let after = store.admit_wake(&request("delivery-a", "digest-1"))?;
            let WakeAdmitOutcome::Existing(after) = after else {
                return Err(crate::NodeCoreError::InvalidConfiguration(
                    "wake dedup terminal".into(),
                ));
            };
            assert_eq!(after.wake_id, record.wake_id);
            assert_eq!(after.terminal, WakeDedupTerminal::Cancelled);
            record.wake_id
        };
        let store = GatewayRedbStore::open(&path)?;
        let restored = store.admit_wake(&request("delivery-a", "digest-1"))?;
        let WakeAdmitOutcome::Existing(restored) = restored else {
            return Err(crate::NodeCoreError::InvalidConfiguration("wake dedup restart".into()));
        };
        assert_eq!(restored.wake_id, created);
        assert_eq!(restored.terminal, WakeDedupTerminal::Cancelled);
        Ok(())
    }

    #[test]
    fn wake_dedup_rejects_blank_identity() -> Result<(), crate::NodeCoreError> {
        let temp =
            tempfile::TempDir::new().map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
        let store = GatewayRedbStore::open(temp.path().join("gateway.redb"))?;
        let mut blank = request("delivery-a", "digest-1");
        blank.source_identity.clear();
        assert!(store.admit_wake(&blank).is_err());
        Ok(())
    }
}
