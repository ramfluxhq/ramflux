// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One current private mirror format for bounded SDK reads and restrictive backup reconciliation.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::contact_reach::{MAX_STATE_BYTES, StateRecord};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) mod bounded;
const KEY: &str = "directory/reach/state";
pub(super) const MAX_BYTES: usize = 2 * MAX_STATE_BYTES + 4096;

/// Historical local mirror data, never a verified authority or a renewed transport lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachSavedState {
    pub root: String,
    pub revision: u64,
    pub admission_revision: u64,
    pub home_head_hash: String,
    pub home_node_key: String,
    pub authority_head_hash: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub custodian_head_hash: Option<String>,
    pub state_hash: String,
    pub provenance_hash: String,
    #[serde(deserialize_with = "bounded::records")]
    pub records: Vec<StateRecord>,
    #[serde(deserialize_with = "bounded::restrictions")]
    pub restrictions: BTreeMap<String, StateRecord>,
    pub conflict: bool,
    pub positive_pending: bool,
}

#[cfg(test)]
mod tests;

impl AccountDb {
    /// Read a complete private mirror after checking its byte count in SQL.
    /// # Errors
    /// Refuses incomplete, unknown or oversized data before adopting any projection.
    pub fn reach_saved_state(&self) -> Result<Option<ReachSavedState>, StorageError> {
        self.load_bounded_actor_state(KEY, MAX_BYTES)
    }
    /// Persist only the current format in the caller's account transaction.
    /// This method conveys no signature verification or permission by itself.
    /// # Errors
    /// Refuses excess records/bytes and storage errors.
    pub fn persist_reach_saved_state(&self, saved: &ReachSavedState) -> Result<(), StorageError> {
        if saved.records.len() > 8192 || saved.restrictions.len() > 8192 {
            return Err(StorageError::SegmentResourceCapacity { limit: MAX_BYTES });
        }
        let bytes = ramflux_protocol::canonical_json_bytes(saved)?;
        if bytes.len() > MAX_BYTES {
            return Err(StorageError::SegmentResourceCapacity { limit: MAX_BYTES });
        }
        self.connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
            rusqlite::params![KEY, bytes],
        )?;
        Ok(())
    }
}
