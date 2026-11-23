// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded inactive public bytes. Hints never authorize a send, a floor change or publication.
use super::{AccountDb, username_directory::UsernameStorageError};
use crate::StorageError;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code, Wire};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

pub(super) const INACTIVE_PREFIX: &str = "username/inactive/";
const INACTIVE_UPPER: &str = "username/inactive0";
const MAX_CANDIDATES: usize = 8;
const MAX_BYTES: usize = 131_072;
type Result<T> = std::result::Result<T, UsernameStorageError>;

/// Public signed intent bytes, including those whose delivery outcome was never observed.
/// Restoring this type does not authenticate it: live recovery verifies the actual native master
/// and an exact fresh global tuple, and never submits these hints as new mutations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameRecoveryCandidate {
    pub center: w::NativeDirectoryPin,
    pub operation: w::UsernameOperation,
    pub profile: w::SignedIdentityProfileV2,
}
impl UsernameRecoveryCandidate {
    /// # Errors
    /// Refuses malformed, oversized, mismatched or avatar-bearing inactive bytes.
    pub fn validate_shape(&self) -> Result<()> {
        self.center.validate().map_err(|_| refused(Code::DirectoryUnavailable))?;
        self.operation.validate().map_err(|_| refused(Code::InvalidProfile))?;
        self.profile.validate().map_err(|_| refused(Code::InvalidProfile))?;
        if self.profile.body.avatar.is_some() {
            return Err(refused(Code::InvalidAvatar));
        }
        if self.operation.body.principal_commitment != self.profile.body.principal_commitment {
            return Err(refused(Code::OwnershipMismatch));
        }
        if self.operation.body.profile.version != 2
            || self.operation.body.profile.epoch != self.profile.body.epoch
            || self.operation.body.profile.hash.as_ref()
                != Some(
                    &ramflux_crypto::username_directory::profile_hash_v2(&self.profile)
                        .map_err(|_| refused(Code::InvalidProfile))?,
                )
        {
            return Err(refused(Code::InvalidProfile));
        }
        if serde_json::to_vec(self).map_err(StorageError::from)?.len() > 16_384 {
            return Err(refused(Code::Capacity));
        }
        Ok(())
    }
    #[must_use]
    pub fn root(&self) -> &str {
        &self.operation.body.principal_commitment
    }
}
fn refused(code: Code) -> UsernameStorageError {
    UsernameStorageError::Refused(code)
}

fn book(db: &Connection) -> Result<Vec<UsernameRecoveryCandidate>> {
    let (keys, bytes): (u64,u64) = db.query_row(
        "SELECT count(*),coalesce(sum(length(state_json)),0) FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2",
        params![INACTIVE_PREFIX,INACTIVE_UPPER], |row| Ok((row.get(0)?,row.get(1)?))).map_err(StorageError::from)?;
    if keys > 8 || bytes > 131_072 {
        return Err(refused(Code::Capacity));
    }
    let mut statement = db.prepare("SELECT CASE WHEN length(state_kind)<=128 THEN state_kind END,state_json FROM main.runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2 ORDER BY state_kind LIMIT 9").map_err(StorageError::from)?;
    let rows = statement
        .query_map(params![INACTIVE_PREFIX, INACTIVE_UPPER], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(StorageError::from)?;
    let mut result = Vec::new();
    for row in rows {
        let (key, bytes) = row.map_err(StorageError::from)?;
        let key = key.ok_or_else(|| refused(Code::Capacity))?;
        let root =
            key.strip_prefix(INACTIVE_PREFIX).ok_or_else(|| refused(Code::OwnershipMismatch))?;
        let candidates = decode_candidates(&bytes)?;
        for candidate in candidates {
            if candidate.root() != root {
                return Err(refused(Code::OwnershipMismatch));
            }
            if result.len() >= MAX_CANDIDATES {
                return Err(refused(Code::Capacity));
            }
            result.push(candidate);
        }
    }
    Ok(result)
}
pub(super) fn decode_candidates(bytes: &[u8]) -> Result<Vec<UsernameRecoveryCandidate>> {
    if bytes.len() > MAX_BYTES {
        return Err(refused(Code::Capacity));
    }
    let candidates: Vec<UsernameRecoveryCandidate> =
        serde_json::from_slice(bytes).map_err(StorageError::from)?;
    if candidates.is_empty() || candidates.len() > MAX_CANDIDATES {
        return Err(refused(Code::Capacity));
    }
    for candidate in &candidates {
        candidate.validate_shape()?;
    }
    Ok(candidates)
}

/// Caller owns the existing account/restore transaction. No live-intent row is written here.
pub(super) fn retain(db: &Connection, incoming: &[UsernameRecoveryCandidate]) -> Result<()> {
    if incoming.len() > MAX_CANDIDATES {
        return Err(refused(Code::Capacity));
    }
    let mut candidates = book(db)?;
    for candidate in incoming {
        candidate.validate_shape()?;
        if let Some(old) = candidates
            .iter()
            .find(|old| old.operation.body.operation_id == candidate.operation.body.operation_id)
        {
            if old != candidate {
                return Err(refused(Code::ProfileEquivocation));
            }
        } else {
            if candidates.len() >= MAX_CANDIDATES {
                return Err(refused(Code::Capacity));
            }
            candidates.push(candidate.clone());
        }
    }
    let mut roots = std::collections::BTreeMap::<String, Vec<&UsernameRecoveryCandidate>>::new();
    for candidate in &candidates {
        roots.entry(candidate.root().into()).or_default().push(candidate);
    }
    let mut bytes = Vec::new();
    let mut total = 0_usize;
    for (root, rows) in roots {
        let encoded = serde_json::to_vec(&rows).map_err(StorageError::from)?;
        total = total.checked_add(encoded.len()).ok_or_else(|| refused(Code::Capacity))?;
        if total > MAX_BYTES {
            return Err(refused(Code::Capacity));
        }
        bytes.push((format!("{INACTIVE_PREFIX}{root}"), encoded));
    }
    for (key, bytes) in bytes {
        db.execute("INSERT INTO main.runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",params![key,bytes]).map_err(StorageError::from)?;
    }
    Ok(())
}
impl AccountDb {
    /// # Errors
    /// Refuses malformed inactive hints, changed IDs, capacity and storage failures.
    pub fn retain_username_candidate(&self, candidate: &UsernameRecoveryCandidate) -> Result<()> {
        let candidate = candidate.clone();
        self.join_write(|| {
            self.connection
                .call(move |db| Ok(retain(db, std::slice::from_ref(&candidate))))
                .map_err(StorageError::from)?
        })
    }
    /// # Errors
    /// Refuses corrupt, oversized or mismatched inactive metadata.
    pub fn username_recovery_candidates(
        &self,
        root: &str,
    ) -> Result<Vec<UsernameRecoveryCandidate>> {
        Ok(self
            .connection
            .call(|db| Ok(book(db)))
            .map_err(StorageError::from)??
            .into_iter()
            .filter(|candidate| candidate.root() == root)
            .collect())
    }
}
