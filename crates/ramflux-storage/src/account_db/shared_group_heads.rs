// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Locally verified content scopes; old arbitrary heads never allocate receiver state.
use super::AccountDb;
use crate::StorageError;
use serde::{Deserialize, Serialize};
const RETAINED_HEADS: usize = 64;
#[derive(Deserialize, Serialize)]
struct Head {
    epoch: u64,
    hash: String,
    #[serde(default)]
    snapshot: Option<ramflux_protocol::group_state::GroupStateSnapshot>,
}
fn key(group: &str) -> String {
    format!("group-state/known-heads/{}", ramflux_protocol::encode_base64url(group))
}
impl AccountDb {
    pub(super) fn remember_shared_group_head(
        &self,
        state: &ramflux_crypto::VerifiedGroupState,
    ) -> Result<(), StorageError> {
        let key = key(&state.view().group_id);
        let mut heads: Vec<Head> = self.load_actor_state(&key)?.unwrap_or_default();
        heads.retain(|head| head.hash != state.snapshot().state_hash);
        heads.push(Head {
            epoch: state.view().epoch,
            hash: state.snapshot().state_hash.clone(),
            snapshot: Some(state.snapshot().clone()),
        });
        if heads.len() > RETAINED_HEADS {
            heads.drain(..heads.len() - RETAINED_HEADS);
        }
        self.persist_actor_state(&key, &heads)
    }
    /// Reverify the most recently pinned snapshot at a historical epoch.
    /// # Errors
    /// Returns storage or native signature errors; unknown/evicted snapshots are absent.
    pub fn shared_group_state_at_epoch(
        &self,
        group: &str,
        epoch: u64,
    ) -> Result<Option<ramflux_crypto::VerifiedGroupState>, StorageError> {
        let current = self.shared_group_state(group)?;
        if current.as_ref().is_some_and(|state| state.view().epoch == epoch) {
            return Ok(current);
        }
        let heads: Vec<Head> = self.load_actor_state(&key(group))?.unwrap_or_default();
        heads
            .into_iter()
            .rev()
            .find(|head| head.epoch == epoch)
            .and_then(|head| head.snapshot)
            .map(ramflux_crypto::verify_group_state_snapshot)
            .transpose()
            .map_err(Into::into)
    }

    /// Reverify one contiguous retained range, reading the history row only once.
    /// The lower epoch is exclusive; an absent epoch or range over 64 heads returns `None`.
    /// # Errors
    /// Returns storage/signature errors and refuses a snapshot whose binding differs from its index.
    pub fn shared_group_state_range(
        &self,
        group: &str,
        after: u64,
        through: u64,
    ) -> Result<Option<Vec<ramflux_crypto::VerifiedGroupState>>, StorageError> {
        let Some(count) = through.checked_sub(after) else {
            return Ok(None);
        };
        if count == 0 {
            return Ok(Some(Vec::new()));
        }
        if count > 64 {
            return Ok(None);
        }
        let heads: Vec<Head> = self.load_actor_state(&key(group))?.unwrap_or_default();
        let mut snapshots = std::collections::BTreeMap::new();
        for head in heads.into_iter().rev() {
            if head.epoch > after && head.epoch <= through {
                snapshots.entry(head.epoch).or_insert(head.snapshot);
            }
        }
        if let Some(current) = self.shared_group_state(group)?
            && current.view().epoch > after
            && current.view().epoch <= through
        {
            snapshots.insert(current.view().epoch, Some(current.snapshot().clone()));
        }
        let first = after.checked_add(1).ok_or(StorageError::GroupPermissionDenied)?;
        let mut verified = Vec::new();
        for epoch in first..=through {
            let Some(Some(snapshot)) = snapshots.remove(&epoch) else {
                return Ok(None);
            };
            let state = ramflux_crypto::verify_group_state_snapshot(snapshot)?;
            if state.view().group_id != group || state.view().epoch != epoch {
                return Err(StorageError::GroupPermissionDenied);
            }
            verified.push(state);
        }
        Ok(Some(verified))
    }
    /// # Errors
    /// Returns storage errors; only previously committed verified snapshots are known.
    pub fn knows_shared_group_head(
        &self,
        group: &str,
        epoch: u64,
        hash: &str,
    ) -> Result<bool, StorageError> {
        let heads: Vec<Head> = self.load_actor_state(&key(group))?.unwrap_or_default();
        Ok(heads.iter().any(|head| head.epoch == epoch && head.hash == hash))
    }
}
