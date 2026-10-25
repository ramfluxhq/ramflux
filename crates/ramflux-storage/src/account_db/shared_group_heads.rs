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
        heads.push(Head { epoch: state.view().epoch, hash: state.snapshot().state_hash.clone() });
        if heads.len() > RETAINED_HEADS {
            heads.drain(..heads.len() - RETAINED_HEADS);
        }
        self.persist_actor_state(&key, &heads)
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
