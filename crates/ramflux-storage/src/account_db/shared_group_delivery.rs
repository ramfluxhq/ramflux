// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded group delivery selection prioritizes local removals independently of recovery capacity.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    /// Prunes bounded pages of expired removal boundaries and unreferenced immutable proofs.
    /// # Errors
    /// Returns database or stored payload decoding errors.
    pub fn prune_shared_group_boundaries(&self, now: i64) -> Result<(), StorageError> {
        self.write_transaction(|| {
            let mut query = self.connection.prepare("SELECT state_kind,state_json FROM runtime_actor_state WHERE state_kind GLOB 'group-state/boundaries/*' AND EXISTS(SELECT 1 FROM json_each(CAST(state_json AS TEXT)) WHERE json_extract(value,'$.expires_at')<=?1) ORDER BY state_kind LIMIT 4")?;
            let rows = query.query_map(params![now], |row| Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for (key, bytes) in rows {
                let mut boundaries: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
                boundaries.retain(|entry| entry["expires_at"].as_i64().is_some_and(|expires| expires > now));
                if boundaries.is_empty() { self.remove_actor_state(&key)?; }
                else { self.persist_actor_state(&key, &boundaries)?; }
            }
            self.connection.execute("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT proof.state_kind FROM runtime_actor_state proof WHERE proof.state_kind GLOB 'group-state/boundary-proof/*' AND NOT EXISTS(SELECT 1 FROM runtime_actor_state boundaries,json_each(CAST(boundaries.state_json AS TEXT)) entry WHERE boundaries.state_kind GLOB 'group-state/boundaries/*' AND proof.state_kind='group-state/boundary-proof/'||json_extract(entry.value,'$.snapshot.state_hash')) AND NOT EXISTS(SELECT 1 FROM runtime_actor_state pending,json_each(CAST(pending.state_json AS TEXT),'$.terminal') entry WHERE pending.state_kind GLOB 'group-state/send/*' AND proof.state_kind='group-state/boundary-proof/'||json_extract(entry.value,'$.snapshot.state_hash')) LIMIT 16)", [])?;
            Ok(())
        })
    }

    /// Counts recovery pointers without decoding their recipient progress or any state proofs.
    /// # Errors
    /// Returns database errors.
    pub fn shared_group_recovery_count(&self) -> Result<u64, StorageError> {
        Ok(self.connection.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind GLOB 'group-state/send/*' AND json_extract(CAST(state_json AS TEXT),'$.origin')='recovery'", [], |row| row.get(0))?)
    }
    /// Reads at most one due pointer, prioritizing removals, then local mutations over recovery.
    /// # Errors
    /// Returns database and typed payload decoding errors.
    pub fn next_shared_group_intent<T: serde::de::DeserializeOwned>(
        &self,
        after: &str,
        now: i64,
    ) -> Result<Option<T>, StorageError> {
        let bytes: Option<Vec<u8>> = self.connection.query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind GLOB 'group-state/send/*' AND json_extract(CAST(state_json AS TEXT),'$.next_at')<=?2 ORDER BY coalesce(json_extract(CAST(state_json AS TEXT),'$.priority'),0) DESC,(json_extract(CAST(state_json AS TEXT),'$.origin')='recovery'),state_kind<=?1,state_kind LIMIT 1", params![after,now], |row| row.get(0)).optional()?;
        bytes.map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into)).transpose()
    }
}
