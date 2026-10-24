// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, non-secret bookkeeping for current, archived and evicted device-pair states.
use super::super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Lists only control-record keys, without copying private state payloads.
    /// # Errors
    /// Returns SQLite errors.
    pub fn actor_state_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let mut query=self.connection.prepare("SELECT state_kind FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 ORDER BY state_kind")?;
        Ok(query
            .query_map(params![prefix], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Selects a pair's session ids without exporting its secret snapshots.
    /// # Errors
    /// Returns SQLite errors.
    pub fn pair_session_ids(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
        remote: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<String>, StorageError> {
        let mut query=self.connection.prepare("SELECT substr(state_kind,17) FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/session/%' AND json_extract(CAST(state_json AS TEXT),'$.local')=?1 AND json_extract(CAST(state_json AS TEXT),'$.remote')=?2")?;
        Ok(query
            .query_map(params![local.storage_key(), remote.storage_key()], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Recovers the original start of a legacy pending reset from retained journal evidence.
    /// # Errors
    /// Returns SQLite errors; missing evidence is explicit rather than renewing the lifetime.
    pub fn legacy_pair_reset_first_at(&self, pair: &str) -> Result<Option<i64>, StorageError> {
        let prefix = format!("pair-reset-attempt:dm-pair/reset-work/{pair}:");
        Ok(self.connection.query_row("SELECT max(at) FROM runtime_journal WHERE substr(source_key,1,length(?1))=?1 AND json_extract(CAST(body_json AS TEXT),'$.attempt')=1",params![prefix],|row|row.get(0))?)
    }
    /// Finds every peer owned by a local device, including work with no remaining live state.
    /// # Errors
    /// Returns SQLite errors.
    pub fn pair_peer_devices(
        &self,
        local: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<Vec<String>, StorageError> {
        let mut query=self.connection.prepare("SELECT DISTINCT remote FROM (SELECT json_extract(CAST(state_json AS TEXT),'$.remote') AS remote FROM runtime_actor_state WHERE (state_kind LIKE 'dm-pair/session/%' OR state_kind LIKE 'dm-pair/reset-work/%') AND json_extract(CAST(state_json AS TEXT),'$.local')=?1 UNION SELECT json_extract(CAST(state_json AS TEXT),'$.device_id') AS remote FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/%/manual' AND json_extract(CAST(state_json AS TEXT),'$.local_device_id')=?1) WHERE remote IS NOT NULL ORDER BY remote")?;
        Ok(query
            .query_map(params![local.storage_key()], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    /// Prunes flags for erased sessions and keeps at most eight recent tombstones per pair.
    /// Legacy tombstones lacking an owner share one bounded upgrade bucket.
    /// # Errors
    /// Returns SQLite errors.
    pub fn prune_pair_metadata(&self) -> Result<(), StorageError> {
        for kind in ["local", "confirmed", "settled", "reset"] {
            let prefix = format!("dm-pair/{kind}/");
            self.connection.execute("DELETE FROM runtime_actor_state WHERE substr(state_kind,1,length(?1))=?1 AND NOT EXISTS(SELECT 1 FROM runtime_actor_state live WHERE live.state_kind='dm-pair/session/'||substr(runtime_actor_state.state_kind,length(?1)+1))",params![prefix])?;
        }
        self.connection.execute_batch("DELETE FROM runtime_actor_state WHERE state_kind IN (SELECT state_kind FROM (SELECT state_kind,row_number() OVER(PARTITION BY coalesce(json_extract(CAST(state_json AS TEXT),'$.pair'),'legacy') ORDER BY coalesce(json_extract(CAST(state_json AS TEXT),'$.retired_at'),0) DESC,state_kind DESC) AS position FROM runtime_actor_state WHERE state_kind LIKE 'dm-pair/retired/%') WHERE position>8);")?;
        Ok(())
    }
    /// Rebinds recent eviction evidence to the pair's selected successor.
    /// # Errors
    /// Returns SQLite errors.
    pub fn supersede_pair_tombstones(
        &self,
        pair: &str,
        successor: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute("UPDATE runtime_actor_state SET state_json=CAST(json_set(CAST(state_json AS TEXT),'$.superseded_by',?2) AS BLOB) WHERE state_kind LIKE 'dm-pair/retired/%' AND json_extract(CAST(state_json AS TEXT),'$.pair')=?1",params![pair,successor])?;
        Ok(())
    }
}
