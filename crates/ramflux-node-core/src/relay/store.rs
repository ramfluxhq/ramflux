// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relay redb persistence, hydration, and legacy snapshot migration.

use super::{
    BTreeMap, BTreeSet, Deserialize, NodeCoreError, ObjectRelayTombstone,
    ObjectRelayTombstoneMutation, Path, RELAY_CACHE_KEY, RELAY_CACHE_TABLE,
    RELAY_CHUNK_ENTRY_TABLE, RELAY_TOMBSTONE_TABLE, ReadableDatabase, RelayCacheState,
    RelayChunkEntry, RelayChunkMeta, RelayChunkStatus, RelayCommitOp, RelayCommitWriter,
    RelayExpiryMutation, Serialize, TableDefinition, env, fs,
};

use redb::ReadableTable;

pub struct RelayRedbStore {
    db: std::sync::Arc<redb::Database>,
    commit_writer: RelayCommitWriter,
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
        let db = std::sync::Arc::new(Self::create_database(path)?);
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

    /// Opens the redb database with the production page-cache cap. RELAY-MEM-03 (CTRL-096): redb 4.1
    /// defaults to a 1 GiB in-heap page cache, which the A0 differential + A0b/A0c cache probes proved
    /// is the sole owner of the relay's unbounded `RssAnon` growth under sustained unique-object
    /// writes (the 1 GiB cache never evicts, so anon climbs with the working set). Capping it to
    /// 16 MiB fully bounds the growth — K4 30-round median 0.92 / peak <=1.14 (vs 1 GiB's 2.96/3.00),
    /// `used_bytes` <=16 MiB with active eviction, durable across restart, and zero measured
    /// latency/throughput cost. 16 MiB is the production default (a named constant, not an env).
    const RELAY_REDB_CACHE_BYTES: usize = 16 * 1024 * 1024;

    #[cfg(not(feature = "itest-redb-cache-probe"))]
    fn create_database(path: &Path) -> Result<redb::Database, NodeCoreError> {
        let mut builder = redb::Database::builder();
        builder.set_cache_size(Self::RELAY_REDB_CACHE_BYTES);
        builder.create(path).map_err(|source| NodeCoreError::Redb(source.to_string()))
    }

    /// Probe build only: `RAMFLUX_RELAY_REDB_CACHE_BYTES` may override the 16 MiB production cap for a
    /// control-vs-candidate experiment. A missing env falls back to the SAME production 16 MiB default
    /// (never redb's 1 GiB); a present-but-invalid or zero value fails closed. The env is read ONLY
    /// under this feature — the default/production binary contains no such env and no override path.
    /// Resolves the probe cache cap from the (optional) env value. A missing env → the production
    /// 16 MiB default (never redb's 1 GiB); a present-but-invalid or zero value fails closed. Pure so
    /// the default/override/invalid behavior is unit-testable without process-global env mutation.
    #[cfg(feature = "itest-redb-cache-probe")]
    pub(crate) fn resolve_probe_cache_bytes(
        env_value: Option<&str>,
    ) -> Result<usize, NodeCoreError> {
        match env_value {
            Some(raw) => raw.parse::<usize>().ok().filter(|&bytes| bytes > 0).ok_or_else(|| {
                NodeCoreError::Redb(format!(
                    "RAMFLUX_RELAY_REDB_CACHE_BYTES must be a positive integer, got {raw:?}"
                ))
            }),
            None => Ok(Self::RELAY_REDB_CACHE_BYTES),
        }
    }

    #[cfg(feature = "itest-redb-cache-probe")]
    fn create_database(path: &Path) -> Result<redb::Database, NodeCoreError> {
        let cache_bytes = Self::resolve_probe_cache_bytes(
            std::env::var("RAMFLUX_RELAY_REDB_CACHE_BYTES").ok().as_deref(),
        )?;
        let mut builder = redb::Database::builder();
        builder.set_cache_size(cache_bytes);
        builder.create(path).map_err(|source| NodeCoreError::Redb(source.to_string()))
    }

    /// RELAY-MEM-03-A0b probe-only redb page-cache metrics (requires the `cache_metrics`-enabled
    /// probe feature). Absent from the production build — no production control-surface expansion.
    #[cfg(feature = "itest-redb-cache-probe")]
    #[must_use]
    pub fn cache_stats(&self) -> redb::CacheStats {
        use redb::ReadableDatabase as _;
        self.db.cache_stats()
    }

    /// # Errors
    /// Returns an error when serialization or storage fails.
    ///
    /// Writes a metadata-only snapshot of the resident state to the legacy `RELAY_CACHE_KEY` and
    /// clears the incremental tables. Ciphertext is NEVER persisted here (it is written through
    /// [`Self::record_relay_chunk_entry`]); `save_state` therefore only snapshots metadata and is
    /// used by tests, not the production write path.
    pub fn save_state(&self, state: &RelayCacheState) -> Result<(), NodeCoreError> {
        let snapshot = serde_json::to_vec(state)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(RELAY_CACHE_KEY, snapshot.as_slice())
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            replace_relay_table_values(&write_txn, RELAY_CHUNK_ENTRY_TABLE, &[])?;
            replace_relay_table_values(&write_txn, RELAY_TOMBSTONE_TABLE, &[])?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// Reads the full stored [`RelayChunkEntry`] (including ciphertext) for a single chunk id from
    /// the existing `RELAY_CHUNK_ENTRY_TABLE` full-entry JSON rows. This is the read-through point
    /// read that serves a GET payload without holding the resident state lock.
    ///
    /// # Errors
    /// Returns [`NodeCoreError::Redb`] on a redb read failure and
    /// [`NodeCoreError::SnapshotSerialization`] on a corrupt row (fail-closed; never yields an empty
    /// payload for a corrupt row).
    pub fn relay_chunk_entry(
        &self,
        chunk_id: &str,
    ) -> Result<Option<RelayChunkEntry>, NodeCoreError> {
        let read_txn =
            self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let table = read_txn
            .open_table(RELAY_CHUNK_ENTRY_TABLE)
            .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        let Some(value) =
            table.get(chunk_id).map_err(|source| NodeCoreError::Redb(source.to_string()))?
        else {
            return Ok(None);
        };
        let entry: RelayChunkEntry = serde_json::from_slice(value.value())
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        Ok(Some(entry))
    }

    /// # Errors
    /// Returns an error when hydration exceeds the resident metadata budget, or on redb/serde
    /// failure.
    ///
    /// Loads a metadata-only state (payload dropped) with the resident budget set to `max_bytes`.
    /// Hydration accumulates the resident charge and fails closed (no partial load) if it would
    /// exceed the budget.
    pub fn load_state(&self, max_bytes: u64) -> Result<Option<RelayCacheState>, NodeCoreError> {
        let (mut incremental, has_incremental_rows) = self.load_incremental_state()?;
        if has_incremental_rows {
            hydrate_relay_budget(&mut incremental, max_bytes)?;
            return Ok(Some(incremental));
        }
        let snapshot_bytes = {
            let read_txn =
                self.db.begin_read().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let table = read_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            let Some(snapshot) = table
                .get(RELAY_CACHE_KEY)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?
            else {
                return Ok(None);
            };
            snapshot.value().to_vec()
        };
        // A pre-incremental snapshot may embed full ciphertext (old format) or only metadata (the
        // current `save_state` format). Deserialize with defaulted payload so both parse, backfill
        // any recovered entries into the incremental table (reusing the existing schema) so a GET can
        // read through, and drop the legacy snapshot key.
        let compat: RelayCacheSnapshotCompat = serde_json::from_slice(&snapshot_bytes)
            .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
        self.migrate_snapshot_to_incremental(&compat)?;
        let mut state = RelayCacheState::default();
        for (chunk_id, chunk) in compat.chunks_by_id {
            state.chunks_by_id.insert(chunk_id, RelayChunkMeta::from(&chunk.into_entry()));
        }
        state.tombstones_by_object_id = compat.tombstones_by_object_id;
        hydrate_relay_budget(&mut state, max_bytes)?;
        Ok(Some(state))
    }

    /// One-time migration: writes the recovered full entries / tombstones into the incremental tables
    /// and removes the legacy snapshot key, so subsequent loads take the incremental path and GETs
    /// read through to the payload.
    fn migrate_snapshot_to_incremental(
        &self,
        compat: &RelayCacheSnapshotCompat,
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut chunk_table = write_txn
                .open_table(RELAY_CHUNK_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for chunk in compat.chunks_by_id.values() {
                let entry = chunk.clone().into_entry();
                let entry_bytes = serialize_relay_value(&entry)?;
                chunk_table
                    .insert(entry.chunk_id.as_str(), entry_bytes.as_slice())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            let mut tombstone_table = write_txn
                .open_table(RELAY_TOMBSTONE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            for tombstone in compat.tombstones_by_object_id.values() {
                let bytes = serialize_relay_value(tombstone)?;
                tombstone_table
                    .insert(tombstone.object_id.as_str(), bytes.as_slice())
                    .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            }
            remove_relay_legacy_snapshot(&write_txn)?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn put_chunk(&self, entry: &RelayChunkEntry) -> Result<(), NodeCoreError> {
        self.record_relay_chunk_entry(entry)
    }

    /// Test-only: writes raw bytes into `RELAY_CHUNK_ENTRY_TABLE` so a test can inject a corrupt
    /// full-entry row and exercise the fail-closed read-through error path.
    #[cfg(test)]
    pub(crate) fn write_raw_chunk_row(
        &self,
        chunk_id: &str,
        bytes: &[u8],
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut table = write_txn
                .open_table(RELAY_CHUNK_ENTRY_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            table
                .insert(chunk_id, bytes)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// Test-only: writes raw legacy-snapshot bytes to `RELAY_CACHE_KEY` and clears the incremental
    /// tables, so tests can craft a pre-incremental (full-entry, payload-bearing) snapshot and verify
    /// the load-time backfill/read-through compatibility.
    #[cfg(test)]
    pub(crate) fn save_legacy_snapshot_bytes(
        &self,
        snapshot_bytes: &[u8],
    ) -> Result<(), NodeCoreError> {
        let write_txn =
            self.db.begin_write().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        {
            let mut legacy_table = write_txn
                .open_table(RELAY_CACHE_TABLE)
                .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
            legacy_table
                .insert(RELAY_CACHE_KEY, snapshot_bytes)
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
                // Read the existing full-entry JSON row and immediately drop the payload: only the
                // metadata becomes resident; the ciphertext stays in redb for read-through.
                let chunk: RelayChunkEntry = serde_json::from_slice(value.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
                state.chunks_by_id.insert(chunk.chunk_id.clone(), RelayChunkMeta::from(&chunk));
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

pub(super) fn serialize_relay_value<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

/// Sets the resident budget on a freshly loaded state and recomputes the resident charge, failing
/// closed (no partial load) when hydration would exceed the budget.
pub(super) fn hydrate_relay_budget(
    state: &mut RelayCacheState,
    max_bytes: u64,
) -> Result<(), NodeCoreError> {
    state.rehydrate_budget(max_bytes).map_err(|error| NodeCoreError::ItestHttp(error.to_string()))
}

/// Deserialization-compat view of a pre-incremental `RELAY_CACHE_KEY` snapshot. Both the old
/// full-entry format and the current metadata-only format parse (ciphertext defaults to empty).
#[derive(Deserialize)]
pub(super) struct RelayCacheSnapshotCompat {
    #[serde(default)]
    chunks_by_id: BTreeMap<String, RelayChunkEntryCompat>,
    #[serde(default)]
    tombstones_by_object_id: BTreeMap<String, ObjectRelayTombstone>,
}

#[derive(Clone, Deserialize)]
pub(super) struct RelayChunkEntryCompat {
    chunk_id: String,
    object_id: String,
    manifest_hash: String,
    chunk_index: u32,
    chunk_cipher_hash: String,
    #[serde(default)]
    owner_signing_key_id: String,
    #[serde(default)]
    owner_public_key: String,
    #[serde(default)]
    encrypted_chunk: Vec<u8>,
    stored_at: u64,
    expires_at: u64,
    delete_after_ack: bool,
    acked_by: BTreeSet<String>,
    status: RelayChunkStatus,
}

impl RelayChunkEntryCompat {
    fn into_entry(self) -> RelayChunkEntry {
        RelayChunkEntry {
            chunk_id: self.chunk_id,
            object_id: self.object_id,
            manifest_hash: self.manifest_hash,
            chunk_index: self.chunk_index,
            chunk_cipher_hash: self.chunk_cipher_hash,
            owner_signing_key_id: self.owner_signing_key_id,
            owner_public_key: self.owner_public_key,
            encrypted_chunk: self.encrypted_chunk,
            stored_at: self.stored_at,
            expires_at: self.expires_at,
            delete_after_ack: self.delete_after_ack,
            acked_by: self.acked_by,
            status: self.status,
        }
    }
}

pub(super) fn replace_relay_table_values(
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

pub(super) fn remove_relay_legacy_snapshot(
    write_txn: &redb::WriteTransaction,
) -> Result<(), NodeCoreError> {
    let mut table = write_txn
        .open_table(RELAY_CACHE_TABLE)
        .map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    let _removed =
        table.remove(RELAY_CACHE_KEY).map_err(|source| NodeCoreError::Redb(source.to_string()))?;
    Ok(())
}
#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
