// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current row-based relay persistence and bounded metadata hydration.

use super::{
    NodeCoreError, ObjectRelayTombstone, ObjectRelayTombstoneMutation, Path, RELAY_CACHE_KEY,
    RELAY_CACHE_TABLE, RELAY_CHUNK_ENTRY_TABLE, RELAY_TOMBSTONE_TABLE, ReadableDatabase,
    RelayCacheState, RelayChunkEntry, RelayChunkMeta, RelayCommitOp, RelayCommitWriter,
    RelayExpiryMutation, Serialize, fs,
};
#[cfg(test)]
use redb::TableDefinition;

use redb::ReadableTable;

pub struct RelayRedbStore {
    db: std::sync::Arc<redb::Database>,
    commit_writer: RelayCommitWriter,
}

impl RelayRedbStore {
    /// Opens a dormant streaming backend on this relay's authoritative metadata.
    /// # Errors
    /// Refuses inaccessible or unsafe private staging roots.
    pub fn local_attachment_backend(
        &self,
        namespace: [u8; 32],
        root: impl AsRef<Path>,
    ) -> Result<
        super::attachment::backend::LocalAttachmentBackend,
        super::attachment::backend::BackendError,
    > {
        super::attachment::backend::LocalAttachmentBackend::open(
            std::sync::Arc::clone(&self.db),
            namespace,
            root.as_ref(),
        )
    }

    /// Opens dormant native attachment accounting on the existing relay database.
    /// # Errors
    /// Refuses invalid operator policy. No serving path is activated.
    pub fn attachment_ledger(
        &self,
        policy: super::AttachmentPolicy,
    ) -> Result<super::AttachmentLedger, super::AttachmentLedgerError> {
        super::AttachmentLedger::new(std::sync::Arc::clone(&self.db), policy)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        Self::open_at(path, crate::now_unix_seconds())
    }
    // Trusted startup time. Keeping the clock explicit permits deterministic
    // restart tests without changing the public store-open API.
    pub(crate) fn open_at(path: impl AsRef<Path>, replay_now: u64) -> Result<Self, NodeCoreError> {
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
        reject_retired_snapshot(&db)?;
        validate_chunk_owners(&db)?;
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
        super::attachment::install(&write_txn, replay_now)?;
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
            crate::environment::var("RAMFLUX_RELAY_REDB_CACHE_BYTES").ok().as_deref(),
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

    /// Test fixtures persist only the current row format, never a cache snapshot.
    #[cfg(test)]
    pub(crate) fn save_state(&self, state: &RelayCacheState) -> Result<(), NodeCoreError> {
        let chunks = state
            .chunks_by_id
            .iter()
            .map(|(key, meta)| {
                Ok((key.clone(), serialize_relay_value(&meta.to_entry(Vec::new()))?))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let tombstones = state
            .tombstones_by_object_id
            .iter()
            .map(|(key, value)| Ok((key.clone(), serialize_relay_value(value)?)))
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let write = self.db.begin_write().map_err(redb_error)?;
        replace_relay_table_values(&write, RELAY_CHUNK_ENTRY_TABLE, &chunks)?;
        replace_relay_table_values(&write, RELAY_TOMBSTONE_TABLE, &tombstones)?;
        write.commit().map_err(redb_error)
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
        if !entry.has_owner_binding() {
            return Err(NodeCoreError::UnsupportedPersistedFormat("relay chunk owner binding"));
        }
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
        reject_retired_snapshot(&self.db)?;
        let (mut state, has_rows) = self.load_incremental_state()?;
        if !has_rows {
            return Ok(None);
        }
        hydrate_relay_budget(&mut state, max_bytes)?;
        Ok(Some(state))
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
    /// the load-time typed refusal at reopen.
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
        }
        write_txn.commit().map_err(|source| NodeCoreError::Redb(source.to_string()))?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the chunk entry cannot be durably recorded.
    pub fn record_relay_chunk_entry(&self, entry: &RelayChunkEntry) -> Result<(), NodeCoreError> {
        if !entry.has_owner_binding() {
            return Err(NodeCoreError::UnsupportedPersistedFormat("relay chunk owner binding"));
        }
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
                if !chunk.has_owner_binding() {
                    return Err(NodeCoreError::UnsupportedPersistedFormat(
                        "relay chunk owner binding",
                    ));
                }
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

fn validate_chunk_owners(db: &redb::Database) -> Result<(), NodeCoreError> {
    let read = db.begin_read().map_err(redb_error)?;
    let table = match read.open_table(RELAY_CHUNK_ENTRY_TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(source) => return Err(redb_error(source)),
    };
    for row in table.iter().map_err(redb_error)? {
        let (_, bytes) = row.map_err(redb_error)?;
        let chunk: RelayChunkEntry = serde_json::from_slice(bytes.value()).map_err(redb_error)?;
        if !chunk.has_owner_binding() {
            return Err(NodeCoreError::UnsupportedPersistedFormat("relay chunk owner binding"));
        }
    }
    Ok(())
}

fn reject_retired_snapshot(db: &redb::Database) -> Result<(), NodeCoreError> {
    let read = db.begin_read().map_err(redb_error)?;
    match read.open_table(RELAY_CACHE_TABLE) {
        Ok(table) => {
            if table.get(RELAY_CACHE_KEY).map_err(redb_error)?.is_some() {
                return Err(NodeCoreError::UnsupportedPersistedFormat("relay cache snapshot"));
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(error) => return Err(redb_error(error)),
    }
    Ok(())
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

#[cfg(test)]
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

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;

#[cfg(test)]
mod startup_format_tests {
    use super::*;
    use crate::tests::persisted_image::image;
    #[test]
    fn ownerless_chunk_refuses_before_attachment_initialization_or_writer_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("relay.redb");
        drop(RelayRedbStore::open_at(&path, 100)?);
        let db = redb::Database::open(&path)?;
        let write = db.begin_write()?;
        let valid = serde_json::json!({"chunk_id":"current","object_id":"object","manifest_hash":"manifest","chunk_index":0,"chunk_cipher_hash":"hash","owner_signing_key_id":"owner","owner_public_key":"key","encrypted_chunk":[1],"stored_at":100,"expires_at":200,"delete_after_ack":false,"acked_by":[],"status":"Available"});
        let mut retired = valid.clone();
        retired["chunk_id"] = serde_json::json!("retired");
        retired["owner_public_key"] = serde_json::json!("");
        {
            let mut rows = write.open_table(RELAY_CHUNK_ENTRY_TABLE)?;
            rows.insert("current", serde_json::to_vec(&valid)?.as_slice())?;
            rows.insert("retired", serde_json::to_vec(&retired)?.as_slice())?;
        }
        write.commit()?;
        drop(db);
        let before = image(directory.path())?;
        assert!(
            matches!(
                RelayRedbStore::open_at(&path, 100),
                Err(NodeCoreError::UnsupportedPersistedFormat("relay chunk owner binding"))
            ),
            "mixed ownerless chunks must fail before startup writes"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "relay refusal changed any chunk, accounting table or journal"
        );
        Ok(())
    }
}
