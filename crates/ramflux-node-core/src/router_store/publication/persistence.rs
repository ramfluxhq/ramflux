// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One checkpoint transaction owns the aborted reason and its durable counter in
//! both WAL and redb-only modes. No tentative content or replay tuple is encoded.

use super::{
    Arc, AtomicBool, BTreeMap, BTreeSet, Descriptor, Inbox, Key, Mutex, NodeCoreError, Notify,
    OnceLock, PublicationCore, Registry, Shared, coalesce, error, resolver, thread,
};
use crate::router_store::{RouterRedbStore, incarnation, incarnation_state};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub(crate) const TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("router_aborted_ranges_v1");

#[derive(Deserialize, Serialize)]
struct AbortedRanges {
    incarnation: String,
    ranges: BTreeMap<u64, u64>,
}

impl RouterRedbStore {
    /// Open the store-owned publication core on a store/blocking thread, after
    /// inbox initialization. This does not change existing allocation/read paths.
    /// # Errors
    /// Returns corrupt metadata or resolver-thread creation errors.
    pub fn publication_core(&self) -> Result<Arc<PublicationCore>, NodeCoreError> {
        crate::fatal_durability::initialize();
        let mut installed =
            self.publication.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(core) = &*installed {
            return Ok(Arc::clone(core));
        }
        let txn = self.begin_write().map_err(error)?;
        txn.open_table(TABLE).map_err(error)?;
        txn.commit().map_err(error)?;
        let txn = self.db.begin_read().map_err(error)?;
        let mut targets = BTreeSet::new();
        for row in txn.open_table(incarnation_state::TABLE).map_err(error)?.iter().map_err(error)? {
            targets.insert(row.map_err(error)?.0.value().to_owned());
        }
        if let Some(wal) = &self.submission_wal {
            targets.extend(wal.issued_watermarks().into_keys());
        }
        let ranges = txn.open_table(TABLE).map_err(error)?;
        let mut registry = Registry::default();
        for target in targets {
            let (Some(incarnation), issued) = self.inbox_status(&target)? else {
                continue;
            };
            let mut aborted = BTreeMap::new();
            if let Some(row) = ranges.get(target.as_str()).map_err(error)? {
                let stored: AbortedRanges = serde_json::from_slice(row.value()).map_err(error)?;
                if stored.incarnation == incarnation {
                    aborted = stored.ranges;
                }
            }
            registry.inboxes.insert(
                Key { target: target.clone(), incarnation },
                Inbox {
                    identity_durable: true,
                    allocated: issued,
                    published: issued,
                    committed_settled: txn
                        .open_table(crate::ROUTER_CURSOR_STATE_TABLE)
                        .map_err(error)?
                        .get(target.as_str())
                        .map_err(error)?
                        .map(|row| incarnation::decode_cursor(row.value()))
                        .transpose()?
                        .map_or(0, |cursor| cursor.settled_inbox_seq),
                    aborted,
                    ..Inbox::default()
                },
            );
        }
        let shared = Arc::new(Shared {
            entry_cleanup: OnceLock::new(),
            replay_cleanup: OnceLock::new(),
            registry: Mutex::new(registry),
            worker: OnceLock::new(),
            stopping: AtomicBool::new(false),
            changed: Notify::new(),
            db: Arc::downgrade(&self.db),
            path: self.path.clone(),
            #[cfg(test)]
            snapshot_hook: Mutex::new(None),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("ramflux-publication-resolver".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    resolver(&worker_shared);
                }));
                if result.is_err() {
                    crate::fatal_durability::fence(true);
                }
            })
            .map_err(error)?;
        let _installed = shared.worker.set(worker.thread().clone());
        let core = Arc::new(PublicationCore { shared, worker: Mutex::new(Some(worker)) });
        *installed = Some(Arc::clone(&core));
        Ok(core)
    }
}

pub(super) fn abort_batch(
    shared: &Shared,
    descriptors: &[Arc<Descriptor>],
) -> Result<(), NodeCoreError> {
    let db = shared.db.upgrade().ok_or_else(|| error("publication store closed"))?;
    let guard = crate::fatal_durability::WriteGuard::new(true)?;
    crate::durability_io::boundary(&shared.path, "tombstone_checkpoint", || {
        let mut tx = crate::durability_io::boundary(&shared.path, "begin_write", || {
            db.begin_write().map_err(std::io::Error::other)
        })?;
        tx.set_durability(redb::Durability::Immediate).map_err(std::io::Error::other)?;
        let mut groups: BTreeMap<&Key, Vec<u64>> = BTreeMap::new();
        for descriptor in descriptors {
            groups.entry(&descriptor.key).or_default().push(descriptor.seq);
        }
        for (key, sequences) in groups {
            let mut table = tx.open_table(TABLE).map_err(std::io::Error::other)?;
            let mut ranges = table
                .get(key.target.as_str())
                .map_err(std::io::Error::other)?
                .map(|row| serde_json::from_slice::<AbortedRanges>(row.value()))
                .transpose()
                .map_err(std::io::Error::other)?
                .filter(|row| row.incarnation == key.incarnation)
                .unwrap_or_else(|| AbortedRanges {
                    incarnation: key.incarnation.clone(),
                    ranges: BTreeMap::new(),
                });
            let mut issued = 0;
            for seq in sequences {
                coalesce(&mut ranges.ranges, seq, seq);
                issued = issued.max(seq);
            }
            let bytes = serde_json::to_vec(&ranges).map_err(std::io::Error::other)?;
            table.insert(key.target.as_str(), bytes.as_slice()).map_err(std::io::Error::other)?;
            drop(table);
            incarnation::set_cursor(&tx, &key.target, issued, &key.incarnation, false)
                .map_err(std::io::Error::other)?;
        }
        crate::durability_io::boundary(&shared.path, "tombstone_commit", || {
            tx.commit().map_err(std::io::Error::other)
        })
    })
    .map_err(error)?;
    guard.complete()
}

pub(crate) fn restore_ranges(
    store: &RouterRedbStore,
    inbox: &mut crate::OpaqueDeviceInbox,
) -> Result<(), NodeCoreError> {
    let txn = store.db.begin_read().map_err(error)?;
    let table = match txn.open_table(TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
        Err(source) => return Err(error(source)),
    };
    for row in table.iter().map_err(error)? {
        let (target, bytes) = row.map_err(error)?;
        let ranges: AbortedRanges = serde_json::from_slice(bytes.value()).map_err(error)?;
        if inbox.incarnation_id(target.value()) == Some(ranges.incarnation.as_str()) {
            inbox.aborted_ranges.insert(target.value().into(), ranges.ranges.into_iter().collect());
        }
    }
    Ok(())
}

pub(crate) fn export_ranges(
    tx: &redb::WriteTransaction,
    inbox: &crate::OpaqueDeviceInbox,
) -> Result<(), NodeCoreError> {
    let mut table = tx.open_table(TABLE).map_err(error)?;
    for (target, ranges) in &inbox.aborted_ranges {
        let Some(id) = inbox.incarnation_id(target) else {
            return Err(error("aborted export lacks incarnation"));
        };
        let bytes = serde_json::to_vec(&AbortedRanges {
            incarnation: id.into(),
            ranges: ranges.iter().copied().collect(),
        })
        .map_err(error)?;
        table.insert(target.as_str(), bytes.as_slice()).map_err(error)?;
    }
    Ok(())
}

/// Prune only reasons covered by the cursor written in this same transaction.
pub(crate) fn prune_ranges(
    tx: &redb::WriteTransaction,
    cursor: &crate::CursorAckState,
) -> Result<(), NodeCoreError> {
    let mut table = tx.open_table(TABLE).map_err(error)?;
    let Some(bytes) = table
        .get(cursor.target_delivery_id.as_str())
        .map_err(error)?
        .map(|row| row.value().to_vec())
    else {
        return Ok(());
    };
    let mut stored: AbortedRanges = serde_json::from_slice(&bytes).map_err(error)?;
    let id = incarnation_state::read(tx, &cursor.target_delivery_id)?.map(|(id, _)| id);
    if id.as_deref() != Some(stored.incarnation.as_str()) {
        return Err(error("aborted checkpoint incarnation mismatch"));
    }
    stored.ranges = stored
        .ranges
        .into_iter()
        .filter_map(|(start, end)| {
            (end > cursor.settled_inbox_seq)
                .then_some((start.max(cursor.settled_inbox_seq.saturating_add(1)), end))
        })
        .collect();
    table
        .insert(
            cursor.target_delivery_id.as_str(),
            serde_json::to_vec(&stored).map_err(error)?.as_slice(),
        )
        .map_err(error)?;
    Ok(())
}
