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

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("router_aborted_ranges_v1");

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
        let mut installed =
            self.publication.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(core) = &*installed {
            return Ok(Arc::clone(core));
        }
        let txn = self.db.begin_write().map_err(error)?;
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
                Key { target, incarnation },
                Inbox { allocated: issued, published: issued, aborted, ..Inbox::default() },
            );
        }
        let shared = Arc::new(Shared {
            registry: Mutex::new(registry),
            worker: OnceLock::new(),
            stopping: AtomicBool::new(false),
            changed: Notify::new(),
            db: Arc::clone(&self.db),
            path: self.path.clone(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("ramflux-publication-resolver".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    resolver(&worker_shared);
                }));
                if result.is_err() {
                    tracing::error!("fatal_tombstone_persistence");
                    eprintln!("fatal_tombstone_persistence");
                    std::process::abort();
                }
            })
            .map_err(error)?;
        let _installed = shared.worker.set(worker.thread().clone());
        let core = Arc::new(PublicationCore { shared, worker: Some(worker) });
        *installed = Some(Arc::clone(&core));
        Ok(core)
    }
}

pub(super) fn abort_batch(
    shared: &Shared,
    descriptors: &[Arc<Descriptor>],
) -> Result<(), NodeCoreError> {
    crate::durability_io::boundary(&shared.path, "tombstone_checkpoint", || {
        let mut tx = crate::durability_io::boundary(&shared.path, "begin_write", || {
            shared.db.begin_write().map_err(std::io::Error::other)
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
    .map_err(error)
}
