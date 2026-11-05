// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline operator rotation and crash-resumable in-root quarantine.
use super::{error, incarnation, recovery};
use crate::router_store::incarnation_state;
use crate::{NodeCoreError, RouterRedbStore, durability_io};
use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) const KEY: &str = "session_push_rotation_pending_v1";
#[derive(Deserialize, Serialize)]
struct Pending {
    version: u32,
    wal_root: Option<PathBuf>,
    quarantine: Option<Quarantine>,
}
#[derive(Deserialize, Serialize)]
struct Quarantine {
    source: PathBuf,
    destination: PathBuf,
}

fn pending(db: &redb::Database) -> Result<Option<Pending>, NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let table = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE).map_err(error)?;
    let request = table
        .get(KEY)
        .map_err(error)?
        .map(|row| serde_json::from_slice::<Pending>(row.value()))
        .transpose()
        .map_err(error)?;
    if request.as_ref().is_some_and(|p| p.version != 1) {
        return Err(error("unsupported future rotation marker version"));
    }
    Ok(request)
}
fn mark(db: &redb::Database, request: &Pending) -> Result<(), NodeCoreError> {
    let mut txn = db.begin_write().map_err(error)?;
    txn.set_durability(redb::Durability::Immediate).map_err(error)?;
    txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)
        .map_err(error)?
        .insert(KEY, serde_json::to_vec(request).map_err(error)?.as_slice())
        .map_err(error)?;
    txn.commit().map_err(error)
}
fn quarantine(root: &Path, source: &Path) -> Result<Quarantine, NodeCoreError> {
    let source = fs::canonicalize(source).map_err(error)?;
    let parent = source.parent().ok_or_else(|| error("segment has no parent"))?;
    let active = parent == root
        || super::router_wal_existing_shard_roots(root)?
            .iter()
            .any(|(_, directory)| directory == parent);
    if !active || !fs::symlink_metadata(&source).map_err(error)?.is_file() {
        return Err(error("quarantine requires an active segment inside the WAL root"));
    }
    let valid = super::router_wal_segment_ids(parent)?
        .iter()
        .any(|id| super::router_wal_segment_path(parent, *id) == source);
    if !valid {
        return Err(error("quarantine requires an active WAL segment"));
    }
    // Unix seconds are a UTC timestamp; the random suffix avoids collisions on rapid retries.
    let utc = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_secs();
    let name = source.file_name().ok_or_else(|| error("segment lacks a name"))?.to_string_lossy();
    let destination =
        root.join("quarantine").join(format!("{utc}-{}-{name}", incarnation::new_id()?));
    Ok(Quarantine { source, destination })
}
fn move_segment(root: &Path, segment: &Quarantine) -> Result<(), NodeCoreError> {
    let directory = root.join("quarantine");
    if directory.exists() {
        if fs::symlink_metadata(&directory).map_err(error)?.file_type().is_symlink()
            || !directory.is_dir()
        {
            return Err(error("quarantine must be a directory on the WAL filesystem"));
        }
    } else {
        durability_io::boundary(&directory, "mkdir", || fs::create_dir(&directory))
            .map_err(error)?;
    }
    // Also sync an existing directory entry: a previous crash may follow mkdir.
    durability_io::sync_dir(root).map_err(error)?;
    match (segment.source.exists(), segment.destination.exists()) {
        (true, false) => durability_io::boundary(&segment.source, "quarantine_rename", || {
            fs::rename(&segment.source, &segment.destination)
        })
        .map_err(error)?,
        (false, true) => {}
        _ => return Err(error("quarantine resume requires exactly one of source and destination")),
    }
    durability_io::sync_dir(segment.source.parent().ok_or_else(|| error("missing source parent"))?)
        .map_err(error)?;
    durability_io::sync_dir(&directory).map_err(error)
}

// A pending marker is authoritative, but a new quarantine argument is never
// silently discarded. Completed moves remain in quarantine when the marker is
// amended to repair another segment; no active frame is replayed from there.
fn amend_quarantine(
    db: &redb::Database,
    path: &Path,
    request: &mut Pending,
    source: &Path,
) -> Result<(), NodeCoreError> {
    let root = request.wal_root.as_deref().ok_or_else(|| error("quarantine requires WAL mode"))?;
    if let Some(previous) = &request.quarantine {
        if source == previous.source {
            return Ok(());
        }
        if previous.source.exists() || !previous.destination.exists() {
            return Err(error(
                "quarantine conflicts with an unfinished pending move; resume it first",
            ));
        }
    }
    let next = quarantine(root, source)?;
    recovery::preflight(root, db, Some(&next.source))?;
    request.quarantine = Some(next);
    durability_io::boundary(path, "operator_quarantine_amend", || {
        mark(db, request).map_err(io::Error::other)
    })
    .map_err(error)
}

/// Resume before enabling any store writer or listener. No TTL can clear this marker.
pub(crate) fn resume(db: &Arc<redb::Database>, path: &Path) -> Result<(), NodeCoreError> {
    let Some(request) = pending(db)? else { return Ok(()) };
    if let Some(root) = &request.wal_root {
        if let Some(segment) = &request.quarantine {
            move_segment(root, segment)?;
        }
        // A single Immediate association transaction pins the complete new E set;
        // its final commit clears the operator marker atomically.
        recovery::prepare_forced(root, Arc::clone(db), path, true)?;
    } else {
        let (mut ids, issued) = recovery::cursors(db)?;
        for target in issued.keys() {
            ids.insert(target.clone(), incarnation::new_id()?);
        }
        durability_io::boundary(path, "operator_rotation", || {
            let mut txn = db.begin_write().map_err(io::Error::other)?;
            txn.set_durability(redb::Durability::Immediate).map_err(io::Error::other)?;
            for (target, id) in &ids {
                incarnation::set_cursor(
                    &txn,
                    target,
                    issued.get(target).copied().unwrap_or(0),
                    id,
                    true,
                )
                .map_err(io::Error::other)?;
            }
            // Rotation and marker removal share one commit in redb-only mode.
            txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)
                .map_err(io::Error::other)?
                .remove(KEY)
                .map_err(io::Error::other)?;
            txn.commit().map_err(io::Error::other)
        })
        .map_err(error)?;
        return Ok(());
    }
    Ok(())
}

impl RouterRedbStore {
    /// Rotate every inbox offline, optionally quarantining exactly one damaged segment.
    /// Returns the inbox count; holds the exclusive redb lock until recovery completes.
    /// # Errors
    /// Refuses missing/locked stores, invalid paths and incomplete durability operations.
    pub fn rotate_inbox_incarnations(
        path: impl AsRef<Path>,
        segment: Option<&Path>,
    ) -> Result<usize, NodeCoreError> {
        let path = path.as_ref();
        let root = crate::router_store::router_wal_root_for_redb_path(path);
        let root = crate::router_store::router_wal_enabled().then_some(root);
        Self::rotate_inbox_incarnations_at(path, root.as_deref(), segment)
    }
    /// Offline rotation with an explicit WAL mode and root.
    /// # Errors
    /// Refuses missing/locked stores, invalid quarantine paths or failed durable recovery.
    pub fn rotate_inbox_incarnations_at(
        path: &Path,
        root: Option<&Path>,
        segment: Option<&Path>,
    ) -> Result<usize, NodeCoreError> {
        let db = Arc::new(redb::Database::open(path).map_err(error)?);
        let resume_pending = pending(&db)?;
        // Maintenance intentionally bypasses ordinary WAL open, which may refuse
        // the damaged segment. Import prior cursor-field E without replaying it.
        let mut tx = db.begin_write().map_err(error)?;
        tx.set_durability(redb::Durability::Immediate).map_err(error)?;
        {
            let _identities = tx.open_table(incarnation_state::TABLE).map_err(error)?;
        }
        incarnation_state::import(&tx)?;
        tx.commit().map_err(error)?;
        if let Some(mut request) = resume_pending {
            if let Some(segment) = segment {
                amend_quarantine(&db, path, &mut request, segment)?;
            }
            resume(&db, path)?;
        } else {
            let wal_root = root
                .map(|root| {
                    durability_io::create_dir_all(root).map_err(error)?;
                    fs::canonicalize(root).map_err(error)
                })
                .transpose()?;
            let quarantine = segment
                .map(|segment| {
                    quarantine(
                        wal_root.as_deref().ok_or_else(|| error("quarantine requires WAL mode"))?,
                        segment,
                    )
                })
                .transpose()?;
            // D6 tolerates exactly the named segment. Refuse before marking if
            // another active segment would prevent completion of the pass.
            if let Some(root) = &wal_root {
                recovery::preflight(root, &db, quarantine.as_ref().map(|q| q.source.as_path()))?;
            }
            let _inventory = recovery::cursors(&db)?;
            let request = Pending { version: 1, wal_root, quarantine };
            durability_io::boundary(path, "operator_rotation_pending", || {
                mark(&db, &request).map_err(io::Error::other)
            })
            .map_err(error)?;
            resume(&db, path)?;
        }
        Ok(recovery::cursors(&db)?.0.len())
    }
}
