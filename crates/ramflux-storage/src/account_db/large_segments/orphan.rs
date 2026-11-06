// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Bounded discovery of file generations whose metadata was lost before resource registration.
use super::{SegmentStore, StorageError, lease};
use rusqlite::params;
use std::{fs::ReadDir, path::PathBuf};
/// Private iterator cursor. Recreate after restart; discovered debt is already durable.
pub struct SegmentOrphanSweep {
    roots: ReadDir,
    children: Option<ReadDir>,
    pending: Option<(String, i64)>,
    done: bool,
}
impl SegmentStore<'_> {
    /// # Errors
    /// Returns private-directory enumeration failures.
    pub fn orphan_sweep(&self) -> Result<SegmentOrphanSweep, StorageError> {
        Ok(SegmentOrphanSweep {
            roots: std::fs::read_dir(&self.root)?,
            children: None,
            pending: None,
            done: false,
        })
    }
    /// Inspect at most32 directory entries per call. True means more discovery work.
    /// Busy preserves the cursor candidate; the caller must retry after actual drain.
    /// # Errors
    /// Refuses unbounded pages, busy owners, unexpected file types and storage failures.
    pub fn discover_orphans(
        &self,
        sweep: &mut SegmentOrphanSweep,
        limit: usize,
    ) -> Result<bool, StorageError> {
        if limit == 0 || limit > 32 {
            return Err(StorageError::Integrity("segment orphan page"));
        }
        for _ in 0..limit {
            if let Some((dir, generation)) = sweep.pending.clone() {
                let _held = lease::Lease::acquire(self.root.join(&dir))?;
                let tx = self.db.connection.immediate_transaction()?;
                let exists:bool=self.db.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_segment_resource WHERE directory=?1 AND generation=?2)",params![dir,generation],|r|r.get(0))?;
                if !exists {
                    super::retirement::check_capacity(&self.db.connection)?;
                    self.db.connection.execute("INSERT INTO object_segment_resource VALUES(?1,?2,NULL,'','','',NULL,NULL,NULL,1)",params![dir,generation])?;
                    self.db.connection.execute("INSERT INTO object_segment_floor VALUES(?1,?2) ON CONFLICT(directory) DO UPDATE SET generation=max(generation,excluded.generation)",params![dir,generation])?;
                }
                tx.commit()?;
                sweep.pending = None;
                continue;
            }
            if let Some(children) = &mut sweep.children {
                if let Some(entry) = children.next() {
                    let entry = entry?;
                    if !entry.file_type()?.is_dir() {
                        return Err(StorageError::Integrity("segment generation directory"));
                    }
                    let path: PathBuf = entry.path();
                    let generation = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|g| *g > 0)
                        .ok_or(StorageError::Integrity("segment orphan generation"))?;
                    let dir = path
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str())
                        .ok_or(StorageError::Integrity("segment orphan directory"))?
                        .to_owned();
                    sweep.pending = Some((dir, generation));
                    continue;
                }
                sweep.children = None;
            }
            if let Some(entry) = sweep.roots.next() {
                let entry = entry?;
                let name = entry.file_name();
                let dir =
                    name.to_str().ok_or(StorageError::Integrity("segment orphan directory"))?;
                if !entry.file_type()?.is_dir()
                    || !ramflux_protocol::decode_base64url(dir).is_ok_and(|b| b.len() == 32)
                {
                    return Err(StorageError::Integrity("segment orphan directory"));
                }
                sweep.children = Some(std::fs::read_dir(entry.path())?);
            } else {
                sweep.done = true;
                return Ok(false);
            }
        }
        Ok(!sweep.done)
    }
}
