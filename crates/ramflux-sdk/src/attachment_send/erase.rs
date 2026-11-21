// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Terminal local erase. The account-sealed file key, the plaintext snapshot and the segment
//! cache are removed only after the fence record that authorizes it is durable on disk,
//! including the parent directory entry. Another recipient's grant is never touched here.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use super::budget;
use super::codes::{CODE_SEAL_FAILED, Refusal};
use super::meta::{Phase, Row};
use super::store::Store;

/// Flushes a file or directory to stable storage.
pub(super) fn sync_path(path: &Path) -> Result<(), Refusal> {
    File::open(path).and_then(|file| file.sync_all()).map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

fn zero_then_remove(path: &Path) -> Result<(), Refusal> {
    let Ok(meta) = fs::metadata(path) else {
        return Ok(());
    };
    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        let len = usize::try_from(meta.len()).unwrap_or(0).min(1 << 20);
        let _ = file.write_all(&vec![0_u8; len]);
        let _ = file.sync_all();
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Refusal::new(CODE_SEAL_FAILED)),
    }
}

impl Store {
    /// Fences the prepare (Cleaning unless already Cleaning or Fenced), makes that record
    /// durable, then removes the key, snapshot and segments. Idempotent.
    /// # Errors
    /// Returns `seal_failed` when the record cannot be made durable or a file cannot be removed.
    pub(crate) fn retire_and_wipe(&self, prepare_id: &str) -> Result<Row, Refusal> {
        let mut row = self.load(prepare_id)?;
        if !matches!(row.phase, Phase::Cleaning | Phase::Fenced) {
            row.phase = Phase::Cleaning;
            budget::release_disk(row.charged);
            row.charged = 0;
            self.save(&row)?;
        }
        self.wipe_fenced(&row)?;
        Ok(row)
    }

    /// Wipes a prepare whose Cleaning or Fenced record is already saved.
    pub(super) fn wipe_after_cancel(&self, row: &Row) -> Result<(), Refusal> {
        self.wipe_fenced(row)
    }

    fn wipe_fenced(&self, row: &Row) -> Result<(), Refusal> {
        let dir = self.dir(&row.prepare_id);
        // The authorizing record must be on stable storage before any secret is removed.
        sync_path(&dir.join("meta.json"))?;
        sync_path(&dir)?;
        zero_then_remove(&dir.join("secret.bin"))?;
        zero_then_remove(&dir.join("plain.bin"))?;
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Refusal::new(CODE_SEAL_FAILED)),
        };
        for entry in entries {
            let path = entry.map_err(|_| Refusal::new(CODE_SEAL_FAILED))?.path();
            let name = path.file_name().and_then(|item| item.to_str()).unwrap_or_default();
            let temporary = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"));
            if name.starts_with("segment-") || temporary {
                zero_then_remove(&path)?;
            }
        }
        sync_path(&dir)
    }

    /// Removes the grant material kept for retirement delivery: signed capabilities in the
    /// stored media entry and Inner. Called once every retirement is acknowledged.
    /// # Errors
    /// Returns `seal_failed` when a file cannot be removed.
    pub(crate) fn wipe_grant_material(&self, prepare_id: &str) -> Result<(), Refusal> {
        let dir = self.dir(prepare_id);
        for name in ["media.bin", "inner.bin", "manifest.bin"] {
            zero_then_remove(&dir.join(name))?;
        }
        if dir.exists() { sync_path(&dir) } else { Ok(()) }
    }

    /// Startup sweep: completes the wipe of every prepare that was cancelled or fenced.
    /// # Errors
    /// Returns `seal_failed` when the directory or a prepare cannot be read.
    #[cfg_attr(not(test), allow(dead_code, reason = "called by retire::sweep at account unlock"))]
    pub(crate) fn cleanup_cancelled(&self) -> Result<usize, Refusal> {
        let entries = fs::read_dir(&self.root).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let mut done = 0_usize;
        for entry in entries {
            let entry = entry.map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(row) = self.load(&id) else {
                continue;
            };
            if matches!(row.phase, Phase::Cleaning) {
                self.wipe_fenced(&row)?;
                done = done.saturating_add(1);
            }
        }
        Ok(done)
    }
}
