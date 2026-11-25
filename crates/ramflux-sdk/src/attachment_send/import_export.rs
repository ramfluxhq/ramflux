// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Export of a verified download to a caller-chosen path. Only whole, verified plaintext is
//! copied, and only after the worker has marked the import ready. The copy goes to an exclusive
//! temporary file in the destination directory, is fsynced, and is published with a hard link,
//! which refuses to replace an existing name. The temporary name is removed on every path.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use super::codes::{CODE_PATH_REFUSED, CODE_SEAL_FAILED, Refusal};

/// Copies exactly `length` bytes of `source` to `dest`, refusing when `dest` already exists.
/// # Errors
/// Returns `path_refused` for a relative, traversing, symlinked or already existing destination,
/// and `seal_failed` when the copy or its durable publish fails.
pub(crate) fn publish(source: &Path, length: u64, dest: &Path) -> Result<(), Refusal> {
    let parent = destination_parent(dest)?;
    let name = dest.file_name().ok_or(Refusal::new(CODE_PATH_REFUSED))?;
    if fs::symlink_metadata(dest).is_ok() {
        return Err(Refusal::new(CODE_PATH_REFUSED));
    }
    let temp = parent.join(format!(".{}.rf-export-{}.tmp", name.to_string_lossy(), nonce()?));
    let result = copy_exact(source, &temp, length)
        .and_then(|()| fs::hard_link(&temp, dest).map_err(|_| Refusal::new(CODE_PATH_REFUSED)));
    let _ = fs::remove_file(&temp);
    result?;
    File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

/// The destination's directory: absolute, free of `..` and `.` components, and every ancestor a
/// real directory (not a symlink) that exists.
fn destination_parent(dest: &Path) -> Result<PathBuf, Refusal> {
    if !dest.is_absolute()
        || dest.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(Refusal::new(CODE_PATH_REFUSED));
    }
    let parent = dest.parent().ok_or(Refusal::new(CODE_PATH_REFUSED))?;
    // Every ancestor must be a real directory, not only the last one: a symlinked ancestor would
    // redirect the publish outside the directory the caller named.
    for ancestor in parent.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| Refusal::new(CODE_PATH_REFUSED))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(Refusal::new(CODE_PATH_REFUSED));
        }
    }
    Ok(parent.to_path_buf())
}

/// An exclusive, fsynced copy of exactly `length` bytes.
fn copy_exact(source: &Path, temp: &Path, length: u64) -> Result<(), Refusal> {
    let mut input = File::open(source).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|_| Refusal::new(CODE_PATH_REFUSED))?;
    let copied = std::io::copy(&mut (&mut input).take(length), &mut output)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    if copied != length {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    output.sync_all().map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

fn nonce() -> Result<String, Refusal> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(bytes.iter().fold(String::with_capacity(16), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    }))
}
