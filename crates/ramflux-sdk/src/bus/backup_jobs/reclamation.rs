// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable post-commit reclamation of exactly the replaced account generation.
use crate::SdkError;
use ramflux_storage::{AccountIndex, LocalAccountRecord};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
const MARKER: &str = ".backup-replaced.json";
pub(super) fn remember(
    generation: &Path,
    previous: Option<&LocalAccountRecord>,
) -> Result<(), SdkError> {
    let Some(previous) = previous else { return Ok(()) };
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(generation.join(MARKER))?;
    file.write_all(&serde_json::to_vec(&previous.db_relative_path)?)?;
    file.sync_all()?;
    std::fs::File::open(generation)?.sync_all()?;
    Ok(())
}
pub(super) fn complete(
    generation: &Path,
    root: &Path,
    index: &AccountIndex,
    id: &str,
) -> Result<(), SdkError> {
    let marker = generation.join(MARKER);
    let meta = match std::fs::symlink_metadata(&marker) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() || meta.len() > 4096 {
        return Err(super::service::refused("unreadable"));
    }
    let selected = root.join(index.account(id)?.db_relative_path);
    if selected.parent() != Some(generation) {
        return Ok(());
    }
    let relative: String = serde_json::from_slice(&std::fs::read(&marker)?)?;
    let account = root.join("accounts").join(id);
    let old = root.join(&relative);
    if Path::new(&relative).components().any(|c| !matches!(c, std::path::Component::Normal(_)))
        || !old.starts_with(&account)
        || old == selected
    {
        return Err(super::service::refused("root_conflict"));
    }
    let parent = old.parent().ok_or_else(|| super::service::refused("unreadable"))?;
    // Never follow a directory symlink, even under the same-user local-bus trust model.
    if parent != account
        && (parent.parent() != Some(account.as_path())
            || !parent.file_name().is_some_and(|n| n.to_string_lossy().starts_with("generation_")))
    {
        return Err(super::service::refused("root_conflict"));
    }
    if std::fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(super::service::refused("root_conflict"));
    }
    if parent == account {
        if old.file_name() != Some(std::ffi::OsStr::new(ramflux_storage::ACCOUNT_DB_FILE)) {
            return Err(super::service::refused("root_conflict"));
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = parent.join(format!("{}{suffix}", ramflux_storage::ACCOUNT_DB_FILE));
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    } else {
        match std::fs::remove_dir_all(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    std::fs::File::open(&account)?.sync_all()?;
    std::fs::remove_file(marker)?;
    std::fs::File::open(generation)?.sync_all()?;
    Ok(())
}
