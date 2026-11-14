// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publish a new profile marker atomically; existing databases are never initialized here.
use crate::{AccountDbKey, StorageError, database::Connection};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

struct Draft {
    path: PathBuf,
    file: File,
}
impl Drop for Draft {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn draft(parent: &Path) -> Result<Draft, StorageError> {
    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        let name = format!(
            ".rf-schema-init-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        );
        let path = parent.join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok(Draft { path, file }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "database initialization name collision",
    )
    .into())
}

pub(crate) fn initialize_if_absent(
    path: &Path,
    key: Option<&AccountDbKey>,
) -> Result<(), StorageError> {
    if path.try_exists()? {
        return Ok(());
    }
    let parent = path.parent().ok_or(StorageError::AuthorizationRejected)?;
    let draft = draft(parent)?;
    let connection = Connection::open(&draft.path)?;
    if let Some(key) = key {
        crate::encryption::apply_key(&connection, key)?;
    }
    connection.execute_batch(&format!(
        "PRAGMA synchronous=FULL; PRAGMA user_version={};",
        ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION,
    ))?;
    drop(connection);
    draft.file.sync_all()?;
    // No replacing rename: another creator or an existing generation-0 path wins unchanged.
    match std::fs::hard_link(&draft.path, path) {
        Ok(()) => {
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
