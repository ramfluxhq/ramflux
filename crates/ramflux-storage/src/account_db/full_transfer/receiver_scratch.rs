// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Transient receiver workspace ownership. Retained stage/publication files are untouched.
use crate::StorageError;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) struct Scratch {
    pub(super) path: PathBuf,
    lock: Option<fs::File>,
    retained: bool,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        self.lock.take();
        if !self.retained {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
impl Scratch {
    pub(super) fn retain(&mut self) {
        self.retained = true;
    }
    pub(super) fn create(stage: &Path, retained: Option<&str>) -> Result<Self, StorageError> {
        reclaim(stage, retained)?;
        let path = stage.join(format!(
            "receiver-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new().mode(0o700).create(&path)?;
        }
        #[cfg(not(unix))]
        return Err(super::stage::context());
        let mut scratch = Self { path, lock: None, retained: false };
        let lock = super::stage::create_file(&scratch.path.join("owner.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)?;
        scratch.lock = Some(lock);
        fs::File::open(&scratch.path)?.sync_all()?;
        fs::File::open(stage)?.sync_all()?;
        Ok(scratch)
    }
}
fn reclaim(stage: &Path, retained: Option<&str>) -> Result<(), StorageError> {
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(raw) = name.to_str().and_then(|name| name.strip_prefix("receiver-")) else {
            continue;
        };
        if super::stage::raw32(raw).is_err() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(super::stage::context());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(super::stage::context());
            }
        }
        // A pin always holds stage.lock while creating this file. A live bulk-copy
        // owner retains its independent lock even after releasing the stage loan.
        if retained == name.to_str() {
            drop(super::stage::open_regular(&entry.path().join("owner.lock"), true)?);
            continue;
        }
        let lock = match super::stage::open_regular(&entry.path().join("owner.lock"), true) {
            Ok(lock) => lock,
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                // Crash between mkdir and owner.lock. No key/copy could have existed.
                fs::remove_dir_all(entry.path())?;
                continue;
            }
            Err(error) => return Err(error),
        };
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => fs::remove_dir_all(entry.path())?,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt as _, symlink};

    #[test]
    fn pairing_full_receiver_scratch_reclaims_only_unlocked_owned_workspaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::tests::temp_root("receiver-scratch-owner");
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let first = Scratch::create(&root, None)?;
        let orphan =
            root.join(format!("receiver-{}", ramflux_protocol::encode_base64url([17; 32])));
        fs::DirBuilder::new().mode(0o700).create(&orphan)?;
        super::super::stage::create_file(&orphan.join("owner.lock"))?.sync_all()?;
        let retained = root.join("stage.key");
        fs::write(&retained, b"retained reconciliation metadata")?;
        let second = Scratch::create(&root, None)?;
        assert!(first.path.exists(), "active owner was reclaimed");
        assert!(!orphan.exists(), "unlocked lost-key workspace survived");
        assert!(retained.exists(), "retained stage metadata was removed");
        let outside = crate::tests::temp_root("receiver-scratch-outside");
        fs::DirBuilder::new().mode(0o700).create(&outside)?;
        let alias = root.join(format!("receiver-{}", ramflux_protocol::encode_base64url([19; 32])));
        symlink(&outside, &alias)?;
        assert!(Scratch::create(&root, None).is_err(), "scratch symlink was accepted");
        assert!(outside.exists());
        drop(first);
        drop(second);
        fs::remove_dir_all(root)?;
        fs::remove_dir_all(outside)?;
        Ok(())
    }
}
