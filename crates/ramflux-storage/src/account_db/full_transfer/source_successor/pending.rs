// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reclaim only interrupted, unkeyed source-copy names while the exact stage lock is held.
use super::{Connection, StorageError, wrong};
use std::path::{Path, PathBuf};
pub(super) struct PendingSnapshot(pub(super) PathBuf);
impl Drop for PendingSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("db-journal"));
    }
}
fn remove_regular(path: &Path) -> Result<(), StorageError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(wrong()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn reclaim(directory: &Path, metadata: &Connection) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(snapshot) = name
            .to_str()
            .and_then(|name| name.strip_prefix("pending-source-"))
            .and_then(|name| name.strip_suffix(".db"))
        else {
            continue;
        };
        super::super::stage::raw32(snapshot)?;
        let pending = entry.path();
        let before = std::fs::symlink_metadata(&pending)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(wrong());
        }
        let keyed: bool = metadata.query_row(
            "SELECT EXISTS(SELECT 1 FROM source_cut WHERE snapshot_id=?1)",
            rusqlite::params![snapshot],
            |r| r.get(0),
        )?;
        if !keyed {
            // adopt_source_cut links, unlinks, fsyncs, THEN commits its key. A crash
            // before that commit can leave an unkeyed alias of the same owned inode.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                for cut in 0..=9 {
                    let alias = directory.join(format!("source-{cut}-{snapshot}.db"));
                    match std::fs::symlink_metadata(&alias) {
                        Ok(alias_metadata)
                            if alias_metadata.is_file()
                                && !alias_metadata.file_type().is_symlink()
                                && alias_metadata.dev() == before.dev()
                                && alias_metadata.ino() == before.ino() =>
                        {
                            remove_regular(&alias)?;
                        }
                        Ok(_) => return Err(wrong()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        remove_regular(&pending)?;
        remove_regular(&pending.with_extension("db-journal"))?;
        crate::sync_path::sync_path(directory)?;
    }
    reclaim_aliases(directory, metadata)?;
    Ok(())
}
fn reclaim_aliases(directory: &Path, metadata: &Connection) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(id) =
            name.strip_prefix("pending-source-").and_then(|name| name.strip_suffix(".db-journal"))
        {
            super::super::stage::raw32(id)?;
            remove_regular(&entry.path())?;
            crate::sync_path::sync_path(directory)?;
            continue;
        }
        let Some(tail) = name.strip_prefix("source-").and_then(|name| name.strip_suffix(".db"))
        else {
            continue;
        };
        let Some((cut, id)) = tail.split_once('-') else {
            continue;
        };
        let Ok(value) = cut.parse::<u64>() else {
            continue;
        };
        if value > 9 || value.to_string() != cut {
            continue;
        }
        super::super::stage::raw32(id)?;
        let keyed: bool = metadata.query_row(
            "SELECT EXISTS(SELECT 1 FROM source_cut WHERE snapshot_id=?1)",
            rusqlite::params![id],
            |r| r.get(0),
        )?;
        if !keyed {
            remove_regular(&entry.path())?;
            remove_regular(&entry.path().with_extension("db-journal"))?;
            crate::sync_path::sync_path(directory)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_full_interrupted_source_copy_reclaims_only_unkeyed_owned_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        let owner = tempfile::Builder::new()
            .prefix("ramflux-storage-full-source-copy-reclaim-")
            .tempdir()?;
        let root = owner.path();
        let metadata = Connection::open(root.join("metadata.db"))?;
        metadata.execute_batch("CREATE TABLE source_cut(snapshot_id TEXT PRIMARY KEY)")?;
        let h = ramflux_protocol::encode_base64url([5; 32]);
        let pending = root.join(format!("pending-source-{h}.db"));
        let alias = root.join(format!("source-1-{h}.db"));
        std::fs::write(&pending, b"unkeyed encrypted copy")?;
        std::fs::hard_link(&pending, &alias)?;
        let keep = root.join("stage.key");
        std::fs::write(&keep, b"retained wrapped stage key")?;
        reclaim(root, &metadata)?;
        assert!(!pending.exists() && !alias.exists(), "unkeyed interrupted adoption survived");
        assert!(keep.exists());
        let orphan =
            root.join(format!("source-2-{}.db", ramflux_protocol::encode_base64url([6; 32])));
        std::fs::write(&orphan, b"unkeyed alias after pending unlink")?;
        reclaim(root, &metadata)?;
        assert!(!orphan.exists(), "unkeyed alias without its pending name survived");
        std::fs::write(&pending, b"keyed encrypted copy")?;
        std::fs::hard_link(&pending, &alias)?;
        metadata.execute("INSERT INTO source_cut VALUES(?1)", rusqlite::params![h])?;
        reclaim(root, &metadata)?;
        assert!(
            !pending.exists() && alias.exists(),
            "reclamation removed a keyed immutable source cut"
        );
        drop(metadata);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
