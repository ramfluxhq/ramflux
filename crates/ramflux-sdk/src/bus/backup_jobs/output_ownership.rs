// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Crash ownership of an exclusive final file while the fallback copy is incomplete.
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
const MARKER: &str = "output-owned.json";
#[derive(serde::Serialize, serde::Deserialize)]
struct Ownership {
    path: PathBuf,
    device: u64,
    inode: u64,
}
pub(super) fn remember(stage: &Path, path: &Path, file: &std::fs::File) -> io::Result<()> {
    let (device, inode) = crate::platform::fs::file_device_inode(file)?;
    let owner = Ownership { path: path.to_owned(), device, inode };
    let mut marker = crate::platform::fs::create_new_owner_only_io(&stage.join(MARKER))?;
    marker.write_all(&serde_json::to_vec(&owner)?)?;
    marker.sync_all()?;
    crate::platform::fs::sync_path(stage)
}
pub(super) fn forget(stage: &Path) -> io::Result<()> {
    std::fs::remove_file(stage.join(MARKER))?;
    crate::platform::fs::sync_path(stage)
}
pub(super) fn recover(stage: &Path) -> io::Result<()> {
    let path = stage.join(MARKER);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !metadata.is_file() || metadata.len() > 32 * 1024 {
        return Ok(());
    }
    let Ok(owner) = serde_json::from_slice::<Ownership>(&std::fs::read(path)?) else {
        return Ok(());
    };
    match std::fs::symlink_metadata(&owner.path) {
        Ok(m)
            if m.is_file()
                && crate::platform::fs::same_metadata_identity(
                    &m,
                    &owner.path,
                    owner.device,
                    owner.inode,
                ) =>
        {
            std::fs::remove_file(&owner.path)?;
            let parent =
                owner.path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            crate::platform::fs::sync_path(parent)?;
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r4_output_recovery_does_not_delete_an_unrelated_file_reusing_the_owned_path()
    -> io::Result<()> {
        let root = crate::bus::runtime_tests::root("backup-output-replacement");
        let stage = root.join("stage");
        std::fs::create_dir_all(&stage)?;
        let path = root.join("final");
        let file = std::fs::File::create(&path)?;
        remember(&stage, &path, &file)?;
        std::fs::rename(&path, root.join("renamed-original"))?;
        std::fs::write(&path, b"unrelated replacement")?;
        recover(&stage)?;
        assert_eq!(std::fs::read(path)?, b"unrelated replacement");
        drop(file);
        std::fs::remove_dir_all(root)
    }
}
