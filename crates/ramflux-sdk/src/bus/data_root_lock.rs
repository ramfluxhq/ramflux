// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cross-process daemon ownership, retained by any detached custody commit worker.
use crate::SdkError;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
};

pub(super) struct DataRootLock {
    _file: File,
}
impl DataRootLock {
    pub(super) fn acquire(root: &Path) -> Result<Arc<Self>, SdkError> {
        // Never unlink this file: all daemon instances must lock the same inode.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join("daemon.lock"))?;
        fs2::FileExt::try_lock_exclusive(&file)?;
        Ok(Arc::new(Self { _file: file }))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custody_data_root_lease_outlives_the_daemon_while_a_commit_worker_holds_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let owner = DataRootLock::acquire(&root.0)?;
        let worker = Arc::clone(&owner);
        assert!(
            matches!(DataRootLock::acquire(&root.0), Err(SdkError::Io(e)) if e.kind()==std::io::ErrorKind::WouldBlock)
        );
        drop(owner);
        assert!(DataRootLock::acquire(&root.0).is_err());
        drop(worker);
        assert!(DataRootLock::acquire(&root.0).is_ok());
        Ok(())
    }
}
