// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cross-process daemon ownership, retained by any detached custody commit worker.
use crate::SdkError;
use std::{fs::File, path::Path, sync::Arc};

pub(crate) struct DataRootLock {
    _file: File,
}
impl DataRootLock {
    pub(crate) fn acquire(root: &Path) -> Result<Arc<Self>, SdkError> {
        // Never unlink this file: all daemon instances must lock the same inode.
        let path = root.join("daemon.lock");
        let file = crate::platform::fs::open_owner_only_read_write(&path)?;
        crate::platform::fs::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                SdkError::DataRootInUse
            } else {
                SdkError::Io(error)
            }
        })?;
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
        assert!(matches!(DataRootLock::acquire(&root.0), Err(SdkError::DataRootInUse)));
        assert_eq!(crate::bus::io::local_bus_error_code(&SdkError::DataRootInUse), "DataRootInUse");
        assert_eq!(SdkError::DataRootInUse.to_string(), "data root is in use by another daemon");
        drop(owner);
        assert!(DataRootLock::acquire(&root.0).is_err());
        drop(worker);
        assert!(DataRootLock::acquire(&root.0).is_ok());
        Ok(())
    }
}

#[cfg(test)]
mod ceremony_tests {
    use super::*;
    use crate::custody::{
        CreationCeremony,
        tests::{Root, TestVault, input, words},
    };
    #[test]
    fn public_ceremony_refuses_while_daemon_holds_data_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let daemon = DataRootLock::acquire(&root.0)?;
        assert!(matches!(
            CreationCeremony::begin(&root.0, input("blocked"), 100),
            Err(SdkError::DataRootInUse)
        ));
        drop(daemon);
        assert!(CreationCeremony::begin(&root.0, input("allowed"), 100).is_ok());
        Ok(())
    }
    #[test]
    fn public_ceremony_excludes_concurrent_reconciliation_until_confirmation()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new()?;
        let mut ceremony = CreationCeremony::begin(&root.0, input("creating"), 100)?;
        let phrase = ceremony.show_once()?;
        let answers = words(&phrase, ceremony.hidden_challenge()?)?;
        let other_root = root.0.clone();
        std::thread::spawn(move || {
            assert!(matches!(DataRootLock::acquire(&other_root), Err(SdkError::DataRootInUse)));
        })
        .join()
        .map_err(|_| "reconciler panicked")?;
        ceremony.confirm(&answers, &TestVault::default(), 100)?;
        let lease = DataRootLock::acquire(&root.0)?;
        crate::custody::reconcile_incomplete_markers(&root.0, &lease)?;
        assert!(crate::custody::load_account(&root.0, "creating", 100).is_ok());
        Ok(())
    }
}
