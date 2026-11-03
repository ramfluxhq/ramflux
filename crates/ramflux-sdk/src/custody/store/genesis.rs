// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable, no-replace publication of complete local custody authority.
use super::{directory, private_directory};
use crate::SdkError;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub(super) fn reserve_account(root: &Path, id: &str, anchor: &str) -> Result<PathBuf, SdkError> {
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        private_directory(&parent)?;
        fs::File::open(root)?.sync_all()?;
    }
    let dir = directory(root, id)?;
    private_directory(&dir)?; // Exclusive reservation is itself a fail-closed mode latch.
    fs::File::open(&parent)?.sync_all()?;
    // Create the crash marker before the insert-only index reservation. Startup can remove
    // a marker with neither an index row nor authority without retiring the account id.
    let index = ramflux_storage::AccountIndex::open(root)?;
    if let Err(error) = index.reserve_account(id, anchor) {
        fs::remove_dir(&dir)?;
        fs::File::open(&parent)?.sync_all()?;
        return match error {
            ramflux_storage::StorageError::AccountAlreadyExists(_) => {
                Err(SdkError::CustodyAccountConflict)
            }
            error => Err(error.into()),
        };
    }
    Ok(dir)
}

pub(super) fn require_owned_reservation(
    root: &Path,
    id: &str,
    anchor: &str,
    dir: &Path,
) -> Result<(), SdkError> {
    let index = ramflux_storage::AccountIndex::open(root)?;
    let owned = match index.account(id) {
        Ok(row) => row.principal_commitment == anchor,
        Err(ramflux_storage::StorageError::AccountNotFound(_)) => false,
        Err(error) => return Err(error.into()),
    };
    if !owned {
        let _ = index.release_unwrapped_reservation(id, anchor);
        // Only our empty unpublished marker may be removed; never delete another authority.
        let _ = fs::remove_dir(dir);
        let _ = File::open(root.join("custody_accounts")).and_then(|parent| parent.sync_all());
        return Err(SdkError::CustodyAccountConflict);
    }
    Ok(())
}

pub(super) fn write_public(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    let parent = path.parent().ok_or_else(super::super::invalid)?;
    let temporary = parent.join(format!(
        ".authority-{}.tmp",
        ramflux_protocol::encode_base64url(*super::super::random()?)
    ));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
    let mut cleanup = TemporaryPublication(Some(temporary.clone()));
    #[cfg(test)]
    checkpoints::run(checkpoints::Stage::TemporaryCreated)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(test)]
    checkpoints::run(checkpoints::Stage::TemporarySynced)?;
    // Linking a fully synced inode publishes all bytes atomically and refuses any existing name.
    fs::hard_link(&temporary, path)?;
    #[cfg(test)]
    checkpoints::run(checkpoints::Stage::Linked)?;
    fs::remove_file(&temporary)?;
    cleanup.0 = None;
    File::open(parent)?.sync_all()?;
    Ok(())
}

struct TemporaryPublication(Option<PathBuf>);
impl Drop for TemporaryPublication {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod checkpoints {
    use crate::SdkError;
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Stage {
        TemporaryCreated,
        TemporarySynced,
        Linked,
    }
    type Hook = Box<dyn FnMut(Stage) -> Result<(), SdkError>>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
    pub(super) struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    pub(super) fn install(hook: impl FnMut(Stage) -> Result<(), SdkError> + 'static) -> Reset {
        HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        Reset
    }
    pub(super) fn run(stage: Stage) -> Result<(), SdkError> {
        HOOK.with(|slot| slot.borrow_mut().as_mut().map_or(Ok(()), |hook| hook(stage)))
    }
}

#[cfg(test)]
#[path = "genesis/tests.rs"]
mod tests;
