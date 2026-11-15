// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable, no-replace publication of complete local custody authority.
use super::{directory, private_directory};
use crate::SdkError;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

pub(super) fn reserve_account(root: &Path, id: &str, anchor: &str) -> Result<PathBuf, SdkError> {
    let parent = root.join("custody_accounts");
    if !parent.try_exists()? {
        private_directory(&parent)?;
        crate::platform::fs::sync_path(root)?;
    }
    let dir = directory(root, id)?;
    private_directory(&dir)?; // Exclusive reservation is itself a fail-closed mode latch.
    crate::platform::fs::sync_path(&parent)?;
    // Create the crash marker before the insert-only index reservation. Startup can remove
    // a marker with neither an index row nor authority without retiring the account id.
    #[cfg(test)]
    super::race_hooks::run(super::race_hooks::Stage::BeforeReservation, root, id)?;
    let index = ramflux_storage::AccountIndex::open(root)?;
    if let Err(error) = index.reserve_account(id, anchor) {
        fs::remove_dir(&dir)?;
        crate::platform::fs::sync_path(&parent)?;
        return match error {
            ramflux_storage::StorageError::AccountAlreadyExists(_) => {
                Err(SdkError::CustodyAccountConflict)
            }
            error => Err(error.into()),
        };
    }
    #[cfg(test)]
    super::race_hooks::run(super::race_hooks::Stage::AfterReservation, root, id)?;
    require_owned_reservation(root, id, anchor, &dir)?;
    #[cfg(test)]
    super::race_hooks::run(super::race_hooks::Stage::AfterReservationCheck, root, id)?;
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

/// Removes an account that never published `authority.json`, including its wrapped data key.
///
/// # Errors
/// Returns filesystem or index errors. A directory that already contains `authority.json` is left
/// in place.
pub(super) fn discard_unpublished(root: &Path, id: &str, anchor: &str) -> Result<(), SdkError> {
    let dir = directory(root, id)?;
    if dir.join("authority.json").try_exists()? {
        return Ok(());
    }
    let index = ramflux_storage::AccountIndex::open(root)?;
    if !index.release_unpublished_reservation(id, anchor)? {
        match index.account(id) {
            Err(ramflux_storage::StorageError::AccountNotFound(_)) => {}
            Ok(_) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    let account_dir = root.join("accounts").join(id);
    if account_dir.try_exists()? {
        fs::remove_dir_all(&account_dir)?;
    }
    if dir.try_exists()? && !dir.join("authority.json").try_exists()? {
        fs::remove_dir_all(&dir)?;
    }
    let accounts = root.join("accounts");
    if accounts.try_exists()? {
        crate::platform::fs::sync_path(&accounts)?;
    }
    let parent = root.join("custody_accounts");
    if parent.try_exists()? {
        crate::platform::fs::sync_path(&parent)?;
    }
    Ok(())
}

pub(super) fn write_public(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    let parent = path.parent().ok_or_else(super::super::invalid)?;
    let temporary = parent.join(format!(
        ".authority-{}.tmp",
        ramflux_protocol::encode_base64url(*super::super::random()?)
    ));
    let mut file = crate::platform::fs::create_new_owner_only(&temporary)?;
    let mut cleanup = TemporaryPublication(Some(temporary.clone()));
    #[cfg(test)]
    checkpoints::run(checkpoints::Stage::TemporaryCreated)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(test)]
    checkpoints::run(checkpoints::Stage::TemporarySynced)?;
    #[cfg(test)]
    if let Err(error) = checkpoints::run(checkpoints::Stage::Publish) {
        return Err(match error {
            SdkError::Io(cause) => publication_failure(&cause),
            other => other,
        });
    }
    // A same-directory rename publishes the synced inode. Android app storage rejects a
    // hard link in this directory. An existing name stays Io(AlreadyExists) and is not replaced.
    match crate::platform::fs::rename_no_replace(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(SdkError::Io(error));
        }
        Err(error) => return Err(publication_failure(&error)),
    }
    cleanup.0 = None;
    #[cfg(test)]
    if let Err(error) = checkpoints::run(checkpoints::Stage::Published) {
        tracing::warn!(%error, "custody publication observer failed");
    }
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        tracing::warn!(%error, "published custody authority directory sync failed");
    }
    Ok(())
}

fn publication_failure(error: &std::io::Error) -> SdkError {
    // The OS error can carry the account path. Keep only the kind.
    tracing::warn!(kind = ?error.kind(), "custody authority publication failed");
    SdkError::CustodyPublicationFailed
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
        Publish,
        Published,
    }
    type Hook = Box<dyn FnMut(Stage) -> Result<(), SdkError>>;
    thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    #[cfg_attr(not(unix), allow(dead_code))]
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

#[cfg(test)]
#[path = "genesis/flow_tests.rs"]
mod flow_tests;
