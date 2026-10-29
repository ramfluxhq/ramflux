// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable, no-replace publication of complete local custody authority.
use crate::SdkError;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

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
mod tests;
