// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Thread-local, test-only checkpoints for already-started legacy writers.
use crate::SdkError;
use std::{cell::RefCell, path::Path};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    AfterReservation,
    AfterManifestCheck,
    BeforeAuthorityPublish,
}
type Hook = Box<dyn FnMut(Stage, &Path, &str) -> Result<(), SdkError>>;
thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
pub(super) struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        HOOK.with(|hook| {
            hook.borrow_mut().take();
        });
    }
}
pub(super) fn install(
    hook: impl FnMut(Stage, &Path, &str) -> Result<(), SdkError> + 'static,
) -> Reset {
    HOOK.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    Reset
}
pub(super) fn run(stage: Stage, root: &Path, id: &str) -> Result<(), SdkError> {
    HOOK.with(|hook| hook.borrow_mut().as_mut().map_or(Ok(()), |hook| hook(stage, root, id)))
}
