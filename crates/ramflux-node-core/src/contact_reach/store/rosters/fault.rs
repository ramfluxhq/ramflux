// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only storage failures at the actual roster transaction boundary.
use super::{Result, storage};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Point {
    BeforeCommit,
    AfterCommit,
}
thread_local! {
    static ARMED: std::cell::Cell<Option<Point>> = const { std::cell::Cell::new(None) };
}
pub(crate) struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        ARMED.set(None);
    }
}
pub(crate) fn arm(point: Point) -> Guard {
    ARMED.set(Some(point));
    Guard
}
pub(super) fn checkpoint(point: Point) -> Result<()> {
    if ARMED.get() == Some(point) {
        ARMED.set(None);
        return Err(storage("test: injected roster storage failure"));
    }
    Ok(())
}
