// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual element reads/writes are observable without counters in production.
use super::{Frame, Inner};
#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
pub(super) struct Element {
    frame: Frame,
    #[cfg(test)]
    accesses: Arc<AtomicUsize>,
}
impl Element {
    pub(super) fn new(frame: Frame, inner: &Inner) -> Self {
        #[cfg(test)]
        inner.accesses.fetch_add(1, Ordering::Relaxed);
        let _ = inner;
        Self {
            frame,
            #[cfg(test)]
            accesses: inner.accesses.clone(),
        }
    }
    pub(super) fn into_frame(self) -> Frame {
        #[cfg(test)]
        self.accesses.fetch_add(1, Ordering::Relaxed);
        self.frame
    }
}
impl std::ops::Deref for Element {
    type Target = Frame;
    fn deref(&self) -> &Frame {
        #[cfg(test)]
        self.accesses.fetch_add(1, Ordering::Relaxed);
        &self.frame
    }
}
