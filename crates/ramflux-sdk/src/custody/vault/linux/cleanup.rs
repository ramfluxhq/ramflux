// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fixed-capacity owned buffers: no secret-bearing growth/reallocation or Debug.
use zeroize::Zeroize;

pub(super) struct Secret<const N: usize> {
    bytes: Box<[u8; N]>,
    #[cfg(test)]
    label: &'static str,
}

impl<const N: usize> Secret<N> {
    pub(super) fn new(label: &'static str) -> Self {
        #[cfg(not(test))]
        let _ = label;
        Self {
            bytes: Box::new([0; N]),
            #[cfg(test)]
            label,
        }
    }
    pub(super) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        observer::inspect(self.label, self.bytes.as_slice());
    }
}

/// Test-only observer (shared, session-scoped; see `custody::observer`).
#[cfg(test)]
pub(crate) use crate::custody::observer;

#[cfg(test)]
mod tests {
    use super::observer;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// Harness rule: re-entry on the same thread fails loudly, the lock is released on drop and
    /// by an unwinding panic.
    #[test]
    fn observer_session_reentry_panics_and_releases() {
        let first = observer::begin(&["x"]);
        let again = catch_unwind(AssertUnwindSafe(|| drop(observer::begin(&["y"]))));
        let message = again.err().map(|e| {
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                .unwrap_or_default()
        });
        assert!(
            message.is_some_and(|m| m.contains("observer::begin while this thread holds")),
            "same-thread re-entry must panic with the scoping message"
        );
        drop(first);
        drop(observer::begin(&["z"]));
        let unwound = catch_unwind(|| {
            let _s = observer::begin(&["w"]);
            assert_eq!(std::hint::black_box(1), 2, "case failed");
        });
        assert!(unwound.is_err());
        drop(observer::begin(&["after"]));
    }
}
