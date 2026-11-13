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

    #[test]
    #[should_panic(expected = "observer::begin while this thread holds")]
    fn observer_session_reentry_panics_and_releases() {
        struct Reopen;
        impl Drop for Reopen {
            fn drop(&mut self) {
                drop(observer::begin(&["after"]));
            }
        }
        let _reopen = Reopen;
        let _first = observer::begin(&["x"]);
        drop(observer::begin(&["y"]));
    }
}
