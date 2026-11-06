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

/// Test-only observer snapshots actual bytes after cleanup and before allocation release.
/// Assertions run after the consumer has unwound; no unsafe freed-memory reads.
#[cfg(test)]
pub(crate) mod observer {
    use std::cell::RefCell;
    pub(crate) struct Observation {
        pub label: &'static str,
        pub bytes: Vec<u8>,
    }
    thread_local! {
        static OBSERVATIONS: RefCell<Option<Vec<Observation>>> = const { RefCell::new(None) };
    }
    pub(crate) fn begin() {
        OBSERVATIONS.with(|items| *items.borrow_mut() = Some(Vec::new()));
    }
    pub(crate) fn inspect(label: &'static str, bytes: &[u8]) {
        OBSERVATIONS.with(|items| {
            if let Some(items) = items.borrow_mut().as_mut() {
                items.push(Observation { label, bytes: bytes.to_vec() });
            }
        });
    }
    pub(crate) fn take() -> Vec<Observation> {
        OBSERVATIONS.with(|items| items.borrow_mut().take().unwrap_or_default())
    }
}
