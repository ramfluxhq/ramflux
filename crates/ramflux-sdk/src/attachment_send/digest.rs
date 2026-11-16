// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental plaintext digest. The finish call must send these bytes.

/// BLAKE3 of the plaintext bytes, with no domain separator.
#[derive(Clone)]
pub struct PlaintextDigester {
    inner: blake3::Hasher,
}

impl Default for PlaintextDigester {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaintextDigester {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: blake3::Hasher::new() }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        *self.inner.finalize().as_bytes()
    }
}
