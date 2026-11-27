// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic length-prefixed encoding for every signed or hashed large-group structure.

use super::LgError;

/// Appends fields in order; variable fields carry a 4-byte big-endian length prefix.
#[derive(Default)]
pub(crate) struct Enc {
    out: Vec<u8>,
}

impl Enc {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut enc = Self { out: Vec::new() };
        enc.var(domain);
        enc
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.out.push(value);
        self
    }

    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Fixed-width field (no prefix).
    pub(crate) fn fixed(&mut self, value: &[u8]) -> &mut Self {
        self.out.extend_from_slice(value);
        self
    }

    /// Variable-width field with a length prefix. Lengths above `u32::MAX` cannot occur for the
    /// bounded inputs of this module; they are clamped to a prefix that makes decoding fail.
    pub(crate) fn var(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.out.extend_from_slice(&len.to_be_bytes());
        self.out.extend_from_slice(value);
        self
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Bounds-checked reader over untrusted bytes.
pub(crate) struct Dec<'a> {
    buf: &'a [u8],
}

impl<'a> Dec<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], LgError> {
        let (head, tail) = self.buf.split_at_checked(len).ok_or(LgError::Format("truncated"))?;
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, LgError> {
        let bytes = self.take(1)?;
        bytes.first().copied().ok_or(LgError::Format("truncated"))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, LgError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| LgError::Format("u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, LgError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| LgError::Format("u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], LgError> {
        self.take(N)?.try_into().map_err(|_| LgError::Format("fixed field"))
    }

    pub(crate) fn var(&mut self, max: usize) -> Result<&'a [u8], LgError> {
        let len = usize::try_from(self.u32()?).map_err(|_| LgError::Format("length"))?;
        if len > max {
            return Err(LgError::Format("field too long"));
        }
        self.take(len)
    }

    pub(crate) fn finish(&self) -> Result<(), LgError> {
        if self.buf.is_empty() { Ok(()) } else { Err(LgError::Format("trailing bytes")) }
    }
}
