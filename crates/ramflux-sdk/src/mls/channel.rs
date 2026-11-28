// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seal once (spec §3.3, S-6): one `PrivateMessage` per message, reused for every target envelope
//! and for every retry. The cache key is `(group_id, epoch, BLAKE3(plaintext))`, so a retry of the
//! same plaintext in the same epoch returns the sealed bytes instead of ratcheting again, and a
//! new epoch seals afresh.
//!
//! The cache is in memory and bounded; a miss after a restart only costs one more ratchet step.

use std::collections::{BTreeMap, VecDeque};

use ramflux_mls::{Mls, MlsError, MlsKv};

use crate::SdkError;

/// Sealed messages kept for retries.
pub(crate) const SEAL_CACHE_ENTRIES: usize = 256;
/// Most plaintext bytes accepted for one seal (the MLS message bound).
pub(crate) const SEAL_PLAINTEXT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Cache key of one sealed message.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SealKey {
    group_id: Vec<u8>,
    epoch: u64,
    plaintext_hash: [u8; 32],
}

impl SealKey {
    /// The key of `plaintext` sealed in `group_id` at `epoch`.
    pub(crate) fn new(group_id: &[u8], epoch: u64, plaintext: &[u8]) -> Self {
        Self {
            group_id: group_id.to_vec(),
            epoch,
            plaintext_hash: *blake3::hash(plaintext).as_bytes(),
        }
    }
}

/// A sealed message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    /// The `PrivateMessage` bytes, identical for every target.
    pub(crate) message: Vec<u8>,
    /// Epoch it was sealed in.
    pub(crate) epoch: u64,
    /// True when the bytes came from the cache (no new ratchet step).
    pub(crate) cached: bool,
}

/// Bounded first-in-first-out cache of sealed messages.
#[derive(Debug, Default)]
pub(crate) struct SealCache {
    entries: BTreeMap<SealKey, Vec<u8>>,
    order: VecDeque<SealKey>,
}

impl SealCache {
    /// The sealed bytes for `key`, if cached.
    pub(crate) fn get(&self, key: &SealKey) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }

    /// Remember `message` under `key`; the oldest entry goes when the cache is full.
    pub(crate) fn put(&mut self, key: SealKey, message: Vec<u8>) {
        if self.entries.insert(key.clone(), message).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > SEAL_CACHE_ENTRIES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Forget every message of `group_id` (switch-over, removal).
    pub(crate) fn evict_group(&mut self, group_id: &[u8]) {
        self.entries.retain(|key, _| key.group_id != group_id);
        self.order.retain(|key| key.group_id != group_id);
    }

    /// Entries held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Seal `plaintext` for `group_id` once. Authenticated data is empty (spec S-1: the per-target
/// fields stay bound by the sender's device signature over the outer envelope).
///
/// A hit returns the cached bytes. A miss runs one `Mls::send` and commits it before the bytes
/// are released.
///
/// # Errors
/// An empty or oversized plaintext, an unknown group, MLS or storage failures.
pub(crate) fn seal_once<K: MlsKv>(
    mls: &Mls<K>,
    cache: &mut SealCache,
    group_id: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, SdkError> {
    if plaintext.is_empty() || plaintext.len() > SEAL_PLAINTEXT_MAX_BYTES {
        return Err(SdkError::Mls {
            code: "too_large",
            detail: "a plaintext to seal is empty or over the bound".to_owned(),
        });
    }
    let epoch = mls.status(group_id)?.epoch;
    let key = SealKey::new(group_id, epoch, plaintext);
    if let Some(message) = cache.get(&key) {
        return Ok(Sealed { message: message.clone(), epoch, cached: true });
    }
    let output = mls.send(group_id, plaintext, &[])?.commit_plain().map_err(MlsError::from)?;
    cache.put(SealKey::new(group_id, output.epoch, plaintext), output.message.clone());
    Ok(Sealed { message: output.message, epoch: output.epoch, cached: false })
}

/// The bounded outer header of a `PrivateMessage` (RFC 9420 6): the group the message belongs to
/// and the epoch it was protected in, read without any key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OuterHeader {
    /// Group id.
    pub(crate) group_id: Vec<u8>,
    /// Epoch of the message.
    pub(crate) epoch: u64,
}

/// Most bytes the header parser reads.
const OUTER_HEADER_MAX_BYTES: usize = 64;
const MLS10: u16 = 1;
const WIRE_FORMAT_PRIVATE_MESSAGE: u16 = 2;
const CONTENT_TYPE_APPLICATION: u8 = 1;

fn header_error() -> SdkError {
    SdkError::Mls {
        code: "decrypt_failed",
        detail: "the message is not a well-formed MLS private message".to_owned(),
    }
}

/// Read `{group_id, epoch}` of an application `PrivateMessage` (the same bounded layout the
/// orderer parses: version, wire format, group id, epoch, content type).
///
/// # Errors
/// A truncated header, another wire format or content type than an application `PrivateMessage`.
pub(crate) fn outer_header(message: &[u8]) -> Result<OuterHeader, SdkError> {
    let mut cursor =
        HeaderCursor { rest: message.get(..OUTER_HEADER_MAX_BYTES).unwrap_or(message) };
    if cursor.u16()? != MLS10 || cursor.u16()? != WIRE_FORMAT_PRIVATE_MESSAGE {
        return Err(header_error());
    }
    let first = cursor.u8()?;
    let group_len = match first >> 6 {
        0 => usize::from(first),
        1 => (usize::from(first & 0x3f) << 8) | usize::from(cursor.u8()?),
        _ => return Err(header_error()),
    };
    let group_id = cursor.take(group_len)?.to_vec();
    let epoch = cursor.u64()?;
    if cursor.u8()? != CONTENT_TYPE_APPLICATION {
        return Err(header_error());
    }
    Ok(OuterHeader { group_id, epoch })
}

struct HeaderCursor<'a> {
    rest: &'a [u8],
}

impl<'a> HeaderCursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SdkError> {
        let (head, tail) = self.rest.split_at_checked(count).ok_or_else(header_error)?;
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, SdkError> {
        self.take(1)?.first().copied().ok_or_else(header_error)
    }

    fn u16(&mut self) -> Result<u16, SdkError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| header_error())?))
    }

    fn u64(&mut self) -> Result<u64, SdkError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| header_error())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_separates_group_epoch_and_plaintext() {
        let base = SealKey::new(&[1], 4, b"hello");
        assert_eq!(base, SealKey::new(&[1], 4, b"hello"), "same inputs, same key");
        assert_ne!(base, SealKey::new(&[2], 4, b"hello"), "another group");
        assert_ne!(base, SealKey::new(&[1], 5, b"hello"), "another epoch seals afresh");
        assert_ne!(base, SealKey::new(&[1], 4, b"hellp"), "another plaintext");
    }

    #[test]
    fn cache_is_bounded_and_drops_the_oldest() {
        let mut cache = SealCache::default();
        for index in 0..SEAL_CACHE_ENTRIES + 3 {
            let text = index.to_be_bytes();
            cache.put(SealKey::new(&[1], 1, &text), text.to_vec());
        }
        assert_eq!(cache.len(), SEAL_CACHE_ENTRIES, "the cache never exceeds its bound");
        assert!(cache.get(&SealKey::new(&[1], 1, &0_usize.to_be_bytes())).is_none(), "oldest gone");
        let last = (SEAL_CACHE_ENTRIES + 2).to_be_bytes();
        assert!(cache.get(&SealKey::new(&[1], 1, &last)).is_some(), "newest kept");
    }

    #[test]
    fn re_putting_a_key_does_not_grow_the_queue() {
        let mut cache = SealCache::default();
        let key = SealKey::new(&[1], 1, b"x");
        cache.put(key.clone(), vec![1]);
        cache.put(key.clone(), vec![2]);
        assert_eq!(cache.len(), 1, "one entry per key");
        assert_eq!(cache.get(&key), Some(&vec![2]), "the latest bytes win");
    }

    #[test]
    fn evicting_a_group_keeps_the_others() {
        let mut cache = SealCache::default();
        cache.put(SealKey::new(&[1], 1, b"a"), vec![1]);
        cache.put(SealKey::new(&[2], 1, b"a"), vec![2]);
        cache.evict_group(&[1]);
        assert_eq!(cache.len(), 1, "only the other group remains");
        assert!(cache.get(&SealKey::new(&[2], 1, b"a")).is_some(), "group 2 untouched");
    }
}
