// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded LRU hint for acknowledgements; encrypted storage remains authoritative.

use ramflux_crypto::RootQualifiedDeviceRef;

type AckPosition = (RootQualifiedDeviceRef, String, u64);

use std::collections::{BTreeSet, VecDeque};

pub(crate) struct AckCache {
    entries: BTreeSet<AckPosition>,
    recent: VecDeque<AckPosition>,
}
impl AckCache {
    pub(crate) fn new() -> Self {
        Self { entries: BTreeSet::new(), recent: VecDeque::new() }
    }
    pub(crate) fn contains(&mut self, id: &AckPosition) -> bool {
        if !self.entries.contains(id) {
            return false;
        }
        self.recent.retain(|entry| entry != id);
        self.recent.push_back(id.clone());
        true
    }
    pub(crate) fn insert(&mut self, id: AckPosition) {
        if self.contains(&id) {
            return;
        }
        self.entries.insert(id.clone());
        self.recent.push_back(id);
        if self.entries.len() > 256
            && let Some(oldest) = self.recent.pop_front()
        {
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AckCache, RootQualifiedDeviceRef};
    #[test]
    fn acknowledgement_hints_are_bounded_and_lru() -> Result<(), ramflux_crypto::CryptoError> {
        let mut cache = AckCache::new();
        let root = ramflux_crypto::create_identity_root("receiver", [81; 32]);
        let device = RootQualifiedDeviceRef::for_owned_account_device(&root, "phone")?;
        let key = |index| (device.clone(), "mailbox".to_owned(), index);
        for index in 0..256 {
            cache.insert(key(index));
        }
        assert!(cache.contains(&key(0)));
        cache.insert(key(256));
        assert!(cache.contains(&key(0)));
        assert!(!cache.contains(&key(1)));
        assert_eq!(cache.entries.len(), 256);
        assert_eq!(cache.recent.len(), 256);
        Ok(())
    }
}
