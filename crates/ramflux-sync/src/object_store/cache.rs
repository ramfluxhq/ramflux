// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional bounded LRU for persisted account objects. Default stores retain all data.
use super::{EncryptedObject, ObjectStore, retirement::ObjectData};
use std::collections::VecDeque;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CachePolicy {
    pub capacity: usize,
    pub(super) recent: VecDeque<String>,
}

impl ObjectStore {
    /// Bounds this store's rebuildable cache. Callers must provide durable fallback on a miss.
    pub fn set_cache_capacity(&mut self, capacity: usize) {
        let mut data = self.data();
        data.cache = Some(CachePolicy {
            capacity: capacity.max(1),
            recent: data.objects.keys().cloned().collect(),
        });
        data.evict_cached();
    }

    #[must_use]
    pub fn cache_capacity(&self) -> Option<usize> {
        self.data().cache.as_ref().map(|cache| cache.capacity)
    }

    #[must_use]
    pub fn cached_object(&self, id: &str) -> Option<EncryptedObject> {
        let mut data = self.data();
        data.touch_cached(id);
        data.objects.get(id).cloned()
    }

    pub fn cache_persisted_object(&mut self, object: EncryptedObject, key: Option<[u8; 32]>) {
        let mut data = self.data();
        let id = object.object_id.clone();
        data.remove(&id);
        data.retired.remove(&id);
        data.objects.insert(id.clone(), object);
        if let Some(key) = key {
            data.object_keys.insert(id.clone(), key);
        }
        data.touch_cached(&id);
        data.evict_cached();
    }
}

impl ObjectData {
    pub(super) fn touch_cached(&mut self, id: &str) {
        if !self.objects.contains_key(id) {
            return;
        }
        if let Some(cache) = self.cache.as_mut() {
            cache.recent.retain(|existing| existing != id);
            cache.recent.push_back(id.to_owned());
        }
    }

    pub(super) fn evict_cached(&mut self) {
        let Some(capacity) = self.cache.as_ref().map(|cache| cache.capacity) else { return };
        while self.objects.len() > capacity {
            let Some(id) = self.cache.as_mut().and_then(|cache| cache.recent.pop_front()) else {
                break;
            };
            self.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ObjectStore;

    #[test]
    fn bounded_object_cache_evicts_least_recently_used_and_bounds_miss_metadata()
    -> Result<(), crate::SyncError> {
        let mut store = ObjectStore::new();
        store.set_cache_capacity(2);
        store.put_encrypted_object("one", b"one")?;
        store.put_encrypted_object("two", b"two")?;
        assert_eq!(store.decrypt_object("one")?, b"one");
        store.put_encrypted_object("three", b"three")?;
        assert!(store.cached_object("one").is_some());
        assert!(store.cached_object("two").is_none());
        assert!(store.cached_object("three").is_some());
        for index in 0..100 {
            assert!(store.object_key(&format!("missing-{index}")).is_err());
        }
        let data = store.data();
        assert_eq!(data.objects.len(), 2);
        assert_eq!(data.object_keys.len(), 2);
        assert_eq!(data.cache.as_ref().map(|cache| cache.recent.len()), Some(2));
        Ok(())
    }

    // Mutation: omit key eviction in ObjectRetirementHandle::retire.
    #[test]
    fn retirement_handle_erases_only_matching_cached_identity() -> Result<(), crate::SyncError> {
        let mut store = ObjectStore::new();
        let object = store.put_encrypted_object("wire", b"private")?;
        store.put_encrypted_object("shared", b"retained")?;
        let handle = store.retirement_handle("root");
        let commitment =
            ramflux_crypto::object_erasure_commitment("root", "wire", &object.manifest_hash);
        handle.retire(&[commitment]);
        assert!(matches!(store.decrypt_object("wire"), Err(crate::SyncError::ObjectErased)));
        assert!(store.cached_object("wire").is_none());
        assert!(!store.data().object_keys.contains_key("wire"));
        assert_eq!(store.decrypt_object("shared")?, b"retained");
        Ok(())
    }
}
