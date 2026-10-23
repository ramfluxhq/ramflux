// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optional bounded LRU for persisted account objects. Default in-process stores retain all data.

use super::{EncryptedObject, ObjectStore};
use std::collections::VecDeque;
use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CachePolicy {
    pub capacity: usize,
    pub(super) recent: VecDeque<String>,
}

impl ObjectStore {
    /// Bounds this store's rebuildable cache. Callers must provide durable fallback on a miss.
    pub fn set_cache_capacity(&mut self, capacity: usize) {
        self.cache = std::cell::RefCell::new(Some(CachePolicy {
            capacity: capacity.max(1),
            recent: self.objects.keys().cloned().collect(),
        }));
        self.evict_cached();
    }

    #[must_use]
    pub fn cache_capacity(&self) -> Option<usize> {
        self.cache.borrow().as_ref().map(|cache| cache.capacity)
    }

    #[must_use]
    pub fn cached_object(&self, id: &str) -> Option<&EncryptedObject> {
        let object = self.objects.get(id)?;
        self.touch_cached(id);
        Some(object)
    }

    pub fn cache_persisted_object(&mut self, object: EncryptedObject, key: Option<[u8; 32]>) {
        let id = object.object_id.clone();
        self.objects.insert(id.clone(), object);
        if let Some(key) = key {
            self.object_keys.insert(id.clone(), key);
        }
        self.touch_cached(&id);
        self.evict_cached();
    }

    pub(super) fn touch_cached(&self, id: &str) {
        if !self.objects.contains_key(id) {
            return;
        }
        if let Some(cache) = self.cache.borrow_mut().as_mut() {
            cache.recent.retain(|existing| existing != id);
            cache.recent.push_back(id.to_owned());
        }
    }

    pub(super) fn evict_cached(&mut self) {
        if let Some(cache) = self.cache.get_mut().as_mut() {
            while self.objects.len() > cache.capacity {
                let Some(id) = cache.recent.pop_front() else {
                    break;
                };
                self.objects.remove(&id);
                if let Some(mut key) = self.object_keys.remove(&id) {
                    key.zeroize();
                }
            }
            self.object_keys.retain(|id, key| {
                if self.objects.contains_key(id) {
                    true
                } else {
                    key.zeroize();
                    false
                }
            });
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
        assert_eq!(store.objects.len(), 2);
        assert_eq!(store.object_keys.len(), 2);
        assert_eq!(store.cache.borrow().as_ref().map(|cache| cache.recent.len()), Some(2));
        Ok(())
    }
}
