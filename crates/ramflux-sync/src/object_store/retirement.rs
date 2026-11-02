// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Weak retirement handles never prolong the lifetime of account key material.
use super::{EncryptedObject, ObjectStore, cache::CachePolicy};
use crate::SyncError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use zeroize::Zeroize;

#[derive(Clone, Default, Eq, PartialEq)]
pub(super) struct ObjectData {
    pub objects: BTreeMap<String, EncryptedObject>,
    pub object_keys: BTreeMap<String, [u8; 32]>,
    pub cache: Option<CachePolicy>,
    pub root: String,
    pub retired: BTreeSet<String>,
}

impl ObjectData {
    pub fn check_retired(&self, id: &str) -> Result<(), SyncError> {
        if self.retired.contains(id) { Err(SyncError::ObjectErased) } else { Ok(()) }
    }

    pub fn remove(&mut self, id: &str) {
        if let Some(mut object) = self.objects.remove(id) {
            object.ciphertext.zeroize();
        }
        if let Some(mut key) = self.object_keys.remove(id) {
            key.zeroize();
        }
        if let Some(cache) = self.cache.as_mut() {
            cache.recent.retain(|entry| entry != id);
        }
    }

    pub fn clear(&mut self) {
        for object in self.objects.values_mut() {
            object.ciphertext.zeroize();
        }
        for key in self.object_keys.values_mut() {
            key.zeroize();
        }
        self.objects.clear();
        self.object_keys.clear();
        if let Some(cache) = self.cache.as_mut() {
            cache.recent.clear();
        }
    }
}

impl Drop for ObjectData {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A storage commit can retire cached ciphertext and keys without borrowing its SDK owner.
#[derive(Clone)]
pub struct ObjectRetirementHandle(Weak<Mutex<ObjectData>>);

impl ObjectRetirementHandle {
    /// Retires only exact identities; a later verified replacement has a distinct commitment.
    pub fn retire(&self, commitments: &[String]) {
        let Some(state) = self.0.upgrade() else { return };
        let mut data = lock(&state);
        let ids: Vec<String> = data
            .objects
            .values()
            .filter(|object| {
                let commitment = ramflux_crypto::object_erasure_commitment(
                    &data.root,
                    &object.object_id,
                    &object.manifest_hash,
                );
                commitments.contains(&commitment)
            })
            .map(|object| object.object_id.clone())
            .collect();
        for id in ids {
            data.remove(&id);
            data.retired.insert(id);
        }
    }

    /// Discards the rebuildable cache if retirement delivery cannot be completed.
    pub fn clear(&self) {
        if let Some(state) = self.0.upgrade() {
            lock(&state).clear();
        }
    }
}

fn lock(state: &Mutex<ObjectData>) -> MutexGuard<'_, ObjectData> {
    // Recover the state after a panic so owned secrets can still be wiped.
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ObjectStore {
    pub(super) fn data(&self) -> MutexGuard<'_, ObjectData> {
        lock(&self.data)
    }

    /// Binds retirement commitments to the authenticated account root.
    pub fn retirement_handle(&self, root: &str) -> ObjectRetirementHandle {
        self.data().root = root.to_owned();
        ObjectRetirementHandle(Arc::downgrade(&self.data))
    }
}

impl Clone for ObjectStore {
    fn clone(&self) -> Self {
        Self { data: Arc::new(Mutex::new(self.data().clone())) }
    }
}

impl PartialEq for ObjectStore {
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.data, &other.data) {
            return true;
        }
        // Snapshot before locking the other store to avoid opposing lock order.
        let snapshot = self.data().clone();
        snapshot == *other.data()
    }
}
impl Eq for ObjectStore {}

impl std::fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.data();
        f.debug_struct("ObjectStore").field("cached_objects", &data.objects.len()).finish()
    }
}
