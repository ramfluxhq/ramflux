// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Snapshot resources follow all private erasures, including shared-reference removal.
use super::{AccountDb, ObjectResourceRetirement, StorageError};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub(super) type Resources = Arc<Mutex<BTreeMap<String, (i64, ObjectResourceRetirement)>>>;

/// Keeps a snapshot retirement callback registered until its owner releases it.
pub struct PrivacyResourceRegistration {
    resources: Resources,
    id: String,
}
impl Drop for PrivacyResourceRegistration {
    fn drop(&mut self) {
        self.resources.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&self.id);
    }
}

pub(super) fn retire(resources: &Resources, generation: i64) -> Result<(), StorageError> {
    let selected = resources
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(_, (expected, _))| *expected != generation)
        .map(|(id, (_, callback))| (id.clone(), Arc::clone(callback)))
        .collect::<Vec<_>>();
    for (id, callback) in selected {
        callback()?;
        resources.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
    }
    Ok(())
}

impl AccountDb {
    /// # Errors
    /// Returns storage errors while reading the snapshot's private-erasure generation.
    pub fn privacy_erasure_generation(&self) -> Result<i64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |r| r.get(0),
        )?)
    }

    /// # Errors
    /// Refuses a stale snapshot and registers cleanup against the current writer generation.
    pub fn register_privacy_resource(
        &self,
        id: &str,
        expected: i64,
        callback: ObjectResourceRetirement,
    ) -> Result<PrivacyResourceRegistration, StorageError> {
        let resources = Arc::clone(&self.object_retirement.generations);
        let mut entries = resources.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let current: i64 = self.erasure_authority.as_ref().unwrap_or(&self.connection).query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if current != expected {
            return Err(StorageError::ObjectErased);
        }
        entries.insert(id.to_owned(), (expected, callback));
        drop(entries);
        Ok(PrivacyResourceRegistration { resources, id: id.to_owned() })
    }
}
