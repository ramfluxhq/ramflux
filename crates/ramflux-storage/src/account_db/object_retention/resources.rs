// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-time retirement of runtime-owned resources, independent of SDK mutable borrows.
use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub type ObjectResourceRetirement = Arc<dyn Fn() -> Result<(), StorageError> + Send + Sync>;
pub(super) type Resources = Arc<Mutex<BTreeMap<String, (String, ObjectResourceRetirement)>>>;

pub(super) fn retire(
    resources: &Resources,
    commitments: Option<&[String]>,
) -> Result<(), StorageError> {
    let selected = {
        let entries = resources.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .iter()
            .filter(|(_, (digest, _))| commitments.is_none_or(|ids| ids.contains(digest)))
            .map(|(id, (_, callback))| (id.clone(), Arc::clone(callback)))
            .collect::<Vec<_>>()
    };
    for (id, callback) in selected {
        callback()?;
        resources.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&id);
    }
    Ok(())
}

impl AccountDb {
    /// # Errors
    /// Registers a runtime-owned resource against a current, exact payload identity.
    pub fn register_object_resource(
        &self,
        resource_id: &str,
        wire: &str,
        manifest: &str,
        retire: ObjectResourceRetirement,
    ) -> Result<(), StorageError> {
        self.check_object_identity(wire, manifest)?;
        let digest = object_erasure_commitment(&self.principal_commitment, wire, manifest);
        self.object_retirement
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(resource_id.to_owned(), (digest, retire));
        Ok(())
    }

    pub fn unregister_object_resource(&self, resource_id: &str) {
        self.object_retirement
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(resource_id);
    }
}
