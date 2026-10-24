// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable signed identity-set publication under the registry's existing single writer.
use crate::{DeviceSetPublishRequest, NodeCoreError, RouterCore, RouterRedbStore};
impl RouterCore {
    /// Persist a validated candidate before publishing its epoch or revocations to readers.
    /// # Errors
    /// Rejects invalid records, monotonic conflicts or durable storage failures without mutation.
    pub fn publish_signed_device_set(
        &self,
        request: &DeviceSetPublishRequest,
        store: &RouterRedbStore,
    ) -> Result<ramflux_protocol::SignedDeviceSetRecord, NodeCoreError> {
        let mut control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut candidate = control.mvp1_identities.clone();
        candidate.publish_signed_device_set(request)?;
        store.record_identity_registry(&candidate)?;
        control.mvp1_identities = candidate;
        self.refresh_migration_read_snapshot_from_control(&control);
        Ok(request.record.clone())
    }
    /// Persist the current registry under its writer lock so concurrent metadata updates cannot
    /// overwrite a newer signed epoch using a previously captured snapshot.
    /// # Errors
    /// Returns durable storage errors.
    pub fn persist_identity_registry(&self, store: &RouterRedbStore) -> Result<(), NodeCoreError> {
        let control = self.control.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.record_identity_registry(&control.mvp1_identities)
    }
    /// Return the full unfiltered root-signed record; no node-authored revocation claims.
    #[must_use]
    pub fn signed_device_set(
        &self,
        commitment: &str,
    ) -> Option<ramflux_protocol::SignedDeviceSetRecord> {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mvp1_identities
            .signed_device_set(commitment)
            .cloned()
    }
}
