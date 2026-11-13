// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded writer admission isolates unverified traffic and limits each authenticated root.
use super::GatewayRedbStore;
use crate::NodeCoreError;
use std::{
    collections::BTreeSet,
    sync::{Arc, atomic::Ordering},
};

pub const GATEWAY_NETWORK_WRITE_LIMIT: usize = 8;
const UNAUTHENTICATED_LIMIT: usize = 2;

#[derive(Default)]
pub(super) struct Pending {
    roots: BTreeSet<String>,
    unauthenticated: usize,
}

/// A queued/running network write. Drop releases its root or unauthenticated slot.
pub struct GatewayWriteAdmission {
    store: Arc<GatewayRedbStore>,
    root: Option<String>,
}
impl Drop for GatewayWriteAdmission {
    fn drop(&mut self) {
        // Recover bookkeeping even when an unrelated caller poisoned this mutex.
        let mut pending =
            self.store.network_admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(root) = &self.root {
            pending.roots.remove(root);
        } else {
            pending.unauthenticated = pending.unauthenticated.saturating_sub(1);
        }
    }
}

/// Exclusive management write, independent of the network pools.
pub struct GatewayManagementAdmission<'a>(&'a GatewayRedbStore);
impl Drop for GatewayManagementAdmission<'_> {
    fn drop(&mut self) {
        self.0.management_pending.store(false, Ordering::Release);
    }
}

impl GatewayRedbStore {
    /// Admit unverified AUTH work from its separate two-operation budget.
    /// # Errors
    /// Returns retryable busy without queueing a waiter when that budget is full.
    pub fn try_admit_async_write(self: &Arc<Self>) -> Result<GatewayWriteAdmission, NodeCoreError> {
        self.admit_network(None)
    }

    /// Admit at most one operation per verified root, across all its sessions/devices.
    /// # Errors
    /// Returns retryable busy if that root or all eight authenticated slots are occupied.
    pub fn try_admit_root_write(
        self: &Arc<Self>,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
    ) -> Result<GatewayWriteAdmission, NodeCoreError> {
        self.admit_network(Some(source.root_commitment()))
    }

    fn admit_network(
        self: &Arc<Self>,
        root: Option<&str>,
    ) -> Result<GatewayWriteAdmission, NodeCoreError> {
        let mut pending =
            self.network_admission.lock().map_err(|_| NodeCoreError::GatewayWriterBusy)?;
        if let Some(root) = root {
            if pending.roots.len() >= GATEWAY_NETWORK_WRITE_LIMIT || pending.roots.contains(root) {
                return Err(NodeCoreError::GatewayWriterBusy);
            }
            pending.roots.insert(root.to_owned());
        } else {
            if pending.unauthenticated >= UNAUTHENTICATED_LIMIT {
                return Err(NodeCoreError::GatewayWriterBusy);
            }
            pending.unauthenticated += 1;
        }
        Ok(GatewayWriteAdmission { store: Arc::clone(self), root: root.map(str::to_owned) })
    }

    /// Current queued/running network operations, including unverified AUTH work.
    #[must_use]
    pub fn pending_network_writes(&self) -> usize {
        let pending =
            self.network_admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.roots.len() + pending.unauthenticated
    }

    /// Admit one test-feature management transaction without waiting.
    /// # Errors
    /// Returns retryable busy when another management transaction is in flight.
    pub fn try_admit_management_write(
        &self,
    ) -> Result<GatewayManagementAdmission<'_>, NodeCoreError> {
        self.management_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| NodeCoreError::GatewayWriterBusy)?;
        Ok(GatewayManagementAdmission(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn noisy_root_and_unverified_work_cannot_consume_other_root_slots()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let store = Arc::new(GatewayRedbStore::open(directory.path().join("gateway.redb"))?);
        let root = ramflux_crypto::create_identity_root("noisy", [1; 32]);
        let device =
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "one")?;
        let other_device =
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "two")?;
        let first = store.try_admit_root_write(&device)?;
        assert!(
            matches!(
                store.try_admit_root_write(&other_device),
                Err(NodeCoreError::GatewayWriterBusy)
            ),
            "another session/device of the same root must be busy"
        );
        let unverified = [store.try_admit_async_write()?, store.try_admit_async_write()?];
        assert!(
            matches!(store.try_admit_async_write(), Err(NodeCoreError::GatewayWriterBusy)),
            "unverified work must have its own bound"
        );
        let mut others = Vec::new();
        for seed in 2..=8 {
            let root = ramflux_crypto::create_identity_root("other", [seed; 32]);
            let device =
                ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "one")?;
            others.push(store.try_admit_root_write(&device)?);
        }
        assert_eq!(
            store.pending_network_writes(),
            10,
            "authenticated slots must survive unverified saturation"
        );
        drop((first, unverified, others));
        assert_eq!(store.pending_network_writes(), 0, "all slots must be released by RAII");
        let _retry = store.try_admit_root_write(&device)?;
        Ok(())
    }
}
