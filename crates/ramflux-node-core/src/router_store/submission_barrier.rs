// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Send-safe striped admission leases serialize WAL/redb submissions with home cutover.
use super::{InboxEntry, NodeCoreError, RouterRedbStore};
use ramflux_protocol::home_migration::{DeliveryMapEntry, Refusal};
use std::{
    collections::BTreeSet,
    hash::{Hash, Hasher},
    sync::Arc,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
pub(super) const STRIPES: usize = 64;
fn stripe(target: &str) -> usize {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut hash);
    usize::try_from(hash.finish() % STRIPES as u64).unwrap_or(0)
}
fn busy() -> NodeCoreError {
    NodeCoreError::HomeMigration(Refusal::MigrationInProgress)
}
impl RouterRedbStore {
    pub(crate) fn submission_permit(
        &self,
        entry: Option<&InboxEntry>,
    ) -> Result<Option<OwnedRwLockReadGuard<()>>, NodeCoreError> {
        let Some(entry) = entry else {
            return Ok(None);
        };
        let permit = Arc::clone(&self.submission_gates[stripe(&entry.target_delivery_id)])
            .try_read_owned()
            .map_err(|_| busy())?;
        if !self.home_migration_target_active(&entry.target_delivery_id)? {
            return Err(busy());
        }
        Ok(Some(permit))
    }
    pub(super) async fn submission_permit_async(
        &self,
        entry: Option<&InboxEntry>,
    ) -> Result<Option<OwnedRwLockReadGuard<()>>, NodeCoreError> {
        let Some(entry) = entry else {
            return Ok(None);
        };
        let permit = Arc::clone(&self.submission_gates[stripe(&entry.target_delivery_id)])
            .read_owned()
            .await;
        if !self.home_migration_target_active(&entry.target_delivery_id)? {
            return Err(busy());
        }
        Ok(Some(permit))
    }
    /// Retry instead of blocking a runtime while a prior append is awaiting its durable ACK.
    pub(crate) fn migration_submission_barrier(
        &self,
        map: &[DeliveryMapEntry],
    ) -> Result<Vec<OwnedRwLockWriteGuard<()>>, NodeCoreError> {
        if map.len() > ramflux_protocol::custody::MAX_ROSTER {
            return Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused));
        }
        map.iter()
            .map(|d| stripe(&d.target_delivery_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|index| {
                Arc::clone(&self.submission_gates[index]).try_write_owned().map_err(|_| busy())
            })
            .collect()
    }
}
