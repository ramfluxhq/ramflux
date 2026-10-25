// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind encrypted routes to verified root-qualified devices and recheck current revocation.
//!
//! Delivery rechecks one owner per wake. The periodic revocation sweep is batched and bounded:
//! each call checks at most [`PUSH_ROUTE_SWEEP_LIMIT`] owners in batches of
//! [`PUSH_ROUTE_AUTHORITY_BATCH`], resuming where the previous call stopped.
use super::{DevicePushRoute, NOTIFY_ROUTE_TABLE, NotifyRedbStore, routes};
use crate::{DeviceAuthKeyResponse, NodeCoreError};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
const OWNERS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_authority_v1");
/// Owners per authority lookup request.
pub const PUSH_ROUTE_AUTHORITY_BATCH: usize = 256;
/// Owners checked per revocation sweep call.
pub const PUSH_ROUTE_SWEEP_LIMIT: usize = 1_024;
pub(super) type RouteAuthorizer =
    dyn Fn(&[DeviceAuthKeyResponse]) -> Result<Vec<bool>, NodeCoreError> + Send + Sync;
fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}
fn context(target: &str) -> Vec<u8> {
    format!("ramflux.notify.route_owner.v1\0{target}").into_bytes()
}
impl NotifyRedbStore {
    /// Only feature-gated synthetic provider fixtures may omit a real device owner.
    #[cfg(feature = "itest-http")]
    pub fn allow_itest_unbound_push_routes(&mut self) {
        self.allow_itest_unbound_routes = true;
    }

    /// Installs a per-device authority lookup (each check is a batch of one).
    pub fn set_push_route_authorizer<F>(&mut self, authorize: F)
    where
        F: Fn(&DeviceAuthKeyResponse) -> Result<bool, NodeCoreError> + Send + Sync + 'static,
    {
        self.route_authorizer = Some(Box::new(move |owners: &[DeviceAuthKeyResponse]| {
            owners.iter().map(&authorize).collect()
        }));
    }

    /// Production installs an authoritative batched router lookup before accepting or
    /// dispatching routes. The result must hold one verdict per owner, in order.
    pub fn set_push_route_batch_authorizer<F>(&mut self, authorize: F)
    where
        F: Fn(&[DeviceAuthKeyResponse]) -> Result<Vec<bool>, NodeCoreError> + Send + Sync + 'static,
    {
        self.route_authorizer = Some(Box::new(authorize));
    }

    fn authorize_owners(
        &self,
        owners: &[DeviceAuthKeyResponse],
    ) -> Result<Vec<bool>, NodeCoreError> {
        let authorize = self
            .route_authorizer
            .as_ref()
            .ok_or_else(|| error("route authority lookup unavailable"))?;
        let verdicts = authorize(owners)?;
        if verdicts.len() != owners.len() {
            return Err(error("route authority lookup returned a mismatched batch"));
        }
        Ok(verdicts)
    }
    /// # Errors
    /// Refuses unverified, revoked, substituted or unavailable device authority.
    pub fn register_authenticated_push_route(
        &self,
        authority: &DeviceAuthKeyResponse,
        route: &DevicePushRoute,
    ) -> Result<(), NodeCoreError> {
        authority.authenticated_device_identity()?;
        if authority.target_delivery_id != route.device_delivery_id
            || !self
                .authorize_owners(std::slice::from_ref(authority))?
                .first()
                .copied()
                .unwrap_or(false)
        {
            return Err(NodeCoreError::Unauthorized("push route owner rejected".into()));
        }
        let now = crate::now_unix_seconds();
        if route.registered_at > now
            || route.expires_at <= now
            || route.expires_at > now.saturating_add(crate::PUSH_ROUTE_TTL_SECONDS)
        {
            return Err(NodeCoreError::Unauthorized("push route lifetime rejected".into()));
        }
        let binding = self.route_key.seal(
            &context(&route.device_delivery_id),
            &serde_json::to_vec(authority).map_err(error)?,
        )?;
        let txn = self.db.begin_write().map_err(error)?;
        let same_owner = self.same_registered_owner(&txn, authority)?;
        {
            let mut table = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
            let prior = table
                .get(route.device_delivery_id.as_str())
                .map_err(error)?
                .map(|v| v.value().to_vec());
            let mut values = prior
                .filter(|_| same_owner)
                .map(|bytes| routes::open(&self.route_key, &route.device_delivery_id, &bytes))
                .transpose()?
                .unwrap_or_default();
            values.retain(|prior| prior.provider != route.provider && prior.expires_at > now);
            values.push(route.clone());
            table
                .insert(
                    route.device_delivery_id.as_str(),
                    routes::seal(&self.route_key, &route.device_delivery_id, &values)?.as_slice(),
                )
                .map_err(error)?;
            txn.open_table(OWNERS)
                .map_err(error)?
                .insert(route.device_delivery_id.as_str(), binding.as_slice())
                .map_err(error)?;
        }
        txn.commit().map_err(error)
    }
    fn same_registered_owner(
        &self,
        txn: &redb::WriteTransaction,
        current: &DeviceAuthKeyResponse,
    ) -> Result<bool, NodeCoreError> {
        let bytes = txn
            .open_table(OWNERS)
            .map_err(error)?
            .get(current.target_delivery_id.as_str())
            .map_err(error)?
            .map(|value| value.value().to_vec());
        let Some(bytes) = bytes else {
            return Ok(false);
        };
        let previous: DeviceAuthKeyResponse = serde_json::from_slice(
            &self.route_key.open(&context(&current.target_delivery_id), &bytes)?,
        )
        .map_err(error)?;
        Ok(previous.authenticated_device_identity()? == current.authenticated_device_identity()?
            && previous.device_epoch == current.device_epoch
            && previous.branch_public_key == current.branch_public_key)
    }
    pub(super) fn prune_route_owners(&self) -> Result<(), NodeCoreError> {
        let txn = self.db.begin_write().map_err(error)?;
        {
            let routes = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
            let mut owners = txn.open_table(OWNERS).map_err(error)?;
            let keys = owners
                .iter()
                .map_err(error)?
                .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(error))
                .collect::<Result<Vec<_>, _>>()?;
            for key in keys {
                if routes.get(key.as_str()).map_err(error)?.is_none() {
                    owners.remove(key.as_str()).map_err(error)?;
                }
            }
        }
        txn.commit().map_err(error)
    }
    fn owner_binding(&self, target: &str) -> Result<Option<Vec<u8>>, NodeCoreError> {
        let txn = self.db.begin_read().map_err(error)?;
        let table = match txn.open_table(OWNERS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(other) => return Err(error(other)),
        };
        Ok(table.get(target).map_err(error)?.map(|value| value.value().to_vec()))
    }

    fn open_binding(
        &self,
        target: &str,
        bytes: &[u8],
    ) -> Result<DeviceAuthKeyResponse, NodeCoreError> {
        serde_json::from_slice(&self.route_key.open(&context(target), bytes)?).map_err(error)
    }

    /// Deletes a revoked owner's routes, but only if the encrypted binding is unchanged, so a
    /// delayed lookup cannot delete a route that was re-registered meanwhile.
    fn revoke_if_unchanged(&self, target: &str, bytes: &[u8]) -> Result<bool, NodeCoreError> {
        let txn = self.db.begin_write().map_err(error)?;
        let removed;
        {
            let mut owners = txn.open_table(OWNERS).map_err(error)?;
            removed = owners.get(target).map_err(error)?.is_some_and(|v| v.value() == bytes);
            if removed {
                owners.remove(target).map_err(error)?;
                txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?.remove(target).map_err(error)?;
            }
        }
        txn.commit().map_err(error)?;
        Ok(removed)
    }

    pub(super) fn authorize_push_route(&self, target: &str) -> Result<bool, NodeCoreError> {
        if self.route_authorizer.is_none() {
            return Ok(true);
        }
        let Some(bytes) = self.owner_binding(target)? else {
            return Ok(self.allow_itest_unbound_routes);
        };
        let authority = self.open_binding(target, &bytes)?;
        if self
            .authorize_owners(std::slice::from_ref(&authority))?
            .first()
            .copied()
            .unwrap_or(false)
        {
            return Ok(true);
        }
        self.revoke_if_unchanged(target, &bytes)?;
        Ok(false)
    }

    /// Checks up to [`PUSH_ROUTE_SWEEP_LIMIT`] owners in batched lookups, continuing from the
    /// previous call, and deletes revoked owners' routes. In production it also deletes legacy
    /// routes that have no verified owner: they can never be delivered.
    /// # Errors
    /// Unavailable authority defers deletion; it never authorizes provider delivery.
    pub fn sweep_push_route_revocations(&self) -> Result<usize, NodeCoreError> {
        if self.route_authorizer.is_none() {
            return Ok(0);
        }
        let mut removed = self.remove_ownerless_routes()?;
        let start = self.revocation_cursor.lock().map_err(error)?.clone();
        let txn = self.db.begin_read().map_err(error)?;
        let mut owners = Vec::new();
        if let Ok(table) = txn.open_table(OWNERS) {
            let rows = match start.as_deref() {
                Some(start) => table
                    .range::<&str>((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded)),
                None => table.range::<&str>(..),
            }
            .map_err(error)?;
            for row in rows.take(PUSH_ROUTE_SWEEP_LIMIT) {
                let (key, value) = row.map_err(error)?;
                owners.push((key.value().to_owned(), value.value().to_vec()));
            }
        }
        drop(txn);
        *self.revocation_cursor.lock().map_err(error)? = (owners.len() == PUSH_ROUTE_SWEEP_LIMIT)
            .then(|| owners.last().map(|(key, _)| key.clone()))
            .flatten();
        for batch in owners.chunks(PUSH_ROUTE_AUTHORITY_BATCH) {
            let authorities = batch
                .iter()
                .map(|(target, bytes)| self.open_binding(target, bytes))
                .collect::<Result<Vec<_>, _>>()?;
            for ((target, bytes), live) in batch.iter().zip(self.authorize_owners(&authorities)?) {
                if !live && self.revoke_if_unchanged(target, bytes)? {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// Runs once per process: production never creates ownerless rows, so only legacy rows
    /// from before ownership binding are removed.
    fn remove_ownerless_routes(&self) -> Result<usize, NodeCoreError> {
        if self.allow_itest_unbound_routes
            || self.ownerless_routes_cleared.load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(0);
        }
        let txn = self.db.begin_write().map_err(error)?;
        let mut removed = 0;
        {
            let owners = txn.open_table(OWNERS).map_err(error)?;
            let mut routes = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
            let mut ownerless = Vec::new();
            for row in routes.iter().map_err(error)? {
                let (key, _) = row.map_err(error)?;
                if owners.get(key.value()).map_err(error)?.is_none() {
                    ownerless.push(key.value().to_owned());
                }
            }
            for key in ownerless {
                routes.remove(key.as_str()).map_err(error)?;
                removed += 1;
            }
        }
        txn.commit().map_err(error)?;
        self.ownerless_routes_cleared.store(true, std::sync::atomic::Ordering::Release);
        Ok(removed)
    }
}
