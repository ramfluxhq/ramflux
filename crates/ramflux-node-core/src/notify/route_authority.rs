// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bind encrypted routes to verified root-qualified devices and recheck current revocation.
use super::{DevicePushRoute, NOTIFY_ROUTE_TABLE, NotifyRedbStore, routes};
use crate::{DeviceAuthKeyResponse, NodeCoreError};
use redb::{ReadableTable, TableDefinition};
const OWNERS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_route_authority_v1");
pub(super) type RouteAuthorizer =
    dyn Fn(&DeviceAuthKeyResponse) -> Result<bool, NodeCoreError> + Send + Sync;
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

    /// Production installs an authoritative router lookup before accepting or dispatching routes.
    pub fn set_push_route_authorizer<F>(&mut self, authorize: F)
    where
        F: Fn(&DeviceAuthKeyResponse) -> Result<bool, NodeCoreError> + Send + Sync + 'static,
    {
        self.route_authorizer = Some(Box::new(authorize));
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
                .route_authorizer
                .as_ref()
                .ok_or_else(|| error("route authority lookup unavailable"))?(
                authority
            )?
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
    pub(super) fn authorize_push_route(&self, target: &str) -> Result<bool, NodeCoreError> {
        let Some(authorize) = &self.route_authorizer else {
            return Ok(true);
        };
        let txn = self.db.begin_write().map_err(error)?;
        let bytes = txn
            .open_table(OWNERS)
            .map_err(error)?
            .get(target)
            .map_err(error)?
            .map(|v| v.value().to_vec());
        txn.abort().map_err(error)?;
        let Some(bytes) = bytes else {
            return Ok(self.allow_itest_unbound_routes);
        };
        let authority = serde_json::from_slice(&self.route_key.open(&context(target), &bytes)?)
            .map_err(error)?;
        if authorize(&authority)? {
            return Ok(true);
        }
        // Compare the encrypted binding so a delayed lookup cannot delete a rotated route.
        let txn = self.db.begin_write().map_err(error)?;
        {
            let mut owners = txn.open_table(OWNERS).map_err(error)?;
            let unchanged = owners.get(target).map_err(error)?.is_some_and(|v| v.value() == bytes);
            if unchanged {
                owners.remove(target).map_err(error)?;
                txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?.remove(target).map_err(error)?;
            }
        }
        txn.commit().map_err(error)?;
        Ok(false)
    }
    /// # Errors
    /// Unavailable authority defers deletion; it never authorizes provider delivery.
    pub fn sweep_push_route_revocations(&self) -> Result<(), NodeCoreError> {
        let txn = self.db.begin_write().map_err(error)?;
        let targets = txn
            .open_table(OWNERS)
            .map_err(error)?
            .iter()
            .map_err(error)?
            .map(|row| row.map(|(key, _)| key.value().to_owned()).map_err(error))
            .collect::<Result<Vec<_>, _>>()?;
        txn.abort().map_err(error)?;
        for target in targets {
            self.authorize_push_route(&target)?;
        }
        Ok(())
    }
}
