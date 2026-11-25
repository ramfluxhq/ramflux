// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route state changes that come from central push answers (N10, N11, A5).
//!
//! Each change acts only on the exact snapshot the wake was built from: the same route tag,
//! the same generation and the same sealed token bytes. A newer registration always carries
//! new sealed bytes and a new generation, so a late answer never touches it.

use super::{NOTIFY_ROUTE_TABLE, NodeCoreError, NotifyRedbStore, route_selection, routes};
use crate::push_handoff::{CentralClass, Served};
use redb::{ReadableDatabase, ReadableTable};

/// What a central answer does to one stored route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CentralEdit {
    /// Delete the route (`invalid_route` with `at` later than registration).
    Remove,
    /// Mark the route as needing a fresh seal (`reseal`).
    MarkReseal,
    /// Pause the route until the given Unix ms time (`unserved`).
    Pause { until_ms: u64 },
}

/// Identity of the snapshot a central answer refers to.
#[derive(Clone, Copy, Debug)]
pub struct CentralRouteSnapshot<'a> {
    pub route_tag: &'a str,
    pub generation: u64,
    pub sealed_token: &'a str,
}

fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}

impl NotifyRedbStore {
    /// `invalid_route` with time `at_ms` (A5). Deletes the route only when its registration time
    /// is strictly earlier than `at_ms`. Returns `true` when the route was deleted.
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_route_invalidate(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        at_ms: u64,
    ) -> Result<bool, NodeCoreError> {
        self.central_route_edit(device_delivery_id, snapshot, |route| {
            (route.registered_at_ms < at_ms).then_some(CentralEdit::Remove)
        })
    }

    /// `reseal`: the route stops receiving wakes until the device registers again.
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_route_mark_reseal(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
    ) -> Result<bool, NodeCoreError> {
        self.central_route_edit(device_delivery_id, snapshot, |_| Some(CentralEdit::MarkReseal))
    }

    /// `unserved`: pause the route until `until_ms` (the node uses 3600 s).
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_route_pause(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        until_ms: u64,
    ) -> Result<bool, NodeCoreError> {
        self.central_route_edit(device_delivery_id, snapshot, |_| {
            Some(CentralEdit::Pause { until_ms })
        })
    }

    fn central_route_edit(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        decide: impl FnOnce(&super::DevicePushRoute) -> Option<CentralEdit>,
    ) -> Result<bool, NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        self.resume_route_mutation(device_delivery_id)?;
        let txn = self.db.begin_write().map_err(error)?;
        let edited = {
            let mut table = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
            let prior = table
                .get(device_delivery_id)
                .map_err(error)?
                .map(|value| value.value().to_vec());
            let mut values = match prior {
                Some(prior) => routes::open(&self.route_key, device_delivery_id, &prior)?,
                None => Vec::new(),
            };
            let index = values.iter().position(|route| {
                route.sealed
                    && route.route_tag == snapshot.route_tag
                    && route.route_generation == snapshot.generation
                    && route.token == snapshot.sealed_token
            });
            let edit = index
                .and_then(|index| values.get(index))
                .and_then(|route| decide(route));
            match (index, edit) {
                (Some(index), Some(CentralEdit::Remove)) => {
                    values.remove(index);
                }
                (Some(index), Some(CentralEdit::MarkReseal)) => {
                    if let Some(route) = values.get_mut(index) {
                        route.needs_reseal = true;
                    }
                }
                (Some(index), Some(CentralEdit::Pause { until_ms })) => {
                    if let Some(route) = values.get_mut(index) {
                        route.unserved_until_ms = until_ms;
                    }
                }
                _ => {
                    drop(table);
                    txn.abort().map_err(error)?;
                    return Ok(false);
                }
            }
            if values.is_empty() {
                table.remove(device_delivery_id).map_err(error)?;
            } else {
                table
                    .insert(
                        device_delivery_id,
                        routes::seal(&self.route_key, device_delivery_id, &values)?.as_slice(),
                    )
                    .map_err(error)?;
            }
            true
        };
        self.commit_route_transaction(txn, device_delivery_id)?;
        Ok(edited)
    }

    /// Routes a central wake may use for `device_delivery_id`, after the same owner check as the
    /// direct path and the served and state rules of A6.4 (see `select_central_routes`).
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn central_candidate_routes(
        &self,
        device_delivery_id: &str,
        class: CentralClass,
        served: &Served,
        now_ms: u64,
    ) -> Result<Vec<super::DevicePushRoute>, NodeCoreError> {
        let now_s = crate::now_unix_seconds();
        let routes = self
            .load_notify_routes(device_delivery_id)?
            .into_iter()
            .filter(|route| route.expires_at > now_s)
            .collect::<Vec<_>>();
        let routes = if routes.is_empty() || self.authorize_push_route(device_delivery_id)? {
            routes
        } else {
            Vec::new()
        };
        Ok(route_selection::select_central_routes(routes, class, served, now_ms))
    }
}
