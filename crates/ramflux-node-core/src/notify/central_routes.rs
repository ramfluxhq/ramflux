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
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get(index)?;
            if route.registered_at_ms < at_ms {
                values.remove(index);
                Some(())
            } else {
                None
            }
        })
        .map(|edited| edited.is_some())
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
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            values.get_mut(index)?.needs_reseal = true;
            Some(())
        })
        .map(|edited| edited.is_some())
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
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            values.get_mut(index)?.unserved_until_ms = until_ms;
            Some(())
        })
        .map(|edited| edited.is_some())
    }

    /// Returns the first-send time of `queue_id` on this route, recording `now_ms` when the
    /// entry has none yet. The value is stored in the route row, so it survives a restart
    /// (N4). Entries whose window (`max_age_ms`) has passed are pruned first. `Ok(None)` means
    /// the route is gone or changed.
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_first_send(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        queue_id: &str,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Result<Option<(u64, bool)>, NodeCoreError> {
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get_mut(index)?;
            route
                .central_first_send
                .retain(|entry| entry.first_send_ms.saturating_add(max_age_ms) >= now_ms);
            if let Some(existing) =
                route.central_first_send.iter().find(|entry| entry.queue_id == queue_id)
            {
                return Some((existing.first_send_ms, existing.dropped));
            }
            route.central_first_send.push(super::device_route::CentralFirstSend {
                queue_id: queue_id.to_owned(),
                first_send_ms: now_ms,
                dropped: false,
            });
            Some((now_ms, false))
        })
    }

    /// Marks one queue entry as dropped for this route (centre `rejected`, plan section 5): it
    /// is never resent. Returns `false` when the route is gone.
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_drop_wake(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        queue_id: &str,
        now_ms: u64,
    ) -> Result<bool, NodeCoreError> {
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get_mut(index)?;
            if let Some(existing) =
                route.central_first_send.iter_mut().find(|entry| entry.queue_id == queue_id)
            {
                existing.dropped = true;
            } else {
                route.central_first_send.push(super::device_route::CentralFirstSend {
                    queue_id: queue_id.to_owned(),
                    first_send_ms: now_ms,
                    dropped: true,
                });
            }
            Some(())
        })
        .map(|edited| edited.is_some())
    }

    /// Runs `edit` on the exact route the snapshot names. `edit` returns `None` to leave the row
    /// unchanged. Returns the value of `edit`, or `None` when the route was not found.
    fn central_route_update<T>(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        edit: impl FnOnce(&mut Vec<super::DevicePushRoute>, usize) -> Option<T>,
    ) -> Result<Option<T>, NodeCoreError> {
        let _writer = self
            .local_writer
            .try_lock()
            .map_err(|_| crate::send_authority::SendAuthorityError::Busy)?;
        self.resume_route_mutation(device_delivery_id)?;
        let txn = self.db.begin_write().map_err(error)?;
        let outcome = {
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
            let outcome = index.and_then(|index| edit(&mut values, index));
            if outcome.is_some() {
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
            }
            outcome
        };
        if outcome.is_some() {
            self.commit_route_transaction(txn, device_delivery_id)?;
        } else {
            txn.abort().map_err(error)?;
        }
        Ok(outcome)
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
