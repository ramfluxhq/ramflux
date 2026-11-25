// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route state and per-wake records for central push (N4, N10, N11, A5, A8).
//!
//! Each route change acts only on the exact snapshot the wake was built from: the same route
//! tag, the same generation and the same sealed token bytes. A newer registration always carries
//! new sealed bytes and a new generation, so a late answer never touches it.

use super::device_route::CentralFirstSend;
use super::{
    DevicePushRoute, NOTIFY_ROUTE_TABLE, NodeCoreError, NotifyDeliveryAction, NotifyQueueEntry,
    NotifyRedbStore, ProviderPushAttempt, PushProviderKind, encrypted_bucket, route_selection,
    routes,
};
use crate::push_handoff::{CentralClass, Served};
use redb::{ReadableDatabase, ReadableTable};

/// Most first-send records kept per route (M1). When full, the oldest settled record is dropped;
/// if none is settled, the new wake is settled without a send.
pub const CENTRAL_FIRST_SEND_LIMIT: usize = 256;

/// State of one queue entry on one route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstSendState {
    /// Not yet settled; `first_send_ms` fixes the deadline (A1.2).
    Open { first_send_ms: u64 },
    /// Settled for this route; never sent again.
    Settled,
    /// The route's record list is full of unsettled entries; this wake is not sent.
    Full,
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
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get(index)?;
            if route.registered_at_ms < at_ms {
                values.remove(index);
                Some(((), true))
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
            Some(((), true))
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
            Some(((), true))
        })
        .map(|edited| edited.is_some())
    }

    /// Returns the state of `queue_id` on this route, creating an open record the first time.
    /// Records are pruned only after the queue entry's own expiry (`expires_s`), so a deferral
    /// never restarts the clock (H4). A new record is written only when none exists (M1).
    /// `Ok(None)` means the route is gone or changed.
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_first_send(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        queue_id: &str,
        now_ms: u64,
        expires_s: u64,
    ) -> Result<Option<FirstSendState>, NodeCoreError> {
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get_mut(index)?;
            let now_seconds = now_ms / 1000;
            let before = route.central_first_send.len();
            route.central_first_send.retain(|entry| entry.expires_s > now_seconds);
            let pruned = route.central_first_send.len() != before;
            if let Some(existing) =
                route.central_first_send.iter().find(|entry| entry.queue_id == queue_id)
            {
                let state = if existing.settled {
                    FirstSendState::Settled
                } else {
                    FirstSendState::Open { first_send_ms: existing.first_send_ms }
                };
                return Some((state, pruned));
            }
            if route.central_first_send.len() >= CENTRAL_FIRST_SEND_LIMIT {
                let oldest_settled = route
                    .central_first_send
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.settled)
                    .min_by_key(|(_, entry)| entry.first_send_ms)
                    .map(|(position, _)| position);
                match oldest_settled {
                    Some(position) => {
                        route.central_first_send.remove(position);
                    }
                    None => return Some((FirstSendState::Full, pruned)),
                }
            }
            route.central_first_send.push(CentralFirstSend {
                queue_id: queue_id.to_owned(),
                first_send_ms: now_ms,
                expires_s,
                settled: false,
            });
            Some((FirstSendState::Open { first_send_ms: now_ms }, true))
        })
    }

    /// Settles `queue_id` on this route: it is never sent to this route again (H2, H4).
    ///
    /// # Errors
    /// Returns storage errors, and `Busy` when another local write holds the writer.
    pub fn central_settle(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        queue_id: &str,
    ) -> Result<(), NodeCoreError> {
        self.central_route_update(device_delivery_id, snapshot, |values, index| {
            let route = values.get_mut(index)?;
            let changed = match route
                .central_first_send
                .iter_mut()
                .find(|entry| entry.queue_id == queue_id)
            {
                Some(entry) => {
                    let changed = !entry.settled;
                    entry.settled = true;
                    changed
                }
                None => false,
            };
            Some(((), changed))
        })
        .map(|_| ())
    }

    /// Records one settlement attempt for a queue entry, so it leaves the pending set once every
    /// candidate route has settled (H2, A8.6).
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn central_record_entry_settled(
        &self,
        entry: &NotifyQueueEntry,
        provider: PushProviderKind,
        accepted: bool,
    ) -> Result<(), NodeCoreError> {
        let attempt = ProviderPushAttempt {
            queue_id: entry.queue_id.clone(),
            device_delivery_id: entry.device_delivery_id.clone(),
            provider,
            push_alias_hash: entry.push_alias_hash.clone(),
            collapse_key_hash: encrypted_bucket(&entry.wake, &entry.queue_id),
            delivery_class: entry.wake.delivery_class.clone(),
            action: if accepted {
                NotifyDeliveryAction::Accept
            } else {
                NotifyDeliveryAction::ProviderRejected
            },
            sent_at: crate::now_unix_seconds(),
            accepted,
            error_class: (!accepted).then(|| "central_settled_without_acceptance".to_owned()),
        };
        self.record_provider_attempt(attempt)
    }

    /// Runs `edit` on the exact route the snapshot names. `edit` returns `None` when the route
    /// is not changed by it and `Some((value, changed))` otherwise. The row is written only when
    /// `changed` is true, so a read of a settled or existing record never commits (M1).
    /// Returns `Some(value)` when `edit` returned `Some`, `None` when the route was not found or
    /// `edit` declined.
    fn central_route_update<T>(
        &self,
        device_delivery_id: &str,
        snapshot: CentralRouteSnapshot<'_>,
        edit: impl FnOnce(&mut Vec<DevicePushRoute>, usize) -> Option<(T, bool)>,
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
            match index.and_then(|index| edit(&mut values, index)) {
                None => None,
                Some((value, changed)) => {
                    if changed {
                        if values.is_empty() {
                            table.remove(device_delivery_id).map_err(error)?;
                        } else {
                            table
                                .insert(
                                    device_delivery_id,
                                    routes::seal(&self.route_key, device_delivery_id, &values)?
                                        .as_slice(),
                                )
                                .map_err(error)?;
                        }
                    }
                    Some((value, changed))
                }
            }
        };
        match outcome {
            None => {
                txn.abort().map_err(error)?;
                Ok(None)
            }
            Some((value, changed)) => {
                if changed {
                    self.commit_route_transaction(txn, device_delivery_id)?;
                } else {
                    txn.abort().map_err(error)?;
                }
                Ok(Some(value))
            }
        }
    }

    /// Earliest end of a `unserved` pause on this device's sealed routes that is still in the
    /// future (Unix ms). `None` when no route is paused.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn central_next_pause_expiry(
        &self,
        device_delivery_id: &str,
        now_ms: u64,
    ) -> Result<Option<u64>, NodeCoreError> {
        Ok(self
            .load_notify_routes(device_delivery_id)?
            .into_iter()
            .filter(|route| route.sealed && !route.needs_reseal && route.unserved_until_ms > now_ms)
            .map(|route| route.unserved_until_ms)
            .min())
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
        served: Served,
        now_ms: u64,
    ) -> Result<Vec<DevicePushRoute>, NodeCoreError> {
        let now_seconds = crate::now_unix_seconds();
        let routes = self
            .load_notify_routes(device_delivery_id)?
            .into_iter()
            .filter(|route| route.expires_at > now_seconds)
            .collect::<Vec<_>>();
        let routes = if routes.is_empty() || self.authorize_push_route(device_delivery_id)? {
            routes
        } else {
            Vec::new()
        };
        Ok(route_selection::select_central_routes(routes, class, served, now_ms))
    }
}
