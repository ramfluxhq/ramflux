// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile contact routing reads adopted state and never creates a durable authority/payload sink.
mod authority;
use super::{Result, refuse, storage};
use crate::{RouterCore, RouterRedbStore};
use ramflux_protocol::contact_reach::{ReachEphemeral, Reason};
use std::{collections::BTreeMap, sync::Mutex};

/// Observed transport facts, never selected from the signed route body.
#[derive(Clone, Copy)]
pub struct ReachEphemeralContext<'a> {
    pub node: &'a crate::MigrationNode,
    pub peer_node: &'a str,
    pub local_source: bool,
    pub now_ms: u64,
}
#[derive(Default)]
pub struct ReachEphemeralAdmission {
    rates: Mutex<BTreeMap<String, (u64, u64)>>,
}
impl ReachEphemeralAdmission {
    /// Validate recipient/source/settings under read-only state, then enter the existing volatile route.
    /// `local_source` is selected from authenticated transport context, never the frame body.
    /// # Errors
    /// Refuses unknown source authority, nonlocal targets, missing grants/settings and rate pressure.
    pub fn route(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        frame: &ReachEphemeral,
        context: ReachEphemeralContext<'_>,
    ) -> Result<crate::EphemeralRouteResult> {
        let now_ms = context.now_ms;
        frame.validate(now_ms)?;
        authority::require(store, frame, context)?;
        let b = &frame.route.body;
        let mut rates = self.rates.lock().map_err(storage)?;
        let window = now_ms / 60_000;
        rates.retain(|_, (old, _)| *old >= window);
        for (key, cap) in [
            (format!("recipient:{}", b.recipient_root), 1000),
            (format!("source:{}:{}", b.source.account_anchor, b.recipient_root), 100),
        ] {
            if !rates.contains_key(&key) && rates.len() >= 4096 {
                return Err(refuse(Reason::ForeignCapacity));
            }
            let (_, count) = rates.entry(key).or_insert((window, 0));
            if *count >= cap {
                return Err(refuse(Reason::ForeignRateLimited));
            }
            *count += 1;
        }
        drop(rates);
        let view = router.ephemeral_view();
        let result = match view.route_gate(&frame.frame.envelope.target_delivery_id) {
            crate::EphemeralRouteGate::Online { gateway_id, session_id } => view
                .admit_routed_replay(
                    &frame.frame.envelope,
                    frame.frame.expires_at_ms,
                    now_ms,
                    gateway_id,
                    session_id,
                ),
            crate::EphemeralRouteGate::Offline => {
                crate::EphemeralRouteResult::Dropped(crate::EphemeralDropReason::Offline)
            }
            crate::EphemeralRouteGate::RecipientUnsupported => {
                crate::EphemeralRouteResult::Dropped(
                    crate::EphemeralDropReason::RecipientUnsupported,
                )
            }
        };
        Ok(result)
    }
}
