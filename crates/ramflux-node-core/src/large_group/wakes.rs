// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded, volatile wake hints for accepted posts. History is the recovery path after a drop
//! or restart. Only (group, route tag), a sealed token and route snapshot, and timing state live
//! here; there is no account, device, pseudonym, roster or provider token.

use std::collections::BTreeMap;
use std::sync::PoisonError;

use ramflux_crypto::large_group::{Envelope, random_array};
use ramflux_crypto::push_token::encode_sealed_token;

use super::host::LargeGroupHost;
use super::refusal::{LgRefusal, LgResult};
use super::route::{SEALED_TOKEN_MAX, WakeTarget};
use crate::RouterRedbStore;
use crate::push_handoff::{CentralClass, HandoffWake, MAX_HANDOFF_FRAME, MAX_WAKES};

/// Pending hints and unexpired cooldowns together are bounded, across all hosted groups.
const MAX_ROUTE_STATES: usize = 4_096;
/// A hint's expiry starts at enqueue, never at handoff or a retry.
const WAKE_TTL_MS: u64 = 60_000;
const JITTER_RANGE_MS: u32 = 30_001;
const RANDOM_ATTEMPTS: usize = 8;
const MENTIONS_GAP_MS: u64 = 60_000;
const ALL_GAP_MS: u64 = 300_000;
const MODE_ALL: u8 = 2;
// Base64url of the largest sealed token plus ample fixed JSON/id/TTL overhead. The enclosing
// request also fits because every entry reserves 256 overhead bytes, including its share of it.
const MAX_GROUP_BATCH: usize = MAX_HANDOFF_FRAME / (SEALED_TOKEN_MAX.div_ceil(3) * 4 + 256);

type RouteKey = ([u8; 32], [u8; 16]);

struct PendingGroupWake {
    target: WakeTarget,
    due_ms: u64,
    expires_ms: u64,
}

#[derive(Default)]
struct RouteState {
    pending: Option<PendingGroupWake>,
    next_allowed_ms: u64,
}

/// Queue and cooldowns share one bounded map, so active cooldowns are never evicted to admit
/// more work. All timing is RAM-only. Losing the map never loses an appended post.
#[derive(Default)]
pub(super) struct WakeQueue {
    routes: BTreeMap<RouteKey, RouteState>,
}

impl WakeQueue {
    fn prune(&mut self, now_ms: u64) {
        self.routes.retain(|_, state| {
            if state.pending.as_ref().is_some_and(|pending| pending.expires_ms <= now_ms) {
                state.pending = None;
            }
            state.pending.is_some() || state.next_allowed_ms > now_ms
        });
    }

    fn enqueue(
        &mut self,
        gid: [u8; 32],
        targets: Vec<WakeTarget>,
        now_ms: u64,
        max_routes: usize,
        ttl_ms: u64,
    ) -> LgResult<()> {
        self.prune(now_ms);
        for target in targets {
            let key = (gid, target.rt);
            if let Some(state) = self.routes.get(&key) {
                if state.pending.is_some() || state.next_allowed_ms > now_ms {
                    continue;
                }
            } else if self.routes.len() >= max_routes {
                // Drop the hint only; never evict an active cooldown or affect the log.
                continue;
            }
            let delay = u64::from(jitter_ms()?);
            let pending = PendingGroupWake {
                target,
                due_ms: now_ms.saturating_add(delay),
                expires_ms: now_ms.saturating_add(ttl_ms),
            };
            self.routes.entry(key).or_default().pending = Some(pending);
        }
        Ok(())
    }

    fn drain(&mut self, now_ms: u64) -> Vec<(RouteKey, PendingGroupWake)> {
        self.prune(now_ms);
        let mut due = Vec::new();
        for (key, state) in &mut self.routes {
            if due.len() >= MAX_WAKES.min(MAX_GROUP_BATCH) {
                break;
            }
            if state.pending.as_ref().is_some_and(|pending| pending.due_ms <= now_ms)
                && let Some(pending) = state.pending.take()
            {
                let gap =
                    if pending.target.mode == MODE_ALL { ALL_GAP_MS } else { MENTIONS_GAP_MS };
                // Reserve the budget before releasing the lock, including failed handoffs.
                state.next_allowed_ms = now_ms.saturating_add(gap);
                due.push((*key, pending));
            }
        }
        due
    }
}

impl LargeGroupHost {
    /// Match only an accepted post, after its append transaction has committed and released
    /// the writer. Notification failure must never turn that committed append into a refusal.
    pub(super) fn enqueue_post_wakes(&self, store: &RouterRedbStore, now_ms: u64, env: &Envelope) {
        let header = &env.header;
        let result = self
            .wake_targets(store, now_ms, &header.group_id, &header.post_id, &header.tags)
            .and_then(|targets| self.enqueue_targets(header.group_id, targets, now_ms));
        if let Err(refusal) = result {
            tracing::warn!(code = refusal.code(), "group post wake hints dropped");
        }
    }

    /// Queue matched routes without any I/O. A pending hint coalesces later posts, and a full
    /// map drops new hints without evicting pending work or active cooldowns.
    ///
    /// # Errors
    /// OS randomness failures. The accepted post is unaffected.
    pub fn enqueue_targets(
        &self,
        gid: [u8; 32],
        targets: Vec<WakeTarget>,
        now_ms: u64,
    ) -> LgResult<()> {
        self.wakes.lock().unwrap_or_else(PoisonError::into_inner).enqueue(
            gid,
            targets,
            now_ms,
            MAX_ROUTE_STATES,
            WAKE_TTL_MS,
        )
    }

    /// Take at most one handoff batch, rechecking the complete route snapshot and UTC-day
    /// expiry before encoding. The caller sends immediately without holding a queue/store lock.
    /// All answers are terminal for this hint; no answer mutates or deletes a route.
    ///
    /// # Errors
    /// Store or OS randomness failures; the drained hints are dropped, never the log entries.
    pub fn drain_due(
        &self,
        store: &RouterRedbStore,
        now_ms: u64,
        central_ttl_max_s: u64,
    ) -> LgResult<Vec<HandoffWake>> {
        let pending = self.wakes.lock().unwrap_or_else(PoisonError::into_inner).drain(now_ms);
        let mut wakes = Vec::new();
        for ((gid, _), pending) in pending {
            let ttl = pending.expires_ms.saturating_sub(now_ms) / 1000;
            let ttl = ttl.min(central_ttl_max_s);
            if ttl == 0 || !Self::wake_target_live(store, now_ms, &gid, &pending.target)? {
                continue;
            }
            wakes.push(HandoffWake {
                w: ramflux_protocol::encode_base64url(random_array::<16>()?),
                c: CentralClass::X,
                ttl,
                rt: ramflux_protocol::encode_base64url(pending.target.rt),
                st: encode_sealed_token(&pending.target.sealed_token),
            });
        }
        Ok(wakes)
    }
}

/// Rejection sampling avoids modulo bias; a bounded failure returns a typed error.
fn jitter_ms() -> LgResult<u32> {
    let limit = u32::MAX - u32::MAX % JITTER_RANGE_MS;
    for _ in 0..RANDOM_ATTEMPTS {
        let draw = u32::from_le_bytes(random_array::<4>()?);
        if draw < limit {
            return Ok(draw % JITTER_RANGE_MS);
        }
    }
    Err(LgRefusal::Internal)
}
