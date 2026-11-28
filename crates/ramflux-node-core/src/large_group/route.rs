// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Anonymous push routes held at the host (MLS-SPEC r1.1 2.7): one route per device and group, a
//! fresh 16-byte tag `rt`, the roster's `mention_key`, a push token sealed to this node, a mode
//! and `del_hash = BLAKE3(del_secret)`. A route row has no account, device or pseudonym, and its
//! registration time is only the UTC day (`registered_day`); a route not renewed within 7 to 8
//! days is dropped. Wake queueing (jitter, coalescing, the centre call) is not here.

use super::check::{DAY_MS, route_expired};
use super::host::LargeGroupHost;
use super::refusal::{LgRefusal, LgResult};
use super::rows::{RouteRow, key};
use crate::RouterRedbStore;
use crate::router_store::lg_store::LgTable;

/// Routes one group holds (one per device and group; 3 000 leaves at most).
pub const ROUTES_MAX: u32 = 4_096;
/// Longest sealed push token.
pub const SEALED_TOKEN_MAX: usize = 1_024;
const MODE_MENTIONS_REPLIES: u8 = 1;
const MODE_ALL: u8 = 2;

/// What a route wakes for (`none` is no route).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteMode {
    /// Posts that mention the device's member or reply to it (default).
    MentionsReplies,
    /// Every post.
    All,
}

impl RouteMode {
    const fn code(self) -> u8 {
        match self {
            Self::MentionsReplies => MODE_MENTIONS_REPLIES,
            Self::All => MODE_ALL,
        }
    }
}

/// `route.register{rt, sealed_token, mention_key, mode, del_hash}`.
#[derive(Clone, Debug)]
pub struct RouteRegistration {
    /// Fresh route tag.
    pub rt: [u8; 16],
    /// Push token sealed to this node for the centre.
    pub sealed_token: Vec<u8>,
    /// The `mention_key` from the member's roster entry.
    pub mention_key: [u8; 32],
    /// What it wakes for.
    pub mode: RouteMode,
    /// `BLAKE3(del_secret)`.
    pub del_hash: [u8; 32],
}

/// A route a post wakes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeTarget {
    /// The route tag.
    pub rt: [u8; 16],
    /// The sealed push token to send to the centre.
    pub sealed_token: Vec<u8>,
    /// The route's mode.
    pub mode: u8,
}

impl LargeGroupHost {
    /// Register a route (member session). Re-registration uses a fresh `rt`.
    ///
    /// # Errors
    /// `not_found`, `bad_request` (token too long, `rt` taken), `limit`.
    pub fn route_register(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        reg: &RouteRegistration,
    ) -> LgResult<()> {
        if reg.sealed_token.is_empty() || reg.sealed_token.len() > SEALED_TOKEN_MAX {
            return Err(LgRefusal::BadRequest);
        }
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            let route_key = key(gid, &[&reg.rt]);
            if cx.tx.get(LgTable::Route, &route_key)?.is_some() {
                return Err(LgRefusal::BadRequest);
            }
            if head.route_count >= ROUTES_MAX {
                return Err(LgRefusal::Limit);
            }
            let row = RouteRow {
                sealed_token: reg.sealed_token.clone(),
                mention_key: reg.mention_key,
                mode: reg.mode.code(),
                del_hash: reg.del_hash,
                registered_day: cx.now / DAY_MS,
            };
            cx.tx.put(LgTable::Route, &route_key, &row.encode())?;
            head.route_count = head.route_count.saturating_add(1);
            cx.put_head(gid, &head)
        })
    }

    /// `route.delete{rt, del_secret}` (ident session; no token, no pseudonym).
    ///
    /// # Errors
    /// `not_found`, `unauthorized` (wrong secret).
    pub fn route_delete(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        rt: &[u8; 16],
        del_secret: &[u8],
    ) -> LgResult<()> {
        self.run(store, now, |cx| {
            let mut head = cx.head(gid)?;
            let route_key = key(gid, &[rt]);
            let bytes = cx.tx.get(LgTable::Route, &route_key)?.ok_or(LgRefusal::NotFound)?;
            let row = RouteRow::decode(&bytes)?;
            let given = blake3::hash(del_secret);
            if !constant_time_eq(given.as_bytes(), &row.del_hash) {
                return Err(LgRefusal::Unauthorized);
            }
            cx.tx.del(LgTable::Route, &route_key)?;
            head.route_count = head.route_count.saturating_sub(1);
            cx.put_head(gid, &head)
        })
    }

    /// The routes a post wakes: `all` routes, and `mentions_replies` routes whose mention tag
    /// `BLAKE3-keyed(mention_key, post_id)[..16]` is among the post's `tags`. Read-only; the caller
    /// queues the wakes.
    ///
    /// # Errors
    /// Store failures.
    pub fn wake_targets(
        &self,
        store: &RouterRedbStore,
        now: u64,
        gid: &[u8; 32],
        post_id: &[u8; 16],
        tags: &[[u8; 16]],
    ) -> LgResult<Vec<WakeTarget>> {
        let today = now / DAY_MS;
        store.lg_read(|view| {
            let prefix = key(gid, &[]);
            let limit = usize::try_from(ROUTES_MAX).unwrap_or(usize::MAX);
            let mut out = Vec::new();
            for (row_key, value) in view.scan(LgTable::Route, &prefix, &prefix, limit)? {
                let Ok(row) = RouteRow::decode(&value) else { continue };
                let Some(rt) = row_key.get(prefix.len()..).and_then(|tail| tail.try_into().ok())
                else {
                    continue;
                };
                if route_expired(row.registered_day, today) {
                    continue;
                }
                let mentioned = {
                    let full = blake3::keyed_hash(&row.mention_key, post_id);
                    let mut tag = [0_u8; 16];
                    tag.copy_from_slice(full.as_bytes().get(..16).unwrap_or(&[0; 16]));
                    tags.contains(&tag)
                };
                if row.mode == MODE_ALL || (row.mode == MODE_MENTIONS_REPLIES && mentioned) {
                    out.push(WakeTarget { rt, sealed_token: row.sealed_token, mode: row.mode });
                }
            }
            Ok(Ok(out))
        })?
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(left.ct_eq(right))
}
