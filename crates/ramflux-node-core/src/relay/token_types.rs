// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current relay timing constants and retained tombstone identity.
use super::ObjectRelayTombstone;

pub const OBJECT_RELAY_CLOCK_SKEW_LEEWAY_SECONDS: u64 = 60;
pub const OBJECT_RELAY_TOKEN_MAX_TTL_SECONDS: u64 = 300;

/// Returns whether the incoming tombstone repeats the persisted scope, event, expiry and owner.
pub(super) fn existing_tombstone_matches_replay(
    existing: &ObjectRelayTombstone,
    incoming: &ObjectRelayTombstone,
) -> bool {
    existing == incoming
}
