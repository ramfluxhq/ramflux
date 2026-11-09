// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing relay allocator: caps, expiry, boot retirement and account isolation.
//! P06 owns HTTP/native routes. This module is not reachable from production listeners.

mod bytes;
mod limits;
mod store;

pub use limits::{
    AllocatorStats, CLAIM_GRACE_MS, ENTRY_OVERHEAD, HOUR_MS, INVITATION_LIFETIME_SECS,
    ISSUED_RESERVE, LIVE_RESERVE, MAX_BACKING, MAX_CLAIMS, MAX_CLAIMS_PER_PREFIX, MAX_CLOSED,
    MAX_FRAME_BYTES, MAX_FRAMES_PER_DIRECTION, MAX_HOUR_ENTRIES, MAX_ISSUES_PER_HOUR,
    MAX_QUEUE_BYTES, MAX_SLOT_METADATA, MAX_SLOTS, MAX_SLOTS_PER_ACCOUNT, NodePairingClock,
    PairingClock, PairingRelayError, SLACK_BYTES, TestPairingClock, claim_source_prefixes,
};
pub use store::{PairingRelayConfig, PairingRelayStore};

#[cfg(test)]
mod tests;
