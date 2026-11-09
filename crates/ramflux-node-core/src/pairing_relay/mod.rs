// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing relay allocator: caps, expiry, boot retirement and account isolation.
//! HTTP dispatch and native Issue/Create stay behind the default-off pairing capability.

mod bytes;
mod http;
mod limits;
mod store;

pub use http::{
    PAIRING_CLAIM_PATH, PAIRING_CLOSE_PATH, PAIRING_HTTP_PREFIX, PAIRING_MAX_BODY_BYTES,
    PAIRING_MAX_HEADER_BYTES, PAIRING_POLL_PATH, PAIRING_REQUEST_TIMEOUT, PAIRING_SEND_PATH,
    PairingHttpResponse, handle_pairing_http, is_pairing_path, pairing_http_limits,
};
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
