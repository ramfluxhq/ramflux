// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact domain separators, resource ceilings and the common release gate.
pub const POLICY_DOMAIN: &str = "ramflux.contact.reach_policy.v1";
pub const ADMISSION_DOMAIN: &str = "ramflux.contact.recipient_admission.v2";
pub const ROUTE_DOMAIN: &str = "ramflux.contact.reach_route.v1";
pub const ENVELOPE_HASH_DOMAIN: &str = "ramflux.contact.reach_envelope.v1";
pub const OPERATION_HASH_DOMAIN: &str = "ramflux.contact.reach_operation.v1";
pub const STATE_DOMAIN: &str = "ramflux.contact.reach_state.v1";
pub const STATE_PAGES_DOMAIN: &str = "ramflux.contact.reach_state_pages.v1";
pub const STATE_CONTENT_DOMAIN: &str = "ramflux.contact.reach_state_content.v1";
pub const COMMAND_LIFETIME: u64 = 300;
pub const CONVERSATION_LIFETIME: u64 = 2_592_000;
pub const DECLINE_COOLDOWN: u64 = 86_400;
pub const MAX_UPDATE_BYTES: usize = 4096;
pub const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SUBJECTS: usize = 1024;

/// Release gate for the complete common reach profile, after its independent authority audit.
/// No environment setting activates an incomplete carrier set.
#[must_use]
pub const fn enabled() -> bool {
    false
}
