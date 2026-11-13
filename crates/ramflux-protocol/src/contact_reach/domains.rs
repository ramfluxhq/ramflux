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

pub const EPHEMERAL_CAPABILITY: &str = "federation_ephemeral.v1";
pub const DIRECTORY_CAPABILITY: &str = "username_directory.v2";

/// The directory requires its separately provisioned and audited centre/witness profile.
#[must_use]
pub const fn directory_enabled() -> bool {
    false
}

/// Derive discovery from the common audited profile, including its volatile dependency.
/// Stale or configured capability strings cannot override a closed release gate.
#[must_use]
pub fn advertised_capabilities(base: &[String]) -> Vec<String> {
    let mut capabilities = base
        .iter()
        .filter(|cap| {
            !matches!(cap.as_str(), super::CAPABILITY | EPHEMERAL_CAPABILITY | DIRECTORY_CAPABILITY)
        })
        .cloned()
        .collect::<Vec<_>>();
    if enabled() {
        capabilities.push(super::CAPABILITY.into());
        capabilities.push(EPHEMERAL_CAPABILITY.into());
        if directory_enabled() {
            capabilities.push(DIRECTORY_CAPABILITY.into());
        }
    }
    capabilities
}
