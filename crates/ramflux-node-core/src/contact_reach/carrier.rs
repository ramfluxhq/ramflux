// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Missing wrappers are refused before legacy source authentication can persist trust.

/// Activated transport never falls back to an unwrapped durable envelope.
/// This precedes foreign-pin, replay, migration and payload writes on legacy ingress.
pub(crate) fn require_submission_carrier() -> std::result::Result<(), crate::NodeCoreError> {
    if super::enabled() {
        return Err(crate::NodeCoreError::ContactReachRefused(
            ramflux_protocol::contact_reach::Reason::ReachRouteInvalid,
        ));
    }
    Ok(())
}

/// Preserve all legacy durable bounds while refusing a missing activated reach wrapper first.
pub(crate) fn require_legacy_durable(
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), crate::NodeCoreError> {
    require_submission_carrier()?;
    ramflux_protocol::ephemeral::require_durable(envelope)?;
    crate::check_entry_bound(envelope)
}
