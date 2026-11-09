// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Release interlock shared by pairing HTTP/native admission and capability discovery.
//! P18 flips [`DEVICE_PAIRING_RELEASE_GATE`] to advertise `device_pairing_v2`.
pub const DEVICE_PAIRING_CAPABILITY: &str = "device_pairing_v2";
/// Discovery advertisement stays off until P18. Routes remain reachable when the env opt-in is set.
pub const DEVICE_PAIRING_RELEASE_GATE: bool = false;

/// Validates the opt-in before any service startup mutation.
/// # Errors
/// Rejects invalid opt-in configuration.
pub fn device_pairing_enabled() -> Result<bool, crate::NodeCoreError> {
    match crate::environment::var("RAMFLUX_DEVICE_PAIRING_ENABLED").ok().as_deref() {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(crate::NodeCoreError::Unauthorized(
            "RAMFLUX_DEVICE_PAIRING_ENABLED must be 0 or 1".into(),
        )),
    }
}
