// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Release interlock shared by pairing HTTP/native admission and capability discovery.
//! A later activation card may enable discovery after companion acceptance.
pub const DEVICE_PAIRING_CAPABILITY: &str = "device_pairing_v2";
/// Discovery stays off in the preview module. Routes require the explicit env opt-in.
pub const DEVICE_PAIRING_RELEASE_GATE: bool = false;

/// Validates the opt-in before any service startup mutation.
/// # Errors
/// Rejects invalid opt-in configuration.
pub fn device_pairing_enabled() -> Result<bool, crate::NodeCoreError> {
    match crate::environment::var("RAMFLUX_DEVICE_PAIRING_ENABLED") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        _ => Err(crate::NodeCoreError::Unauthorized(
            "RAMFLUX_DEVICE_PAIRING_ENABLED must be 0 or 1".into(),
        )),
    }
}
