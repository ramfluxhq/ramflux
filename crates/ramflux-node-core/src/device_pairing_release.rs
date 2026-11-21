// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device pairing capability and node opt-in, shared by pairing HTTP/native admission and
//! capability discovery. A node enables pairing with `RAMFLUX_DEVICE_PAIRING_ENABLED=1`; only an
//! enabled node serves the pairing routes and advertises `device_pairing_v2` (with
//! `primary_transfer_full_v1`). A disabled node advertises neither.
pub const DEVICE_PAIRING_CAPABILITY: &str = "device_pairing_v2";
/// Full-transfer capability that a pairing-enabled node advertises alongside pairing.
pub const PRIMARY_TRANSFER_FULL_CAPABILITY: &str = "primary_transfer_full_v1";

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
