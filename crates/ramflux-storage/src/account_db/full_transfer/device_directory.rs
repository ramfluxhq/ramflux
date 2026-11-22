// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Historical public address bindings; no device branch, key, pin or current authority.
use crate::StorageError;

pub(super) fn validate(address: &str, root: &str, raw: &str) -> Result<(), StorageError> {
    let invalid = || StorageError::PairingField("UnsupportedRecord");
    ramflux_protocol::validate_device_name(raw).map_err(|_| invalid())?;
    let expected = ramflux_protocol::qualified_device_id(root, raw).map_err(|_| invalid())?;
    if address != expected {
        return Err(invalid());
    }
    Ok(())
}
