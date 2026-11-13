// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Unified recipient-owned reach policy, independent of friendship and discovery.
mod admission;
pub mod directory;
mod foreign;
pub use foreign::*;
mod policy;
mod route;
mod state;
#[cfg(test)]
mod tests;
pub use admission::*;
pub use policy::*;
pub use route::*;
pub use state::*;

use crate::{MAX_SAFE_JSON_INTEGER, ProtocolError};
use serde::{Deserialize, Serialize};

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

pub(crate) fn invalid(reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidIdentityRecord(reason)
}

pub(crate) fn safe(value: u64) -> Result<(), ProtocolError> {
    if value > MAX_SAFE_JSON_INTEGER {
        return Err(invalid("unsafe reach integer"));
    }
    Ok(())
}

pub(crate) fn digest(value: &str) -> Result<(), ProtocolError> {
    let bytes = crate::decode_base64url(value).map_err(|_| invalid("invalid reach digest"))?;
    if bytes.len() != 32 || crate::encode_base64url(&bytes) != value {
        return Err(invalid("noncanonical reach digest"));
    }
    Ok(())
}

pub(crate) fn text(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid("invalid reach text"));
    }
    Ok(())
}

pub(crate) fn node(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(invalid("invalid reach node id"));
    }
    Ok(())
}

pub(crate) fn actor(value: &crate::custody::DeviceRef) -> Result<(), ProtocolError> {
    digest(&value.account_anchor)?;
    crate::validate_device_name(&value.device_id)?;
    safe(value.device_epoch)?;
    if value.device_epoch == 0 {
        return Err(invalid("zero reach device epoch"));
    }
    Ok(())
}

pub(crate) fn lifetime(issued: u64, expires: u64, duration: u64) -> Result<(), ProtocolError> {
    safe(issued)?;
    safe(expires)?;
    if issued.checked_add(duration) != Some(expires) {
        return Err(invalid("invalid reach lifetime"));
    }
    Ok(())
}

/// Check a submission window. Stored decisions do not expire with this window.
/// # Errors
/// Refuses an unsafe clock, future command or expired submission.
pub fn check_submission_time(issued: u64, expires: u64, now: u64) -> Result<(), ProtocolError> {
    safe(now)?;
    if issued > now.checked_add(60).ok_or_else(|| invalid("reach clock overflow"))?
        || now >= expires
    {
        return Err(invalid("reach submission expired or future"));
    }
    Ok(())
}

/// Decode original I-JSON with all null fields explicit and bounded nesting.
/// # Errors
/// Refuses duplicate, missing or unknown fields and unsafe/oversized documents.
pub fn decode<T: Serialize + for<'de> Deserialize<'de>>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, ProtocolError> {
    if bytes.len() > limit {
        return Err(invalid("reach wire byte budget"));
    }
    let mut depth = 0_u32;
    let mut quoted = false;
    let mut escaped = false;
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > 32 {
                        return Err(invalid("reach nesting exceeds 32"));
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    let raw: serde_json::Value = crate::parse_i_json(bytes)?;
    let value: T = serde_json::from_value(raw.clone())?;
    if serde_json::to_value(&value)? != raw {
        return Err(invalid("reach fields must be explicit"));
    }
    Ok(value)
}
