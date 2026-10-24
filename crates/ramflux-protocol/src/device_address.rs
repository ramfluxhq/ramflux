// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified device addresses use the existing gateway lookup encoding.
use crate::ProtocolError;
/// Reject address-shaped names at live device enrollment and group-control ingress.
/// The address codec itself still preserves historical literal names without recursive decoding.
/// # Errors
/// Rejects empty, oversized, control-containing or reserved-prefix device names.
pub fn validate_device_name(name: &str) -> Result<(), ProtocolError> {
    if name.is_empty()
        || name.len() > 256
        || name.chars().any(char::is_control)
        || name.starts_with("root~")
        || name.starts_with("legacy~")
    {
        return Err(ProtocolError::InvalidIdentityRecord("invalid or reserved live device name"));
    }
    Ok(())
}
/// Encode a root plus a literal device name, including names beginning with `root~`.
/// # Errors
/// Rejects empty/oversized identifiers or serialization errors.
pub fn qualified_device_id(root: &str, device: &str) -> Result<String, ProtocolError> {
    if root.is_empty() || root.len() > 256 || device.is_empty() || device.len() > 1024 {
        return Err(ProtocolError::InvalidIdentityRecord("invalid qualified device address"));
    }
    Ok(format!("root~{}", crate::encode_base64url(serde_json::to_vec(&(root, device))?)))
}
/// Decode an address; a bare legacy identifier returns None. Decode only once: device names
/// inside an address are literal names, never another address to interpret recursively.
/// # Errors
/// Rejects malformed, noncanonical or oversized address encodings.
pub fn parse_qualified_device_id(value: &str) -> Result<Option<(String, String)>, ProtocolError> {
    let Some(encoded) = value.strip_prefix("root~") else { return Ok(None) };
    if value.len() > 2048 {
        return Err(ProtocolError::InvalidIdentityRecord("qualified address too large"));
    }
    let bytes = crate::decode_base64url(encoded)
        .map_err(|source| ProtocolError::InvalidBase64Url { field: "device address", source })?;
    let (root, device): (String, String) = crate::parse_i_json(&bytes)?;
    if qualified_device_id(&root, &device)? != value {
        return Err(ProtocolError::InvalidIdentityRecord("noncanonical device address"));
    }
    Ok(Some((root, device)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualified_addresses_preserve_literal_address_shaped_names_and_decode_once()
    -> Result<(), ProtocolError> {
        let first = qualified_device_id("root-a", "phone")?;
        let nested = qualified_device_id("root-b", &first)?;
        assert_ne!(first, nested);
        assert_eq!(parse_qualified_device_id(&nested)?, Some(("root-b".into(), first)));
        assert_eq!(parse_qualified_device_id("phone")?, None);
        assert!(parse_qualified_device_id("root~junk").is_err());
        Ok(())
    }
}
