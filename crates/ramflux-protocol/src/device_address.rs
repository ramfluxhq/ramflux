// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-qualified device addresses use the existing gateway lookup encoding.
use crate::ProtocolError;
/// Read-only identity view for protocol guards without a dependency on the crypto crate.
/// Production callers use `ramflux_crypto::RootQualifiedDeviceRef`, whose constructors
/// authenticate root ownership or a signed device-set entry. A string is not an identity.
/// The workspace identity guard permits no other production implementation.
pub trait RootQualifiedDeviceIdentity {
    #[must_use]
    fn root_commitment(&self) -> &str;
    #[must_use]
    fn device_id(&self) -> &str;
}
/// Maximum byte length of a live device name. The native delivery address
/// (`root~base64url(json([root, device]))`) must fit `MAX_IDENTIFIER_BYTES`.
pub const MAX_DEVICE_NAME_BYTES: usize = 128;
/// Length of a root commitment (43 base64url characters) inside a native delivery address.
const ROOT_COMMITMENT_BYTES: usize = 43;
/// Length of the native delivery address for a device name of `device_bytes` bytes that needs no
/// JSON escaping: `root~` plus the base64url of `["<root>","<device>"]`. Names whose JSON form
/// grows (`"`, `\\`, controls) are measured exactly by `validate_device_name`.
const fn native_delivery_id_bytes(device_bytes: usize) -> usize {
    // `["<root>","<device>"]`: two brackets, four quotes, one comma.
    let json = ROOT_COMMITMENT_BYTES + device_bytes + 7;
    5 + (json * 4).div_ceil(3)
}
const _: () = assert!(
    native_delivery_id_bytes(MAX_DEVICE_NAME_BYTES) <= crate::message::outer::MAX_IDENTIFIER_BYTES,
    "a maximum-length device name must still yield a delivery id within MAX_IDENTIFIER_BYTES"
);
/// Reject address-shaped names at live device enrollment and group-control ingress.
/// The address codec itself still preserves historical literal names without recursive decoding.
/// # Errors
/// Rejects empty, oversized, control/format-containing, blank or reserved-prefix device names.
pub fn validate_device_name(name: &str) -> Result<(), ProtocolError> {
    if !crate::text_safety::single_line_is_safe(name) {
        return Err(ProtocolError::DeviceNameControlCharacter);
    }
    if name.trim().is_empty()
        || name.len() > MAX_DEVICE_NAME_BYTES
        || name.starts_with("root~")
        || name.starts_with("legacy~")
    {
        return Err(ProtocolError::InvalidIdentityRecord("invalid or reserved live device name"));
    }
    // JSON escaping can grow the name, so measure the exact derived delivery id of a
    // standard-length root commitment instead of trusting the byte cap alone.
    let json = serde_json::to_vec(&("r".repeat(ROOT_COMMITMENT_BYTES), name))?;
    let actual = 5 + (json.len() * 4).div_ceil(3);
    let limit = crate::message::outer::MAX_IDENTIFIER_BYTES;
    if actual > limit {
        return Err(ProtocolError::DeviceDeliveryIdTooLong { actual, limit });
    }
    Ok(())
}
/// Encode a root plus a literal device name, including names beginning with `root~`.
/// # Errors
/// Rejects empty/oversized identifiers or serialization errors.
pub fn qualified_device_id(root: &str, device: &str) -> Result<String, ProtocolError> {
    if root.is_empty()
        || root.len() > 256
        || device.is_empty()
        || device.len() > MAX_DEVICE_NAME_BYTES
    {
        return Err(ProtocolError::InvalidIdentityRecord("invalid qualified device address"));
    }
    let id = format!("root~{}", crate::encode_base64url(serde_json::to_vec(&(root, device))?));
    let limit = crate::message::outer::MAX_IDENTIFIER_BYTES;
    if id.len() > limit {
        return Err(ProtocolError::DeviceDeliveryIdTooLong { actual: id.len(), limit });
    }
    Ok(id)
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
    fn live_names_reject_controls_formats_and_blank_names_but_keep_printable_unicode() {
        for name in [
            "",
            " ",
            "\u{3000}",
            "phone\n",
            "a\u{202e}b",
            "a\u{200b}b",
            "a\u{200d}b",
            "root~x",
            "legacy~x",
        ] {
            assert!(validate_device_name(name).is_err(), "{name:?}");
        }
        for name in ["中文", "téléphone", "🦀", "phone 2"] {
            assert!(validate_device_name(name).is_ok(), "{name:?}");
        }
    }
    #[test]
    fn control_characters_are_a_typed_refusal() {
        for name in ["phone\n", "a\u{202e}b", "tab\there"] {
            assert!(
                matches!(
                    validate_device_name(name),
                    Err(ProtocolError::DeviceNameControlCharacter)
                ),
                "{name:?} must be refused with the control-character error"
            );
        }
    }
    #[test]
    fn json_escaping_cannot_push_the_delivery_id_past_the_identifier_cap() {
        let quotes = "\"".repeat(MAX_DEVICE_NAME_BYTES);
        assert!(
            matches!(
                validate_device_name(&quotes),
                Err(ProtocolError::DeviceDeliveryIdTooLong { actual, limit })
                    if actual > limit
            ),
            "a 128-byte name of quotes doubles in JSON and must be refused by length"
        );
        let slashes = "\\".repeat(MAX_DEVICE_NAME_BYTES);
        assert!(validate_device_name(&slashes).is_err(), "backslashes escape the same way");
        assert!(
            validate_device_name(&"d".repeat(MAX_DEVICE_NAME_BYTES)).is_ok(),
            "a 128-byte plain name stays accepted"
        );
    }
    #[test]
    fn device_names_are_capped_at_128_bytes_and_max_name_fits_the_delivery_id()
    -> Result<(), ProtocolError> {
        let max = "d".repeat(MAX_DEVICE_NAME_BYTES);
        validate_device_name(&max)?;
        let id = qualified_device_id(&"r".repeat(ROOT_COMMITMENT_BYTES), &max)?;
        assert_eq!(id.len(), native_delivery_id_bytes(MAX_DEVICE_NAME_BYTES), "length model");
        assert!(
            id.len() <= crate::message::outer::MAX_IDENTIFIER_BYTES,
            "delivery id {} exceeds the identifier cap",
            id.len()
        );
        let over = "d".repeat(MAX_DEVICE_NAME_BYTES + 1);
        assert!(
            matches!(validate_device_name(&over), Err(ProtocolError::InvalidIdentityRecord(_))),
            "129-byte device name must be refused with the typed validation error"
        );
        assert!(
            matches!(
                qualified_device_id(&"r".repeat(ROOT_COMMITMENT_BYTES), &over),
                Err(ProtocolError::InvalidIdentityRecord(_))
            ),
            "129-byte device name must not form an address"
        );
        Ok(())
    }
    #[test]
    fn the_encoder_refuses_a_root_that_pushes_the_delivery_id_past_the_identifier_cap() {
        let long_root = "r".repeat(256);
        let device = "d".repeat(MAX_DEVICE_NAME_BYTES);
        assert!(
            matches!(
                qualified_device_id(&long_root, &device),
                Err(ProtocolError::DeviceDeliveryIdTooLong { actual, limit }) if actual > limit
            ),
            "a non-standard 256-byte root must not form an over-long delivery id"
        );
    }
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
