// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Strict I-JSON ingress before conversion into typed protocol objects.
//! Exact integer tokens use the interoperable 53-bit range; fractional/exponent tokens are binary64.
//! Strings are checked but never normalized. Call this before constructing a `Value`, since an
//! already-built map cannot retain evidence of duplicate members.
use crate::ProtocolError;
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;

pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
/// Stable public reason code for an I-JSON ingress refusal.
pub const I_JSON_REJECTED: &str = "i_json_rejected";

/// Parse original UTF-8 JSON, detecting duplicate decoded names at every depth.
/// # Errors
/// Rejects invalid JSON/Unicode, noncharacters, duplicate names, unsafe exact integers,
/// non-finite/out-of-range numbers, trailing input, or the target type's schema violations.
pub fn parse_i_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    let validated = (|| -> Result<T, serde_json::Error> {
        numbers(bytes)?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let Strict(value) = Strict::deserialize(&mut decoder)?;
        decoder.end()?;
        serde_json::from_value(value)
    })();
    validated.map_err(ProtocolError::IJson)
}

/// Validate original JSON bytes as I-JSON without constructing an intermediate value.
/// Use this before decoding fields such as `RawValue` whose exact wire representation matters.
/// # Errors
/// Rejects invalid JSON/Unicode, noncharacters, duplicate names, unsafe exact integers,
/// non-finite/out-of-range numbers, or trailing input.
pub fn validate_i_json_bytes(bytes: &[u8]) -> Result<(), ProtocolError> {
    let validated = (|| -> Result<(), serde_json::Error> {
        numbers(bytes)?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        Validate::deserialize(&mut decoder)?;
        decoder.end()
    })();
    validated.map_err(ProtocolError::IJson)
}

/// Decode a signed envelope from its original JSON bytes using the I-JSON predicate.
/// # Errors
/// Returns [`ProtocolError::IJson`] when the bytes are not valid I-JSON or do not match the schema.
pub fn decode_signed_envelope_ijson(bytes: &[u8]) -> Result<crate::Envelope, ProtocolError> {
    parse_i_json(bytes)
}

/// Decode a signed acknowledgement from its original JSON bytes using the I-JSON predicate.
/// # Errors
/// Returns [`ProtocolError::IJson`] when the bytes are not valid I-JSON or do not match the schema.
pub fn decode_signed_ack_ijson(bytes: &[u8]) -> Result<crate::Ack, ProtocolError> {
    parse_i_json(bytes)
}

/// Decode a signed negative acknowledgement from its original JSON bytes using the I-JSON predicate.
/// # Errors
/// Returns [`ProtocolError::IJson`] when the bytes are not valid I-JSON or do not match the schema.
pub fn decode_signed_nack_ijson(bytes: &[u8]) -> Result<crate::Nack, ProtocolError> {
    parse_i_json(bytes)
}

/// Build the stable JSON body returned for an I-JSON ingress refusal.
#[must_use]
pub fn i_json_rejection_body() -> Value {
    serde_json::json!({"error": I_JSON_REJECTED, "reason_code": I_JSON_REJECTED})
}

/// Detect an I-JSON refusal through standard error-source chains.
#[must_use]
pub fn is_i_json_rejection(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<ProtocolError>()
            .is_some_and(|error| matches!(error, ProtocolError::IJson(_)))
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn invalid(message: &'static str) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, message))
}
fn unicode(value: &str) -> Result<(), serde_json::Error> {
    if value.chars().any(|c| {
        let n = u32::from(c);
        (0xfdd0..=0xfdef).contains(&n) || n & 0xffff >= 0xfffe
    }) {
        return Err(invalid("noncharacter in I-JSON string"));
    }
    Ok(())
}

// Preserve number-token intent before serde can round an oversized integer into a float.
fn numbers(bytes: &[u8]) -> Result<(), serde_json::Error> {
    let mut index = 0;
    let mut quoted = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if quoted => index += 2,
            b'"' => {
                quoted = !quoted;
                index += 1;
            }
            b'-' | b'0'..=b'9' if !quoted => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && matches!(bytes[index], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    index += 1;
                }
                let token = std::str::from_utf8(&bytes[start..index])
                    .map_err(|_| invalid("invalid JSON number"))?;
                let number = token.parse::<f64>().map_err(|_| invalid("invalid JSON number"))?;
                let significand = token.split(['e', 'E']).next().unwrap_or(token);
                let underflow =
                    number == 0.0 && significand.bytes().any(|c| matches!(c, b'1'..=b'9'));
                if !number.is_finite() || underflow {
                    return Err(invalid("JSON number exceeds binary64 range"));
                }
                if !token.contains(['.', 'e', 'E']) {
                    let integer =
                        token.parse::<i128>().map_err(|_| invalid("unsafe exact JSON integer"))?;
                    if integer.unsigned_abs() > u128::from(MAX_SAFE_JSON_INTEGER) {
                        return Err(invalid("unsafe exact JSON integer"));
                    }
                }
            }
            _ => index += 1,
        }
    }
    Ok(())
}

/// Check already-typed values without changing their Unicode or numeric representation.
/// # Errors
/// Rejects noncharacters, non-finite numbers and integer values outside the safe range.
/// Duplicate detection requires [`parse_i_json`] on the original bytes.
pub fn validate_i_json_value(value: &Value) -> Result<(), ProtocolError> {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) => unicode(value).map_err(ProtocolError::IJson)?,
            Value::Number(n) => {
                if n.as_u64().is_some_and(|n| n > MAX_SAFE_JSON_INTEGER)
                    || n.as_i64().is_some_and(|n| n.unsigned_abs() > MAX_SAFE_JSON_INTEGER)
                    || n.as_f64().is_none_or(|n| !n.is_finite())
                {
                    return Err(ProtocolError::IJson(invalid("unsafe I-JSON number")));
                }
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                for (key, value) in values {
                    unicode(key).map_err(ProtocolError::IJson)?;
                    pending.push(value);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(StrictVisitor)
    }
}

struct Validate;
impl<'de> Deserialize<'de> for Validate {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_any(ValidateVisitor)
    }
}

struct ValidateVisitor;
impl<'de> Visitor<'de> for ValidateVisitor {
    type Value = Validate;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an I-JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Validate, E> {
        Ok(Validate)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Validate, E> {
        Ok(Validate)
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Validate, E> {
        if value.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
            return Err(E::custom("unsafe exact JSON integer"));
        }
        Ok(Validate)
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Validate, E> {
        if value > MAX_SAFE_JSON_INTEGER {
            return Err(E::custom("unsafe exact JSON integer"));
        }
        Ok(Validate)
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Validate, E> {
        if !value.is_finite() {
            return Err(E::custom("non-finite JSON number"));
        }
        Ok(Validate)
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Validate, E> {
        unicode(value).map_err(E::custom)?;
        Ok(Validate)
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Validate, E> {
        self.visit_str(&value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Validate, A::Error> {
        while seq.next_element::<Validate>()?.is_some() {}
        Ok(Validate)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Validate, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            unicode(&name).map_err(serde::de::Error::custom)?;
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate I-JSON member"));
            }
            map.next_value::<Validate>()?;
        }
        Ok(Validate)
    }
}
struct StrictVisitor;
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an I-JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
        if v.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
            return Err(E::custom("unsafe exact JSON integer"));
        }
        Ok(Strict(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
        if v > MAX_SAFE_JSON_INTEGER {
            return Err(E::custom("unsafe exact JSON integer"));
        }
        Ok(Strict(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Strict, E> {
        self.visit_string(v.to_owned())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Strict, E> {
        unicode(&v).map_err(E::custom)?;
        Ok(Strict(Value::String(v)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut values = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            values.push(v);
        }
        Ok(Strict(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            unicode(&key).map_err(serde::de::Error::custom)?;
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate I-JSON member"));
            }
            let Strict(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(Strict(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        I_JSON_REJECTED, decode_signed_ack_ijson, decode_signed_envelope_ijson,
        decode_signed_nack_ijson, i_json_rejection_body, is_i_json_rejection,
        validate_i_json_bytes,
    };
    use crate::{
        Ack, DeliveryClass, Envelope, Ext, Nack, NackReason, Priority, ProtocolError, SignatureAlg,
        SignedFields,
    };
    use serde::Serialize;
    use std::error::Error;

    const SAFE: i64 = 9_007_199_254_740_991;
    const UNSAFE: i64 = 9_007_199_254_740_992;

    fn signed() -> SignedFields {
        SignedFields {
            signing_key_id: "key".into(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "sig".into(),
        }
    }

    fn envelope() -> Envelope {
        Envelope {
            schema: "envelope.v1".into(),
            version: 1,
            domain: "envelope".into(),
            ext: Ext::default(),
            signed: signed(),
            envelope_id: "envelope-id".into(),
            source_principal_id: "source".into(),
            source_device_id: "device".into(),
            target_delivery_id: "target".into(),
            routing_set_id: None,
            delivery_class: DeliveryClass::OpaqueEvent,
            priority: Priority::Normal,
            ttl: 60,
            created_at: 0,
            encrypted_payload: "MARKER".into(),
            payload_hash: "hash".into(),
            delivery_mode: None,
            collapse_tag: None,
        }
    }

    fn ack() -> Ack {
        Ack {
            schema: "ack.v1".into(),
            version: 1,
            domain: "ack".into(),
            ext: Ext::default(),
            signed: signed(),
            ack_id: "ack-id".into(),
            envelope_id: "envelope-id".into(),
            receiver_device_id: "MARKER".into(),
            received_at: 0,
            cursor_after: None,
        }
    }

    fn nack() -> Nack {
        Nack {
            schema: "nack.v1".into(),
            version: 1,
            domain: "nack".into(),
            ext: Ext::default(),
            signed: signed(),
            nack_id: "nack-id".into(),
            envelope_id: "envelope-id".into(),
            receiver_device_id: "MARKER".into(),
            reason: NackReason::Expired,
            received_at: 0,
            retry_after: None,
            proof_hash: None,
            new_home_node_hint: None,
        }
    }

    fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(value)
    }

    fn patched(original: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
        let start =
            original.windows(needle.len()).position(|window| window == needle).unwrap_or_default();
        assert_eq!(
            original.windows(needle.len()).filter(|window| *window == needle).count(),
            1,
            "fixture marker is unique"
        );
        let mut result = original.to_vec();
        result.splice(start..start + needle.len(), replacement.iter().copied());
        result
    }

    fn assert_i_json_error<T>(result: Result<T, ProtocolError>) {
        assert_eq!(result.err().map(|error| matches!(error, ProtocolError::IJson(_))), Some(true));
    }

    #[test]
    fn validator_only_checks_original_bytes() {
        assert!(validate_i_json_bytes(br#"{"body":{"x":1,   "y":2}}  "#).is_ok());
        assert_i_json_error(validate_i_json_bytes(br#"{"x":1,"x":1}"#));
        assert_i_json_error(validate_i_json_bytes(br#"{"x":9007199254740992}"#));
        assert_i_json_error(validate_i_json_bytes(br#"{"x":"\ud800"}"#));
        assert_i_json_error(validate_i_json_bytes(br"{} {}"));
    }

    #[derive(Debug)]
    struct ErrorContext(ProtocolError);

    impl std::fmt::Display for ErrorContext {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(&self.0, formatter)
        }
    }

    impl Error for ErrorContext {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn signed_envelope_ijson_predicates() -> Result<(), Box<dyn Error>> {
        let envelope_bytes = bytes(&envelope())?;
        for timestamp in [SAFE, -SAFE] {
            let fixture = patched(
                &envelope_bytes,
                b"\"created_at\":0",
                format!("\"created_at\":{timestamp}").as_bytes(),
            );
            let mut expected = envelope();
            expected.created_at = timestamp;
            let decoded = decode_signed_envelope_ijson(&fixture)?;
            assert_eq!(bytes(&decoded)?, fixture);
            assert_eq!(decoded, expected);
        }
        for timestamp in [UNSAFE, -UNSAFE] {
            let fixture = patched(
                &envelope_bytes,
                b"\"created_at\":0",
                format!("\"created_at\":{timestamp}").as_bytes(),
            );
            assert_i_json_error(decode_signed_envelope_ijson(&fixture));
        }
        let decoded = decode_signed_envelope_ijson(&envelope_bytes)?;
        assert_eq!(bytes(&decoded)?, envelope_bytes);
        assert_eq!(decoded, envelope());

        let ttl_duplicate = patched(&envelope_bytes, b"\"ttl\":60", b"\"ttl\":60,\"ttl\":60");
        assert_i_json_error(decode_signed_envelope_ijson(&ttl_duplicate));
        let envelope_ext = envelope_with_ext();
        let envelope_ext_bytes = bytes(&envelope_ext)?;
        let nested_duplicate = patched(
            &envelope_ext_bytes,
            b"\"x_probe\":\"MARKER\"",
            b"\"x_probe\":\"v\",\"x_probe\":\"v\"",
        );
        assert_i_json_error(decode_signed_envelope_ijson(&nested_duplicate));

        let lone_surrogate = patched(&envelope_bytes, b"MARKER", b"\\ud800");
        assert_i_json_error(decode_signed_envelope_ijson(&lone_surrogate));
        let invalid_utf8 = patched(&envelope_bytes, b"MARKER", &[0xff]);
        assert_i_json_error(decode_signed_envelope_ijson(&invalid_utf8));
        let fdd0 = patched(&envelope_bytes, b"MARKER", &[0xef, 0xb7, 0x90]);
        assert_i_json_error(decode_signed_envelope_ijson(&fdd0));
        let fffe = patched(&envelope_bytes, b"MARKER", &[0xef, 0xbf, 0xbe]);
        assert_i_json_error(decode_signed_envelope_ijson(&fffe));

        let ack_bytes = bytes(&ack())?;
        for timestamp in [SAFE, -SAFE] {
            let fixture = patched(
                &ack_bytes,
                b"\"received_at\":0",
                format!("\"received_at\":{timestamp}").as_bytes(),
            );
            let mut expected = ack();
            expected.received_at = timestamp;
            let decoded = decode_signed_ack_ijson(&fixture)?;
            assert_eq!(bytes(&decoded)?, fixture);
            assert_eq!(decoded, expected);
        }
        for timestamp in [UNSAFE, -UNSAFE] {
            let fixture = patched(
                &ack_bytes,
                b"\"received_at\":0",
                format!("\"received_at\":{timestamp}").as_bytes(),
            );
            assert_i_json_error(decode_signed_ack_ijson(&fixture));
        }
        let decoded = decode_signed_ack_ijson(&ack_bytes)?;
        assert_eq!(bytes(&decoded)?, ack_bytes);
        assert_eq!(decoded, ack());
        let ack_ext_bytes = bytes(&ack_with_ext())?;
        let ack_duplicate = patched(
            &ack_ext_bytes,
            b"\"x_probe\":\"MARKER\"",
            b"\"x_probe\":\"v\",\"x_probe\":\"v\"",
        );
        assert_i_json_error(decode_signed_ack_ijson(&ack_duplicate));
        for replacement in
            [&b"\\ud800"[..], &[0xff][..], &[0xef, 0xb7, 0x90][..], &[0xef, 0xbf, 0xbe][..]]
        {
            let fixture = patched(&ack_bytes, b"MARKER", replacement);
            assert_i_json_error(decode_signed_ack_ijson(&fixture));
        }

        let nack_bytes = bytes(&nack())?;
        for timestamp in [SAFE, -SAFE] {
            let fixture = patched(
                &nack_bytes,
                b"\"received_at\":0",
                format!("\"received_at\":{timestamp}").as_bytes(),
            );
            let mut expected = nack();
            expected.received_at = timestamp;
            let decoded = decode_signed_nack_ijson(&fixture)?;
            assert_eq!(bytes(&decoded)?, fixture);
            assert_eq!(decoded, expected);
        }
        for timestamp in [UNSAFE, -UNSAFE] {
            let fixture = patched(
                &nack_bytes,
                b"\"received_at\":0",
                format!("\"received_at\":{timestamp}").as_bytes(),
            );
            assert_i_json_error(decode_signed_nack_ijson(&fixture));
        }
        let decoded = decode_signed_nack_ijson(&nack_bytes)?;
        assert_eq!(bytes(&decoded)?, nack_bytes);
        assert_eq!(decoded, nack());
        let nack_ext_bytes = bytes(&nack_with_ext())?;
        let nack_duplicate = patched(
            &nack_ext_bytes,
            b"\"x_probe\":\"MARKER\"",
            b"\"x_probe\":\"v\",\"x_probe\":\"v\"",
        );
        assert_i_json_error(decode_signed_nack_ijson(&nack_duplicate));
        for replacement in
            [&b"\\ud800"[..], &[0xff][..], &[0xef, 0xb7, 0x90][..], &[0xef, 0xbf, 0xbe][..]]
        {
            let fixture = patched(&nack_bytes, b"MARKER", replacement);
            assert_i_json_error(decode_signed_nack_ijson(&fixture));
        }

        assert_eq!(
            i_json_rejection_body(),
            serde_json::json!({"error": I_JSON_REJECTED, "reason_code": I_JSON_REJECTED})
        );
        let unsafe_fixture =
            patched(&envelope_bytes, b"\"created_at\":0", b"\"created_at\":9007199254740992");
        let Err(rejection) = decode_signed_envelope_ijson(&unsafe_fixture) else {
            return Err("unsafe integer was accepted".into());
        };
        assert!(is_i_json_rejection(&rejection));
        let wrapped = ErrorContext(rejection);
        assert!(is_i_json_rejection(&wrapped));
        Ok(())
    }

    fn envelope_with_ext() -> Envelope {
        let mut value = envelope();
        value.ext.ext.insert("x_probe".into(), serde_json::json!("MARKER"));
        value
    }

    fn ack_with_ext() -> Ack {
        let mut value = ack();
        value.ext.ext.insert("x_probe".into(), serde_json::json!("MARKER"));
        value
    }

    fn nack_with_ext() -> Nack {
        let mut value = nack();
        value.ext.ext.insert("x_probe".into(), serde_json::json!("MARKER"));
        value
    }
}
