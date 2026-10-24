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
use std::fmt;

pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

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
