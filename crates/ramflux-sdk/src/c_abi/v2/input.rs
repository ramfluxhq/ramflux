// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded I-JSON ingress with wiping ownership, including incomplete values and strings.
use super::super::{CAbiError, RamfluxErrorCode};
use serde_json::{Map, Number, Value};
use zeroize::{Zeroize, Zeroizing};

pub(super) fn invalid() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, "input")
}
pub(super) struct Wiping(pub Value);
impl Drop for Wiping {
    fn drop(&mut self) {
        crate::bus::inprocess::erase_value(&mut self.0);
    }
}
impl Wiping {
    pub fn take(&mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}
pub(super) trait Decode: Sized {
    fn decode(value: &mut Value) -> Result<Self, CAbiError>;
}

pub(super) fn decode<T: Decode>(bytes: &[u8]) -> Result<T, CAbiError> {
    if bytes.is_empty() || bytes.len() > super::state::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut parser = Parser { bytes, cursor: 0, remaining: 4096 };
    let mut value = parser.value(0)?;
    parser.space();
    if parser.cursor != bytes.len() {
        return Err(invalid());
    }
    T::decode(&mut value.0)
}
struct Parser<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }
    fn byte(&mut self) -> Result<u8, CAbiError> {
        let b = self.peek().ok_or_else(invalid)?;
        self.cursor += 1;
        Ok(b)
    }
    fn space(&mut self) {
        while self.peek().is_some_and(|b| matches!(b, b' ' | b'\r' | b'\n' | b'\t')) {
            self.cursor += 1;
        }
    }
    fn value(&mut self, depth: usize) -> Result<Wiping, CAbiError> {
        if depth > 32 || self.remaining == 0 {
            return Err(invalid());
        }
        self.remaining -= 1;
        self.space();
        match self.peek().ok_or_else(invalid)? {
            b'"' => Ok(Wiping(Value::String(std::mem::take(&mut *self.string()?)))),
            b'{' | b'[' => self.container(depth),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(invalid()),
        }
    }
    fn literal(&mut self, token: &[u8], value: Value) -> Result<Wiping, CAbiError> {
        for expected in token {
            if self.byte()? != *expected {
                return Err(invalid());
            }
        }
        Ok(Wiping(value))
    }
    fn container(&mut self, depth: usize) -> Result<Wiping, CAbiError> {
        let object = self.byte()? == b'{';
        let end = if object { b'}' } else { b']' };
        let mut result =
            Wiping(if object { Value::Object(Map::new()) } else { Value::Array(Vec::new()) });
        self.space();
        if self.peek() == Some(end) {
            self.cursor += 1;
            return Ok(result);
        }
        loop {
            self.space();
            let key = if object {
                let k = self.string()?;
                self.space();
                if self.byte()? != b':' {
                    return Err(invalid());
                }
                Some(k)
            } else {
                None
            };
            let mut child = self.value(depth + 1)?;
            match (&mut result.0, key) {
                (Value::Object(map), Some(mut key)) => {
                    if map.contains_key(key.as_str()) {
                        return Err(invalid());
                    }
                    map.insert(std::mem::take(&mut *key), child.take());
                }
                (Value::Array(values), None) => values.push(child.take()),
                _ => return Err(invalid()),
            }
            self.space();
            match self.byte()? {
                b if b == end => return Ok(result),
                b',' => {}
                _ => return Err(invalid()),
            }
        }
    }
    fn hex(&mut self) -> Result<u32, CAbiError> {
        let mut value = 0;
        for _ in 0..4 {
            let b = self.byte()?;
            let n = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(invalid()),
            };
            value = value * 16 + u32::from(n);
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<Zeroizing<String>, CAbiError> {
        if self.byte()? != b'"' {
            return Err(invalid());
        }
        // Find the exact upper bound before allocating. No secret-bearing reallocation.
        let start = self.cursor;
        let mut end = start;
        let mut escaped = false;
        loop {
            let b = *self.bytes.get(end).ok_or_else(invalid)?;
            end += 1;
            if !escaped && b == b'"' {
                break;
            }
            escaped = !escaped && b == b'\\';
        }
        let size = end.saturating_sub(start).saturating_sub(1);
        let mut output = Zeroizing::new(vec![0; size]);
        let mut written = 0;
        while self.cursor < end.saturating_sub(1) {
            let b = self.byte()?;
            if b < 32 {
                return Err(invalid());
            }
            if b != b'\\' {
                *output.get_mut(written).ok_or_else(invalid)? = b;
                written += 1;
                continue;
            }
            let b = self.byte()?;
            let simple = match b {
                b'"' => Some(b'"'),
                b'\\' => Some(b'\\'),
                b'/' => Some(b'/'),
                b'b' => Some(8),
                b'f' => Some(12),
                b'n' => Some(10),
                b'r' => Some(13),
                b't' => Some(9),
                b'u' => None,
                _ => return Err(invalid()),
            };
            if let Some(b) = simple {
                *output.get_mut(written).ok_or_else(invalid)? = b;
                written += 1;
                continue;
            }
            let mut cp = self.hex()?;
            if (0xd800..=0xdbff).contains(&cp) {
                if self.byte()? != b'\\' || self.byte()? != b'u' {
                    return Err(invalid());
                }
                let low = self.hex()?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Err(invalid());
                }
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            }
            let ch = char::from_u32(cp).ok_or_else(invalid)?;
            let mut utf8 = Zeroizing::new([0; 4]);
            for b in ch.encode_utf8(&mut *utf8).bytes() {
                *output.get_mut(written).ok_or_else(invalid)? = b;
                written += 1;
            }
            utf8.zeroize();
        }
        if self.cursor != end.saturating_sub(1) || self.byte()? != b'"' {
            return Err(invalid());
        }
        output.truncate(written);
        let value = String::from_utf8(std::mem::take(&mut *output)).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            invalid()
        })?;
        let value = Zeroizing::new(value);
        if value.chars().any(|c| {
            let n = u32::from(c);
            (0xfdd0..=0xfdef).contains(&n) || n & 0xffff >= 0xfffe
        }) {
            return Err(invalid());
        }
        Ok(value)
    }
    fn digits(&mut self) -> usize {
        let start = self.cursor;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.cursor += 1;
        }
        self.cursor - start
    }
    fn number(&mut self) -> Result<Wiping, CAbiError> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        if self.peek() == Some(b'0') {
            self.cursor += 1;
            if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
        } else if self.digits() == 0 {
            return Err(invalid());
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.cursor += 1;
            if self.digits() == 0 {
                return Err(invalid());
            }
        }
        if self.peek().is_some_and(|b| matches!(b, b'e' | b'E')) {
            float = true;
            self.cursor += 1;
            if self.peek().is_some_and(|b| matches!(b, b'+' | b'-')) {
                self.cursor += 1;
            }
            if self.digits() == 0 {
                return Err(invalid());
            }
        }
        let token = std::str::from_utf8(self.bytes.get(start..self.cursor).ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let n = if float {
            let value = token.parse::<f64>().map_err(|_| invalid())?;
            if value == 0.0
                && token
                    .split(['e', 'E'])
                    .next()
                    .unwrap_or("")
                    .bytes()
                    .any(|b| matches!(b, b'1'..=b'9'))
            {
                return Err(invalid());
            }
            Number::from_f64(value).ok_or_else(invalid)?
        } else if token == "-0" {
            Number::from_f64(-0.0).ok_or_else(invalid)?
        } else {
            let n = token.parse::<i64>().map_err(|_| invalid())?;
            if n.unsigned_abs() > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
                return Err(invalid());
            }
            n.into()
        };
        Ok(Wiping(Value::Number(n)))
    }
}

pub(super) fn object(value: &Value, fields: &[&str]) -> Result<(), CAbiError> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map.keys().any(|k| !fields.contains(&k.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CAbiError> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
pub(super) fn optional<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, CAbiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(invalid()),
    }
}
pub(super) fn boolean(value: &Value, key: &str, default: Option<bool>) -> Result<bool, CAbiError> {
    match value.get(key) {
        Some(Value::Bool(v)) => Ok(*v),
        None => default.ok_or_else(invalid),
        _ => Err(invalid()),
    }
}
pub(super) fn unsigned(value: &Value, key: &str, default: Option<u64>) -> Result<u64, CAbiError> {
    match value.get(key) {
        None => default.ok_or_else(invalid),
        Some(Value::String(v)) => v.parse().map_err(|_| invalid()),
        Some(v) => v.as_u64().ok_or_else(invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    impl Decode for Wiping {
        fn decode(v: &mut Value) -> Result<Self, CAbiError> {
            Ok(Self(std::mem::take(v)))
        }
    }
    #[test]
    fn wiping_parser_matches_shared_ijson_on_escapes_numbers_duplicates_and_unicode() {
        let cases: &[&[u8]] = &[
            br#"{"text":"escaped\n\u263a","key":null}"#,
            br#"{"text":"\ud83d\ude00","number":-0}"#,
            br"[1.0,-1.5,1e3,9007199254740991,true,false]",
            br#"{"a":1,"\u0061":2}"#,
            br"[9007199254740992]",
            br"[1e400]",
            br"[1e-4000]",
            br#"{"text":"\ud800"}"#,
            br#"{"text":"\ufdd0"}"#,
            br"[01]",
            br"[1,]",
            br#"{"a":1,}"#,
            br"[.5]",
            br"[1.]",
            b"[\"unterminated",
            b"[true] trailing",
        ];
        for bytes in cases {
            let actual = decode::<Wiping>(bytes);
            let expected = ramflux_protocol::parse_i_json::<Value>(bytes);
            assert_eq!(
                actual.is_ok(),
                expected.is_ok(),
                "wiping parser must preserve the shared ingress predicate for {:?}",
                String::from_utf8_lossy(bytes)
            );
            if let (Ok(actual), Ok(expected)) = (actual, expected) {
                assert_eq!(
                    actual.0, expected,
                    "typed JSON value must preserve Unicode and number semantics"
                );
            }
        }
    }
    #[test]
    fn wiping_parser_differential_bounded_generated_inputs() {
        const CASES: usize = 2048;
        const MAX_BYTES: usize = 256;
        const SEEDS: &[&[u8]] = &[
            br#"{"text":"hello\n\u263a","items":[1,true,null]}"#,
            br"[0,-0,1.25,1e3,9007199254740991]",
            br#"{"a":1,"a":2}"#,
            br#""\ud83d\ude00""#,
            br"[1e-4000,1e400]",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        };
        let mut accepted = 0;
        for case in 0..CASES {
            let mut bytes = if case % 3 == 0 {
                let len = usize::from(next()) % MAX_BYTES;
                (0..len).map(|_| next()).collect::<Vec<_>>()
            } else {
                SEEDS[case % SEEDS.len()].to_vec()
            };
            if case % 3 == 1 && !bytes.is_empty() {
                let index = usize::from(next()) % bytes.len();
                bytes[index] = next();
            }
            let actual = decode::<Wiping>(&bytes);
            let expected = ramflux_protocol::parse_i_json::<Value>(&bytes);
            assert_eq!(
                actual.is_ok(),
                expected.is_ok(),
                "parser predicate diverged at case {case}: {bytes:?}"
            );
            if let (Ok(actual), Ok(expected)) = (actual, expected) {
                accepted += 1;
                assert_eq!(actual.0, expected, "parser value diverged at case {case}");
            }
        }
        assert!(accepted > 100, "differential corpus must exercise successful decoding too");
    }
}
