// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent names: the grammar PRX enforces, the reserved names, and the rf-derived form
//! `a_` + 52 lowercase base32 characters encoding a 32-byte anchor.

use crate::error::{local_refusal, ApiCode, PrxError};
use serde::{Deserialize, Deserializer};

const NAME_MAX_LEN: usize = 64;
const RF_PREFIX: &str = "a_";
const ANCHOR_BYTES: usize = 32;
/// Names PRX refuses for named agents. Matches the catalog's `reserved_names`; a test checks it.
const RESERVED: [&str; 2] = ["catalog", "main"];

/// A valid, non-reserved agent name. Refusals are local and carry the code PRX would return.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentName(String);

impl AgentName {
    /// Parses `[a-z][a-z0-9_-]{0,63}`, refusing `main` and `catalog`.
    ///
    /// # Errors
    /// Returns `PrxError::Api` with `agent_invalid` (400) when the name is refused. Nothing is sent.
    pub fn parse(raw: &str) -> Result<Self, PrxError> {
        if is_grammar(raw) && !RESERVED.contains(&raw) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(local_refusal(ApiCode::AgentInvalid))
        }
    }

    /// The rf-derived name for a 32-byte anchor: `a_` followed by 52 lowercase base32 characters.
    #[must_use]
    pub fn from_anchor(anchor: &[u8; ANCHOR_BYTES]) -> Self {
        Self(format!("{RF_PREFIX}{}", base32_lower(anchor)))
    }

    /// The name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when the name is `a_` plus a canonical encoding of 32 bytes (an rf-derived name).
    /// Hand-written agents return false; they are never an error.
    #[must_use]
    pub fn is_rf_derived(&self) -> bool {
        self.0
            .strip_prefix(RF_PREFIX)
            .and_then(base32_decode)
            .is_some_and(|bytes| bytes.len() == ANCHOR_BYTES)
    }
}

impl<'de> Deserialize<'de> for AgentName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| serde::de::Error::custom("agent name is not valid"))
    }
}

fn is_grammar(raw: &str) -> bool {
    let Some((first, rest)) = raw.as_bytes().split_first() else {
        return false;
    };
    raw.len() <= NAME_MAX_LEN
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

fn symbol(value: u32) -> char {
    let v = u8::try_from(value & 31).unwrap_or(0);
    if v < 26 {
        char::from(b'a' + v)
    } else {
        char::from(b'2' + (v - 26))
    }
}

fn symbol_value(byte: u8) -> Option<u32> {
    match byte {
        b'a'..=b'z' => Some(u32::from(byte - b'a')),
        b'2'..=b'7' => Some(u32::from(byte - b'2') + 26),
        _ => None,
    }
}

/// RFC 4648 base32, lowercase, unpadded.
fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol(buffer >> bits));
        }
        buffer &= (1_u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(symbol(buffer << (5 - bits)));
    }
    out
}

/// Decodes lowercase unpadded base32. Non-zero trailing bits are refused (canonical form only).
fn base32_decode(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in raw.bytes() {
        buffer = (buffer << 5) | symbol_value(byte)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
            buffer &= (1_u32 << bits) - 1;
        }
    }
    if buffer != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_gives_54_characters_and_round_trips() {
        let name = AgentName::from_anchor(&[0_u8; ANCHOR_BYTES]);
        assert_eq!(name.as_str().len(), 54, "a_ plus 52 base32 characters");
        assert_eq!(name.as_str(), format!("a_{}", "a".repeat(52)));
        let parsed = AgentName::parse(name.as_str()).expect("test: anchor name is valid");
        assert_eq!(parsed, name);
        assert!(name.is_rf_derived());
    }

    #[test]
    fn last_character_carries_the_leftover_bit() {
        let name = AgentName::from_anchor(&[0xff_u8; ANCHOR_BYTES]);
        assert_eq!(name.as_str(), format!("a_{}q", "7".repeat(51)), "51 full groups then one bit padded to q");
        assert!(name.is_rf_derived());
    }

    #[test]
    fn non_canonical_or_hand_written_names_are_not_rf_derived() {
        let hand = AgentName::parse("worker1").expect("test: hand-written name parses");
        assert!(!hand.is_rf_derived());
        let short = AgentName::parse(&format!("a_{}", "a".repeat(51))).expect("test: grammar-valid");
        assert!(!short.is_rf_derived(), "51 characters decode to 31 bytes");
        let dirty = AgentName::parse(&format!("a_{}b", "a".repeat(51))).expect("test: grammar-valid");
        assert!(!dirty.is_rf_derived(), "non-zero trailing bits are not canonical");
    }

    #[test]
    fn grammar_bounds() {
        let long = format!("a{}", "b".repeat(63));
        for good in ["a", "a_b-c9", long.as_str()] {
            assert!(AgentName::parse(good).is_ok(), "valid name refused: {good}");
        }
        let too_long = format!("a{}", "b".repeat(64));
        for bad in ["", "1abc", "A_BAD", "a b", "a.b", too_long.as_str()] {
            assert!(
                matches!(AgentName::parse(bad), Err(PrxError::Api { status: 400, code: ApiCode::AgentInvalid, .. })),
                "invalid name must be refused as agent_invalid: {bad:?}"
            );
        }
    }

    #[test]
    fn reserved_names_are_refused_before_any_request() {
        for reserved in RESERVED {
            assert!(
                matches!(AgentName::parse(reserved), Err(PrxError::Api { code: ApiCode::AgentInvalid, .. })),
                "reserved name must be refused: {reserved}"
            );
        }
    }

    #[test]
    fn base32_decode_refuses_non_canonical_and_foreign_characters() {
        assert_eq!(base32_decode("aa").map(|b| b.len()), Some(1), "10 bits give one byte");
        assert!(base32_decode("ab").is_none(), "non-zero leftover bit is refused");
        assert!(base32_decode("A").is_none(), "uppercase is refused");
        assert!(base32_decode("0").is_none(), "digits outside 2-7 are refused");
    }
}
