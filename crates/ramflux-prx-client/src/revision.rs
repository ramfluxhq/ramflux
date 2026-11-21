// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Revision values. The config revision and the catalog revision are distinct types, so one
//! cannot be passed where the other is expected.

use crate::error::config;
use crate::error::PrxError;
use serde::{Deserialize, Deserializer};

fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

macro_rules! revision_type {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            /// Parses a 64-character lowercase hex SHA-256 revision.
            ///
            /// # Errors
            /// Returns `PrxError::Config` when the text is not 64 lowercase hex characters.
            pub fn parse(raw: &str) -> Result<Self, PrxError> {
                if is_sha256_hex(raw) {
                    Ok(Self(raw.to_owned()))
                } else {
                    Err(config(concat!($what, " is not 64 lowercase hex")))
                }
            }

            /// The revision text, as sent in `If-Match` or read from a body.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                if is_sha256_hex(&raw) {
                    Ok(Self(raw))
                } else {
                    Err(serde::de::Error::custom(concat!($what, " is not 64 lowercase hex")))
                }
            }
        }
    };
}

revision_type!(
    /// Config revision: SHA-256 over the PRX configuration files. Used by the agent routes.
    ConfigRevision,
    "config revision"
);

revision_type!(
    /// Catalog revision: SHA-256 of the catalog body. Never matches an agent route's `If-Match`.
    CatalogRevision,
    "catalog revision"
);

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_64_lowercase_hex() {
        let parsed = ConfigRevision::parse(HEX64).expect("test: valid revision parses");
        assert_eq!(parsed.as_str(), HEX64, "revision text must round-trip unchanged");
    }

    #[test]
    fn refuses_uppercase_short_and_non_hex() {
        for bad in [
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef",
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "",
        ] {
            assert!(
                matches!(ConfigRevision::parse(bad), Err(PrxError::Config { .. })),
                "non-conforming revision must be refused: {bad}"
            );
        }
    }

    #[test]
    fn deserialization_refuses_a_bad_revision() {
        let parsed: Result<CatalogRevision, _> = serde_json::from_str("\"not-a-revision\"");
        assert!(parsed.is_err(), "a malformed catalog revision must not decode");
    }
}
