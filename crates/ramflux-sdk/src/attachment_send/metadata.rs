// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable client-supplied media hints accepted with the plaintext commitment.
use super::codes::{CODE_LAYOUT_INVALID, Refusal};
use ramflux_protocol::message::Thumbnail;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Metadata {
    pub width: Option<u32>,
    pub height: Option<u32>,
    #[serde(default, with = "duration")]
    pub duration_ms: Option<u64>,
    pub animated: Option<bool>,
}

impl Metadata {
    pub(super) fn validate(&self) -> Result<(), Refusal> {
        ramflux_protocol::message::media_metadata::validate_dimensions(self.width, self.height)
            .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
    }
}

pub(crate) struct Finished {
    pub digest: [u8; 32],
    pub thumbnail: Option<Thumbnail>,
    pub metadata: Metadata,
}

/// Exact u64 durations across I-JSON and durable JSON; never round through f64.
pub(super) mod duration {
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Decimal(String),
        Number(u64),
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        Option::<Value>::deserialize(d)?
            .map(|v| match v {
                Value::Number(n) if n <= 9_007_199_254_740_991 => Ok(n),
                Value::Decimal(s)
                    if !s.is_empty()
                        && s.len() <= 20
                        && s.bytes().all(|b| b.is_ascii_digit())
                        && (s == "0" || !s.starts_with('0')) =>
                {
                    s.parse().map_err(serde::de::Error::custom)
                }
                _ => Err(serde::de::Error::custom("duration_ms must be an exact unsigned decimal")),
            })
            .transpose()
    }

    #[allow(clippy::ref_option)] // serde `with` passes the declared field by reference.
    pub(crate) fn serialize<S: Serializer>(value: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }
}
