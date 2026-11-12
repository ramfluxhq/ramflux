// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current replay identities only; historical shapes require explicit store reset.
use serde::{Deserialize, Deserializer, de::Error};
use std::collections::BTreeMap;

pub(super) fn deserialize_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, i64>, D::Error> {
    let entries = BTreeMap::<String, i64>::deserialize(deserializer)?;
    if entries.keys().any(|key| !current_key(key)) {
        return Err(D::Error::custom("unsupported replay identity; reset the node state"));
    }
    Ok(entries)
}
fn current_key(key: &str) -> bool {
    key.strip_prefix("request/v2/").is_some_and(|hash| {
        ramflux_protocol::decode_base64url(hash).is_ok_and(|bytes| {
            bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == hash
        })
    }) || key.strip_prefix("envelope/v3/").is_some_and(|tail| {
        let Some((source, tail)) = tail.split_once('/') else {
            return false;
        };
        let Some((envelope, target)) = tail.split_once('/') else {
            return false;
        };
        ramflux_protocol::parse_qualified_device_id(source).is_ok_and(|value| value.is_some())
            && [envelope, target].iter().all(|value| {
                ramflux_protocol::decode_base64url(value)
                    .is_ok_and(|bytes| ramflux_protocol::encode_base64url(bytes) == *value)
            })
    })
}
