// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Isolate persisted replay rows whose originating root cannot be recovered.
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

pub(super) fn deserialize_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, i64>, D::Error> {
    Ok(BTreeMap::<String, i64>::deserialize(deserializer)?
        .into_iter()
        .map(|(key, expiry)| (isolate_unknown_key(key), expiry))
        .collect())
}
pub(super) fn isolate_unknown_key(key: String) -> String {
    let current = key.strip_prefix("request/v2/").is_some_and(|hash| {
        ramflux_protocol::decode_base64url(hash).is_ok_and(|bytes| bytes.len() == 32)
    }) || key.strip_prefix("envelope/v2/").is_some_and(|suffix| {
        suffix.split_once('/').is_some_and(|(source, envelope)| {
            ramflux_protocol::parse_qualified_device_id(source).is_ok_and(|value| value.is_some())
                && ramflux_protocol::decode_base64url(envelope).is_ok()
        })
    });
    if current || key.starts_with("legacy/replay/") {
        key
    } else {
        format!("legacy/replay/{}", ramflux_protocol::encode_base64url(key))
    }
}
