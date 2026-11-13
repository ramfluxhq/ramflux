// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Only current root-qualified replay identities may enter persisted authority.
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;

pub(super) fn deserialize_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, i64>, D::Error> {
    let entries = BTreeMap::<String, i64>::deserialize(deserializer)?;
    if entries.keys().any(|key| !is_current_key(key)) {
        return Err(serde::de::Error::custom("unsupported persisted replay identity"));
    }
    Ok(entries)
}

pub(crate) fn is_current_key(key: &str) -> bool {
    key.strip_prefix("request/v2/").is_some_and(|hash| {
        ramflux_protocol::decode_base64url(hash).is_ok_and(|bytes| bytes.len() == 32)
    }) || key.strip_prefix("envelope/v3/").is_some_and(|suffix| {
        suffix.split_once('/').is_some_and(|(source, tail)| {
            let Some((envelope, target)) = tail.split_once('/') else {
                return false;
            };
            ramflux_protocol::parse_qualified_device_id(source).is_ok_and(|value| value.is_some())
                && ramflux_protocol::decode_base64url(envelope).is_ok()
                && ramflux_protocol::decode_base64url(target).is_ok()
        })
    })
}

pub(crate) fn require_current_key(key: &str) -> Result<(), crate::NodeCoreError> {
    if !is_current_key(key) {
        return Err(crate::NodeCoreError::UnsupportedPersistedFormat("router replay identity"));
    }
    Ok(())
}
