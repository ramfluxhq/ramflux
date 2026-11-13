// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only protobuf projection skips keys, thumbnails, forwarding and private entropy.
use super::SearchError;
use crate::SdkError;
use prost::Message as _;
use ramflux_protocol::message as g;
use serde::Deserialize as _;
use zeroize::Zeroize as _;

#[derive(Clone, PartialEq, prost::Message, serde::Deserialize)]
#[prost(skip_debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct DisplayMessage {
    #[serde(default)]
    #[prost(string, tag = "1")]
    pub text: String,
    #[serde(default)]
    #[prost(message, repeated, tag = "2")]
    pub entities: Vec<DisplayEntity>,
    #[serde(default)]
    #[prost(message, repeated, tag = "5")]
    pub media: Vec<DisplayMedia>,
    #[serde(default)]
    #[prost(message, optional, tag = "16")]
    #[serde(alias = "sealed_group")]
    pub sealed_group: Option<Concealed>,
}
impl Drop for DisplayMessage {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}
#[derive(Clone, PartialEq, prost::Message, serde::Deserialize)]
#[prost(skip_debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct DisplayEntity {
    #[serde(default)]
    #[prost(enumeration = "g::EntityKind", tag = "3")]
    #[serde(deserialize_with = "entity_kind")]
    pub kind: i32,
}
#[derive(Clone, PartialEq, prost::Message, serde::Deserialize)]
#[prost(skip_debug)]
#[serde(rename_all = "camelCase")]
pub(super) struct DisplayMedia {
    #[serde(default)]
    #[prost(string, tag = "1")]
    #[serde(alias = "object_id")]
    pub object_id: String,
    #[serde(default, deserialize_with = "digest_bytes", alias = "manifest_digest")]
    #[prost(bytes = "vec", tag = "2")]
    pub manifest_digest: Vec<u8>,
    #[serde(default)]
    #[prost(string, optional, tag = "6")]
    #[serde(alias = "file_name")]
    pub file_name: Option<String>,
}
impl Drop for DisplayMedia {
    fn drop(&mut self) {
        self.object_id.zeroize();
        self.manifest_digest.zeroize();
        self.file_name.zeroize();
    }
}
#[derive(Clone, PartialEq, prost::Message, serde::Deserialize)]
#[prost(skip_debug)]
pub(super) struct Concealed {}
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct Replacement {
    #[prost(message, optional, tag = "4")]
    replacement: Option<DisplayMessage>,
}

pub(super) fn decode(bytes: &[u8]) -> Result<Option<DisplayMessage>, SdkError> {
    let scanned = g::validation::scan_inner(bytes).map_err(|_| SearchError::IndexUnavailable)?;
    if scanned.outcome != g::validation::ScanOutcome::Supported {
        return Ok(None);
    }
    let display = match scanned.kind {
        1 => Some(DisplayMessage::decode(scanned.body).map_err(|_| SearchError::IndexUnavailable)?),
        3 => {
            Replacement::decode(scanned.body)
                .map_err(|_| SearchError::IndexUnavailable)?
                .replacement
        }
        _ => None,
    };
    Ok(display)
}

fn entity_kind<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(name) => g::EntityKind::from_str_name(&name)
            .map(|kind| kind as i32)
            .ok_or_else(|| serde::de::Error::custom("invalid entity kind")),
        serde_json::Value::Number(number) => number
            .as_i64()
            .and_then(|number| i32::try_from(number).ok())
            .ok_or_else(|| serde::de::Error::custom("invalid entity kind")),
        _ => Err(serde::de::Error::custom("invalid entity kind")),
    }
}

fn digest_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.len() > 44 {
        return Err(serde::de::Error::custom("invalid media digest"));
    }
    let normalized = value.trim_end_matches('=').replace('+', "-").replace('/', "_");
    let decoded = ramflux_protocol::decode_base64url(&normalized)
        .map_err(|_| serde::de::Error::custom("invalid media digest"))?;
    if decoded.len() != 32 {
        return Err(serde::de::Error::custom("invalid media digest"));
    }
    Ok(decoded)
}
