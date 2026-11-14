// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed v3 event frames and the upstream four mutation envelopes.
use crate::{MAX_SAFE_JSON_INTEGER, ProtocolError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const CATALOG_ID: &str = "urn:ramflux:catalog:rf-card:1.0";
pub const EVENT_SCHEMA: &str = "ramflux.surface.event.v3";
pub const ACTION_SCHEMA: &str = "ramflux.surface.action.v3";
pub const MAX_STATE_BYTES: usize = 16 * 1024;
pub const MAX_MODEL_BYTES: usize = 12 * 1024;
pub const MAX_DELTA_BYTES: usize = 4 * 1024;
pub const MAX_COMPONENTS: usize = 32;
pub const MAX_FINAL_RECORDS: usize = 64;
pub const MAX_CONTEXT_ENTRIES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "reject", content = "detail", rename_all = "snake_case")]
pub enum Reject {
    #[error("INTEGRITY_ERROR")]
    Integrity,
    #[error("VALIDATION_FAILED: {0}")]
    Validation(String),
    #[error("VALIDATION_FAILED: locale-sensitive button check")]
    LocaleDependentCheck,
    #[error("EXPRESSION_ERROR")]
    Expression,
    #[error("surface version: expected {expected}, received {actual}")]
    Version { expected: u64, actual: u64 },
    #[error("surface version or hash conflict")]
    Conflict,
    #[error("surface is terminally closed")]
    Closed,
    #[error("surface has not been created")]
    NotCreated,
    #[error("surface already exists")]
    AlreadyCreated,
    #[error("surface resource limit exceeded")]
    Limit,
    #[error("invalid canonical I-JSON")]
    Encoding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub extensions: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSurface {
    pub surface_id: String,
    pub catalog_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_data_model: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_model: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateComponents {
    pub surface_id: String,
    pub components: Vec<Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateDataModel {
    pub surface_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteSurface {
    pub surface_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mutation {
    CreateSurface(CreateSurface),
    UpdateComponents(UpdateComponents),
    UpdateDataModel(UpdateDataModel),
    DeleteSurface(DeleteSurface),
}
impl Mutation {
    #[must_use]
    pub fn surface_id(&self) -> &str {
        match self {
            Self::CreateSurface(v) => &v.surface_id,
            Self::UpdateComponents(v) => &v.surface_id,
            Self::UpdateDataModel(v) => &v.surface_id,
            Self::DeleteSurface(v) => &v.surface_id,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationMessage {
    pub version: String,
    #[serde(flatten)]
    pub mutation: Mutation,
}
impl MutationMessage {
    #[must_use]
    pub fn new(mutation: Mutation) -> Self {
        Self { version: "1.0".into(), mutation }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendText {
    pub surface_id: String,
    pub path: String,
    pub delta: String,
    #[serde(rename = "final")]
    pub final_: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalRecord {
    pub pointer: String,
    pub text_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resync {
    pub a2ui: MutationMessage,
}

/// Local event intent. Only validated original bytes produce a received event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventFrame {
    pub schema: String,
    pub conversation_id: String,
    pub surface_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_surface_hash: Option<String>,
    pub new_surface_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2ui: Option<MutationMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append_text: Option<AppendText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resync: Option<Resync>,
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_: Option<Vec<FinalRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceEvent(EventFrame);
impl SurfaceEvent {
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.0.surface_version
    }
    #[must_use]
    pub fn is_create(&self) -> bool {
        matches!(self.0.a2ui.as_ref().map(|m| &m.mutation), Some(Mutation::CreateSurface(_)))
    }
    #[must_use]
    pub fn is_resync(&self) -> bool {
        self.0.resync.is_some()
    }

    /// Decode original signed bytes, retaining duplicate-key and canonicality evidence.
    /// # Errors
    /// Rejects malformed, noncanonical, open, out-of-profile or ambiguous frames.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Reject> {
        let raw: Value = decode_canonical(bytes, MAX_STATE_BYTES * 2 + MAX_DELTA_BYTES)?;
        reject_null_fields(
            &raw,
            &[
                "baseSurfaceHash",
                "fallbackText",
                "closeReason",
                "a2ui",
                "appendText",
                "resync",
                "final",
                "closed",
                "metadata",
            ],
        )?;
        for key in ["a2ui", "resync"] {
            if let Some(message) = raw.get(key) {
                let message = if key == "resync" {
                    message.get("a2ui").ok_or(Reject::Encoding)?
                } else {
                    message
                };
                validate_message_keys(message)?;
            }
        }
        let frame: EventFrame = serde_json::from_value(raw).map_err(|_| Reject::Encoding)?;
        frame.validate()?;
        Ok(Self(frame))
    }
    #[must_use]
    pub const fn frame(&self) -> &EventFrame {
        &self.0
    }
    #[must_use]
    pub fn surface_id(&self) -> &str {
        self.0.surface_id()
    }
}
impl EventFrame {
    #[must_use]
    pub fn surface_id(&self) -> &str {
        if let Some(m) = &self.a2ui {
            return m.mutation.surface_id();
        }
        if let Some(a) = &self.append_text {
            return &a.surface_id;
        }
        self.resync.as_ref().map_or("", |r| r.a2ui.mutation.surface_id())
    }
    /// Encode and validate locally authored intent before signing.
    /// # Errors
    /// Rejects invalid schemas, operations, identifiers or bounds.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, Reject> {
        let bytes = canonical(self)?;
        SurfaceEvent::from_wire_bytes(&bytes)?;
        Ok(bytes)
    }
    fn validate(&self) -> Result<(), Reject> {
        if self.schema != EVENT_SCHEMA
            || self.conversation_id.is_empty()
            || self.conversation_id.len() > 256
            || !(1..=MAX_SAFE_JSON_INTEGER).contains(&self.surface_version)
            || self.new_surface_hash.is_empty()
            || usize::from(self.a2ui.is_some())
                + usize::from(self.append_text.is_some())
                + usize::from(self.resync.is_some())
                != 1
        {
            return Err(Reject::Encoding);
        }
        identifier(self.surface_id())?;
        if let Some(message) = self.a2ui.as_ref().or_else(|| self.resync.as_ref().map(|r| &r.a2ui))
        {
            if message.version != "1.0" {
                return Err(Reject::Encoding);
            }
            if let Mutation::CreateSurface(c) = &message.mutation {
                if c.catalog_id != CATALOG_ID || c.send_data_model == Some(true) {
                    return Err(Reject::Validation("catalogId/sendDataModel".into()));
                }
                validate_metadata(c.metadata.as_ref())?;
            }
        }
        let create =
            matches!(self.a2ui.as_ref().map(|m| &m.mutation), Some(Mutation::CreateSurface(_)));
        let delete =
            matches!(self.a2ui.as_ref().map(|m| &m.mutation), Some(Mutation::DeleteSurface(_)));
        if create && (self.base_surface_hash.is_some() || self.fallback_text.is_none())
            || self.close_reason.is_some() && !delete
            || self.resync.is_none()
                && (self.final_.is_some() || self.closed.is_some() || self.metadata.is_some())
            || !create && self.resync.is_none() && self.base_surface_hash.is_none()
            || !create && self.resync.is_none() && self.fallback_text.is_some()
        {
            return Err(Reject::Encoding);
        }
        if let Some(r) = &self.resync {
            if !matches!(r.a2ui.mutation, Mutation::CreateSurface(_))
                || self.final_.is_none()
                || self.closed.is_none()
                || self.fallback_text.is_none()
            {
                return Err(Reject::Encoding);
            }
            validate_metadata(self.metadata.as_ref())?;
        }
        Ok(())
    }
}

pub(super) fn validate_message_keys(message: &Value) -> Result<(), Reject> {
    let map = message.as_object().ok_or(Reject::Encoding)?;
    if let Some(create) = map.get("createSurface") {
        reject_null_fields(
            create,
            &["catalogId", "sendDataModel", "components", "dataModel", "metadata"],
        )?;
    }
    if let Some(update) = map.get("updateDataModel") {
        reject_null_fields(update, &["path"])?;
    }

    if map.len() != 2
        || map.get("version").and_then(Value::as_str) != Some("1.0")
        || !["createSurface", "updateComponents", "updateDataModel", "deleteSurface"]
            .iter()
            .any(|key| map.contains_key(*key))
    {
        return Err(Reject::Encoding);
    }
    Ok(())
}
pub(super) fn validate_metadata(metadata: Option<&Metadata>) -> Result<(), Reject> {
    if let Some(m) = metadata {
        if m.extensions.is_empty() {
            return Err(Reject::Encoding);
        }
        for key in m.extensions.keys() {
            identifier(key)?;
        }
    }
    Ok(())
}
pub(super) fn identifier(id: &str) -> Result<(), Reject> {
    let mut bytes = id.bytes();
    let first = bytes.next().ok_or_else(|| Reject::Validation("identifier".into()))?;
    if id.len() > 64
        || !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || matches!(id, "__proto__" | "prototype" | "constructor")
    {
        return Err(Reject::Validation("identifier".into()));
    }
    Ok(())
}
pub(super) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Reject> {
    let value = serde_json::to_value(value).map_err(|_| Reject::Encoding)?;
    crate::validate_i_json_value(&value).map_err(|_| Reject::Encoding)?;
    crate::canonical_json_bytes(&value).map_err(|_| Reject::Encoding)
}
pub(super) fn decode_canonical<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    cap: usize,
) -> Result<T, Reject> {
    if bytes.len() > cap {
        return Err(Reject::Limit);
    }
    let value: Value = crate::parse_i_json(bytes).map_err(|_: ProtocolError| Reject::Encoding)?;
    if canonical(&value)? != bytes {
        return Err(Reject::Encoding);
    }
    serde_json::from_value(value).map_err(|_| Reject::Encoding)
}

/// Static per-release renderer capability metadata, using the pinned upstream transport key.
#[must_use]
pub fn renderer_capabilities() -> Value {
    serde_json::json!({"1.0":{"supportedCatalogIds":[CATALOG_ID]}})
}

pub(super) fn reject_null_fields(value: &Value, fields: &[&str]) -> Result<(), Reject> {
    if fields.iter().any(|key| value.get(*key).is_some_and(Value::is_null)) {
        return Err(Reject::Encoding);
    }
    Ok(())
}
