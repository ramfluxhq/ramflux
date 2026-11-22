// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed body declarations (A1). A carried JSON body leaves as the canonical re-serialization
//! of its declared type, never as the original bytes. B runs the same code on what it receives.
//! `MessageMetadata` and `EventIdentity` refuse any non-null field the type drops. Directory
//! identity and conversation project the declared subset and drop every other field; a wrong
//! type or a missing required field still refuses the export.
use crate::StorageError;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Column-level body rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyCodec {
    /// `direct_message_projection.metadata_json`: `crate::MessageMetadata`.
    MessageMetadata,
    /// `runtime_actor_state.state_json`: the codec of the row's exact exported namespace.
    ActorNamespace,
}

/// Body type of one exported actor namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActorCodec {
    /// `ramflux_protocol::message::EventIdentity` (generated, rejects unknown fields).
    EventIdentity,
    /// `directory/identity/`: display name, home node and root commitment only.
    DirectoryIdentity,
    /// `directory/conversation/`: the fields a directory list needs, and nothing else.
    DirectoryConversation,
}

impl BodyCodec {
    pub(crate) const ALL: &'static [Self] = &[Self::MessageMetadata, Self::ActorNamespace];
    pub(crate) const fn version(self) -> u32 {
        match self {
            Self::MessageMetadata | Self::ActorNamespace => 1,
        }
    }
}

impl ActorCodec {
    pub(crate) const fn version(self) -> u32 {
        match self {
            Self::EventIdentity | Self::DirectoryIdentity | Self::DirectoryConversation => 1,
        }
    }

    /// Directory namespaces whose exported body is a named subset. Other codecs keep every
    /// declared field and refuse anything else.
    pub(crate) const fn directory_prefix(self) -> Option<&'static str> {
        match self {
            Self::DirectoryIdentity => Some("directory/identity/"),
            Self::DirectoryConversation => Some("directory/conversation/"),
            Self::EventIdentity => None,
        }
    }
}

fn undeclared() -> StorageError {
    StorageError::TransferExportRefused("undeclared_body_field")
}

/// True when `canonical` holds every non-null value of `original`. A key that is present
/// in the input but dropped by the typed round trip is an undeclared field.
fn covers(canonical: &Value, original: &Value) -> bool {
    match (canonical, original) {
        (_, Value::Null) => true,
        (Value::Object(kept), Value::Object(input)) => input.iter().all(|(key, value)| {
            value.is_null() || kept.get(key).is_some_and(|kept| covers(kept, value))
        }),
        (Value::Array(kept), Value::Array(input)) => {
            kept.len() == input.len()
                && kept.iter().zip(input).all(|(kept, value)| covers(kept, value))
        }
        (kept, input) => kept == input,
    }
}

/// Strict typed round trip of one JSON body.
fn strict<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let original: Value = serde_json::from_slice(bytes).map_err(|_| undeclared())?;
    let typed: T = serde_json::from_value(original.clone()).map_err(|_| undeclared())?;
    let canonical = serde_json::to_value(&typed)?;
    if !covers(&canonical, &original) {
        return Err(undeclared());
    }
    Ok(serde_json::to_vec(&canonical)?)
}

/// Canonical bytes of a column body. `actor` is the codec of the row's namespace and is
/// required exactly when the column rule is `ActorNamespace`.
/// # Errors
/// `TransferExportRefused` when the body does not parse strictly as its declared type.
pub(crate) fn canonical(
    codec: BodyCodec,
    actor: Option<ActorCodec>,
    bytes: &[u8],
) -> Result<Vec<u8>, StorageError> {
    match (codec, actor) {
        (BodyCodec::MessageMetadata, None) => strict::<crate::MessageMetadata>(bytes),
        (BodyCodec::ActorNamespace, Some(ActorCodec::EventIdentity)) => {
            strict::<ramflux_protocol::message::EventIdentity>(bytes)
        }
        (BodyCodec::ActorNamespace, Some(ActorCodec::DirectoryIdentity)) => {
            directory_identity(bytes)
        }
        (BodyCodec::ActorNamespace, Some(ActorCodec::DirectoryConversation)) => {
            directory_conversation(bytes)
        }
        _ => Err(undeclared()),
    }
}

/// Names only, from a canonical body: each top-level key, `parent.child` for an object
/// value, and `parent[].child` when an array holds an object. The caller never logs values.
/// # Errors
/// `TransferExportRefused` when the bytes are not a JSON object.
pub(crate) fn census_keys(bytes: &[u8]) -> Result<Vec<String>, StorageError> {
    let map = json_object(bytes)?;
    let mut names = Vec::new();
    for (key, value) in &map {
        names.push(key.clone());
        match value {
            Value::Object(child) => {
                for child_key in child.keys() {
                    names.push(format!("{key}.{child_key}"));
                }
            }
            Value::Array(items) => {
                for item in items {
                    let Value::Object(child) = item else {
                        continue;
                    };
                    for child_key in child.keys() {
                        names.push(format!("{key}[].{child_key}"));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(names)
}

fn json_object(bytes: &[u8]) -> Result<serde_json::Map<String, Value>, StorageError> {
    match serde_json::from_slice(bytes).map_err(|_| undeclared())? {
        Value::Object(map) => Ok(map),
        _ => Err(undeclared()),
    }
}

fn opt_string(
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, StorageError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(undeclared()),
    }
}

fn req_string(map: &serde_json::Map<String, Value>, key: &str) -> Result<String, StorageError> {
    match opt_string(map, key)? {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(undeclared()),
    }
}

fn opt_strings(
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<Vec<String>>, StorageError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut values = Vec::new();
            for item in items {
                let Value::String(value) = item else {
                    return Err(undeclared());
                };
                values.push(value.clone());
            }
            Ok(Some(values))
        }
        Some(_) => Err(undeclared()),
    }
}

/// Public home-node locator copied from a contact card (`url` and `key_fingerprint` only).
#[derive(serde::Serialize)]
struct DirectoryNode {
    url: String,
    key_fingerprint: String,
}

/// Contact directory subset. Extra fields on A's row are not copied. A wrong type on a
/// carried field, or a missing root commitment, refuses the export.
#[derive(serde::Serialize)]
struct DirectoryIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<DirectoryNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    home_node_id: Option<String>,
    contact_identity_commitment: String,
}

fn opt_node(
    map: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<DirectoryNode>, StorageError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(fields)) => Ok(Some(DirectoryNode {
            url: req_string(fields, "url")?,
            key_fingerprint: req_string(fields, "key_fingerprint")?,
        })),
        Some(_) => Err(undeclared()),
    }
}

fn directory_identity(bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let map = json_object(bytes)?;
    let body = DirectoryIdentity {
        display_name: opt_string(&map, "display_name")?,
        node: opt_node(&map, "node")?,
        home_node_id: opt_string(&map, "home_node_id")?,
        contact_identity_commitment: req_string(&map, "contact_identity_commitment")?,
    };
    Ok(serde_json::to_vec(&body)?)
}

/// Conversation directory subset: identity of the row plus what a list shows. Routes,
/// device ids and any other field stay on A.
#[derive(serde::Serialize)]
struct DirectoryConversation {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    participants: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    participant_roots: Option<Vec<String>>,
}

fn directory_conversation(bytes: &[u8]) -> Result<Vec<u8>, StorageError> {
    let map = json_object(bytes)?;
    let body = DirectoryConversation {
        id: opt_string(&map, "id")?,
        kind: req_string(&map, "kind")?,
        group_id: opt_string(&map, "group_id")?,
        title: opt_string(&map, "title")?,
        participants: opt_strings(&map, "participants")?,
        participant_roots: opt_strings(&map, "participant_roots")?,
    };
    Ok(serde_json::to_vec(&body)?)
}
