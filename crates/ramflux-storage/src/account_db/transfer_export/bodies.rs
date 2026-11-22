// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed body declarations (A1). A carried JSON body is parsed into its declared type, must
//! hold no field the type does not declare, and leaves as the canonical re-serialization of
//! the typed value, never as the original bytes. B runs the same code on what it receives.
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
            Self::EventIdentity => 1,
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
        _ => Err(undeclared()),
    }
}
