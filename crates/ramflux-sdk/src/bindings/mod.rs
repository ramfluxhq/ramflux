// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate CLI/C ABI/`UniFFI`/WASM adapters for generated request/update types (S10a P23).
//! Field names come from the descriptor. This module does not send or persist.

pub mod cli;
pub mod uniffi;
pub mod wasm;

use crate::SdkError;
use ramflux_protocol::message as g;
use ramflux_protocol::message::registry::{self, BindingField};
use serde_json::Value;
use std::collections::BTreeSet;

/// Generated product messages shared by every exported adapter.
pub const PRODUCT_MESSAGES: [&str; 3] = ["MessageRequest", "SendMessage", "MessageUpdate"];

/// One exported product surface. All four share [`binding_vector`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AdapterSurface {
    /// `rf` CLI handlers.
    Cli,
    /// Stable C ABI JSON codecs.
    CAbi,
    /// `UniFFI` contract module (no runtime linked).
    Uniffi,
    /// WASM contract module (no runtime linked).
    Wasm,
}

/// Descriptor field vector for one generated message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingVector {
    /// Unqualified descriptor name.
    pub message: String,
    /// Fields in descriptor order.
    pub fields: Vec<BindingField>,
}

/// Shared error model used by CLI, C ABI, `UniFFI` and WASM adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterError {
    /// Matches `RamfluxErrorCode` for the same refusal.
    pub code: i32,
    /// Stable error name.
    pub name: &'static str,
    /// Human-readable detail.
    pub message: String,
}

impl AdapterError {
    /// Invalid adapter argument (C ABI code 1).
    pub const INVALID_ARGUMENT: i32 = 1;
    /// Non-canonical or unknown-field JSON (C ABI code 2).
    pub const INVALID_JSON: i32 = 2;

    /// Map an SDK refusal onto the shared adapter error surface.
    #[must_use]
    pub fn from_sdk(error: &SdkError) -> Self {
        match error {
            SdkError::EditConflict { .. } => Self {
                code: Self::INVALID_ARGUMENT,
                name: "EditConflict",
                message: error.to_string(),
            },
            SdkError::Json(_) => Self {
                code: Self::INVALID_JSON,
                name: "InvalidCanonicalJson",
                message: error.to_string(),
            },
            SdkError::LocalBus(message) if message.contains("unknown adapter field") => Self {
                code: Self::INVALID_JSON,
                name: "InvalidCanonicalJson",
                message: error.to_string(),
            },
            _ => Self {
                code: Self::INVALID_ARGUMENT,
                name: "InvalidArgument",
                message: error.to_string(),
            },
        }
    }
}

/// Descriptor-derived field vector. Product adapters must not hand-maintain names.
///
/// # Errors
/// Returns an error when the descriptor cannot be loaded.
pub fn binding_vector(message: &str) -> Result<BindingVector, SdkError> {
    Ok(BindingVector {
        message: message.to_string(),
        fields: registry::binding_fields(message).map_err(descriptor_error)?,
    })
}

/// Field vector exported by one product surface. Every surface uses [`binding_vector`].
///
/// # Errors
/// Returns an error when the descriptor cannot be loaded.
pub fn adapter_binding_vector(
    surface: AdapterSurface,
    message: &str,
) -> Result<BindingVector, SdkError> {
    match surface {
        AdapterSurface::Cli
        | AdapterSurface::CAbi
        | AdapterSurface::Uniffi
        | AdapterSurface::Wasm => binding_vector(message),
    }
}

/// Look up one adapter field by proto or JSON name. Hand-maintained names fail here.
///
/// # Errors
/// Returns an error when `json_name` is not a descriptor field of `message`.
pub fn bind_adapter_field(message: &str, json_name: &str) -> Result<BindingField, SdkError> {
    binding_vector(message)?
        .fields
        .into_iter()
        .find(|field| field.json_name == json_name || field.name == json_name)
        .ok_or_else(|| invalid(format!("unknown adapter field {message}.{json_name}")))
}

/// Encode a generated request to `ProtoJSON` using descriptor field names.
///
/// # Errors
/// Returns an error when required fields are missing or JSON encoding fails.
pub fn encode_message_request(request: &g::MessageRequest) -> Result<Value, SdkError> {
    let mut request = request.clone();
    normalize_request(&mut request)?;
    encode_named("MessageRequest", &request)
}

/// Decode a generated request and refuse keys that are not descriptor fields.
///
/// # Errors
/// Returns an error for unknown fields, missing action, or invalid JSON.
pub fn decode_message_request(value: &Value) -> Result<g::MessageRequest, SdkError> {
    reject_unknown_keys("MessageRequest", value)?;
    let mut request: g::MessageRequest = serde_json::from_value(value.clone())?;
    normalize_request(&mut request)?;
    Ok(request)
}

/// Encode a generated send payload.
///
/// # Errors
/// Returns an error when conversation id is empty or JSON encoding fails.
pub fn encode_send_message(send: &g::SendMessage) -> Result<Value, SdkError> {
    let mut send = send.clone();
    normalize_send(&mut send)?;
    encode_named("SendMessage", &send)
}

/// Decode a generated send payload and refuse unknown keys.
///
/// # Errors
/// Returns an error for unknown fields or a missing conversation id.
pub fn decode_send_message(value: &Value) -> Result<g::SendMessage, SdkError> {
    reject_unknown_keys("SendMessage", value)?;
    let mut send: g::SendMessage = serde_json::from_value(value.clone())?;
    normalize_send(&mut send)?;
    Ok(send)
}

/// Encode a generated update to `ProtoJSON`.
///
/// # Errors
/// Returns an error when required fields are missing or JSON encoding fails.
pub fn encode_message_update(update: &g::MessageUpdate) -> Result<Value, SdkError> {
    validate_update(update)?;
    encode_named("MessageUpdate", update)
}

/// Decode a generated update and refuse keys that are not descriptor fields.
///
/// # Errors
/// Returns an error for unknown fields, missing state, or invalid JSON.
pub fn decode_message_update(value: &Value) -> Result<g::MessageUpdate, SdkError> {
    reject_unknown_keys("MessageUpdate", value)?;
    let update: g::MessageUpdate = serde_json::from_value(value.clone())?;
    validate_update(&update)?;
    Ok(update)
}

/// JSON round-trip through the shared request codec.
///
/// # Errors
/// Returns an error when encode or decode refuses the value.
pub fn round_trip_request(request: &g::MessageRequest) -> Result<g::MessageRequest, SdkError> {
    decode_message_request(&encode_message_request(request)?)
}

/// JSON round-trip through the shared update codec.
///
/// # Errors
/// Returns an error when encode or decode refuses the value.
pub fn round_trip_update(update: &g::MessageUpdate) -> Result<g::MessageUpdate, SdkError> {
    decode_message_update(&encode_message_update(update)?)
}

fn encode_named<T: serde::Serialize>(message: &str, value: &T) -> Result<Value, SdkError> {
    let encoded = serde_json::to_value(value)?;
    reject_unknown_keys(message, &encoded)?;
    Ok(encoded)
}

fn reject_unknown_keys(message: &str, value: &Value) -> Result<(), SdkError> {
    let Some(object) = value.as_object() else {
        return Err(invalid(format!("{message} must be a JSON object")));
    };
    let allowed: BTreeSet<String> = binding_vector(message)?
        .fields
        .iter()
        .flat_map(|field| [field.json_name.clone(), field.name.clone()])
        .collect();
    for key in object.keys() {
        if !allowed.contains(key) {
            return Err(invalid(format!("unknown adapter field {message}.{key}")));
        }
        bind_adapter_field(message, key)?;
    }
    Ok(())
}

fn validate_request(request: &g::MessageRequest) -> Result<(), SdkError> {
    if request.request_id.is_empty() || request.account_id.is_empty() {
        return Err(invalid("MessageRequest requires request_id and account_id"));
    }
    match request.action.as_ref() {
        Some(g::message_request::Action::Send(send)) => validate_send(send),
        Some(g::message_request::Action::Edit(edit)) => {
            if edit.target.is_none() || edit.replacement.is_none() {
                Err(invalid("edit requires target and replacement"))
            } else {
                Ok(())
            }
        }
        Some(g::message_request::Action::Delete(delete)) => {
            if delete.targets.is_empty() {
                Err(invalid("delete requires at least one target"))
            } else {
                Ok(())
            }
        }
        Some(g::message_request::Action::Reaction(reaction)) => {
            if reaction.target.is_none() || reaction.token.is_empty() {
                Err(invalid("reaction requires target and token"))
            } else {
                Ok(())
            }
        }
        Some(g::message_request::Action::Typing(_)) => Err(invalid("use send.content.typing")),
        None => Err(invalid("MessageRequest requires one action")),
    }
}

fn normalize_request(request: &mut g::MessageRequest) -> Result<(), SdkError> {
    validate_request(request)?;
    if let Some(g::message_request::Action::Send(send)) = request.action.as_mut() {
        normalize_send(send)?;
    }
    Ok(())
}

fn normalize_send(send: &mut g::SendMessage) -> Result<(), SdkError> {
    validate_send(send)?;
    if let Some(g::content::Value::Message(message)) =
        send.content.as_mut().and_then(|content| content.value.as_mut())
        && message.reply_to.is_none()
    {
        message.reply_to.clone_from(&send.reply_to);
    }
    Ok(())
}

fn validate_send(send: &g::SendMessage) -> Result<(), SdkError> {
    if send.conversation_id.is_empty() || !(16..=64).contains(&send.operation_id.len()) {
        return Err(invalid("SendMessage requires conversation_id and a 16..64-byte operation_id"));
    }
    let content = send
        .content
        .as_ref()
        .and_then(|content| content.value.as_ref())
        .ok_or_else(|| invalid("SendMessage requires content"))?;
    match content {
        g::content::Value::Message(message) => {
            if let (Some(outer), Some(inner)) = (&send.reply_to, &message.reply_to)
                && outer != inner
            {
                return Err(invalid("SendMessage reply_to conflicts with Message reply_to"));
            }
        }
        g::content::Value::Typing(typing) => {
            if typing.expires_at != 0 {
                return Err(invalid("Typing request expires_at must be zero"));
            }
        }
        g::content::Value::SelfSync(_)
        | g::content::Value::Surface(_)
        | g::content::Value::Task(_)
        | g::content::Value::Call(_) => (),
        _ => return Err(invalid("content kind is not accepted by SendMessage")),
    }
    if send.reply_to.is_some() && !matches!(content, g::content::Value::Message(_)) {
        return Err(invalid("reply_to is only accepted for Message content"));
    }
    Ok(())
}

fn validate_update(update: &g::MessageUpdate) -> Result<(), SdkError> {
    if update.account_id.is_empty() {
        return Err(invalid("MessageUpdate requires account_id"));
    }
    if update.state.is_none() {
        return Err(invalid("MessageUpdate requires one state"));
    }
    Ok(())
}

fn descriptor_error(_: ramflux_protocol::message::validation::ValidationError) -> SdkError {
    invalid("invalid message descriptor")
}

pub(crate) fn invalid(message: impl Into<String>) -> SdkError {
    SdkError::LocalBus(message.into())
}

#[cfg(test)]
mod tests;
