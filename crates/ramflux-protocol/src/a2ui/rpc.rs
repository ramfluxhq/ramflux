// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The r3c RPC frame: original request identity is independent of surface sequence consumption.
use super::wire::{canonical, decode_canonical, identifier};
use super::{MAX_DELTA_BYTES, Reject};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const RPC_SCHEMA: &str = "ramflux.surface.rpc.v3";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcKind {
    FunctionCall,
    FunctionResponse,
    Error,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcFrame {
    pub schema: String,
    pub conversation_id: String,
    pub surface_id: String,
    pub known_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_version: Option<u64>,
    pub a2ui: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceRpc(RpcFrame);
impl SurfaceRpc {
    /// Identify one of the three pinned RPC payload kinds from the original frame bytes.
    /// # Errors
    /// Refuses noncanonical, ambiguous or invalid frames before returning a discriminator.
    pub fn detect(bytes: &[u8]) -> Result<(RpcKind, Self), Reject> {
        let raw: Value = decode_canonical(bytes, MAX_DELTA_BYTES)?;
        if raw.get("schema").and_then(Value::as_str) != Some(RPC_SCHEMA) {
            return Err(Reject::Encoding);
        }
        let message = raw.get("a2ui").and_then(Value::as_object).ok_or(Reject::Encoding)?;
        let kind = if message.contains_key("callRendererFunction") {
            RpcKind::FunctionCall
        } else if message.contains_key("rendererFunctionResponse") {
            RpcKind::FunctionResponse
        } else if message.contains_key("error") {
            RpcKind::Error
        } else {
            return Err(Reject::Encoding);
        };
        Ok((kind, Self::from_wire_bytes(bytes, kind)?))
    }

    /// Frame admission precedes inner schema validation, allowing the pinned malformed-call reply.
    /// # Errors
    /// Refuses noncanonical bytes, null optional fields, extras, invalid scope/version/id or kind.
    pub fn from_wire_bytes(bytes: &[u8], kind: RpcKind) -> Result<Self, Reject> {
        let raw: Value = decode_canonical(bytes, MAX_DELTA_BYTES)?;
        for key in ["knownHash", "functionCallId", "rejectedVersion"] {
            if raw.get(key).is_some_and(Value::is_null) {
                return Err(Reject::Encoding);
            }
        }
        let frame: RpcFrame = serde_json::from_value(raw).map_err(|_| Reject::Encoding)?;
        if frame.schema != RPC_SCHEMA
            || frame.conversation_id.is_empty()
            || frame.conversation_id.len() > 256
            || frame.known_version > crate::MAX_SAFE_JSON_INTEGER
            || (frame.known_version > 0) != frame.known_hash.is_some()
            || frame.known_hash.as_ref().is_some_and(String::is_empty)
            || frame.surface_id == "~rpc" && frame.known_version != 0
        {
            return Err(Reject::Encoding);
        }
        if frame.surface_id != "~rpc" {
            identifier(&frame.surface_id)?;
        }
        if let Some(id) = &frame.function_call_id {
            call_id(id)?;
        }
        let key = match kind {
            RpcKind::FunctionCall => "callRendererFunction",
            RpcKind::FunctionResponse => "rendererFunctionResponse",
            RpcKind::Error => "error",
        };
        let object = frame.a2ui.as_object().ok_or(Reject::Encoding)?;
        if object.len() != 2 || object.get("version").and_then(Value::as_str) != Some("1.0") {
            return Err(Reject::Encoding);
        }
        let body = object.get(key).and_then(Value::as_object).ok_or(Reject::Encoding)?;
        let inner_id = body.get("functionCallId");
        if inner_id.is_some_and(Value::is_null) {
            return Err(Reject::Encoding);
        }
        match kind {
            RpcKind::FunctionCall => {
                if frame.function_call_id.is_none() || frame.rejected_version.is_some() {
                    return Err(Reject::Encoding);
                }
                if inner_id.and_then(Value::as_str) != frame.function_call_id.as_deref() {
                    return Err(Reject::Integrity);
                }
                let surface = body
                    .get("surfaceId")
                    .map(|v| v.as_str().ok_or(Reject::Encoding))
                    .transpose()?
                    .unwrap_or("~rpc");
                if surface != frame.surface_id {
                    return Err(Reject::Integrity);
                }
            }
            RpcKind::FunctionResponse => {
                if frame.function_call_id.is_none()
                    || inner_id.and_then(Value::as_str) != frame.function_call_id.as_deref()
                    || frame.rejected_version.is_some()
                {
                    return Err(Reject::Integrity);
                }
                super::schema::rpc_message(&frame.a2ui, kind)?;
            }
            RpcKind::Error => {
                if inner_id.and_then(Value::as_str) != frame.function_call_id.as_deref() {
                    return Err(Reject::Integrity);
                }
                let surface = body
                    .get("surfaceId")
                    .map(|v| v.as_str().ok_or(Reject::Encoding))
                    .transpose()?;
                if let Some(surface) = surface {
                    if frame.surface_id != surface
                        || frame
                            .rejected_version
                            .is_none_or(|v| !(1..=crate::MAX_SAFE_JSON_INTEGER).contains(&v))
                    {
                        return Err(Reject::Integrity);
                    }
                } else if frame.surface_id != "~rpc"
                    || frame.function_call_id.is_none()
                    || frame.rejected_version.is_some()
                {
                    return Err(Reject::Integrity);
                }
                super::schema::rpc_message(&frame.a2ui, kind)?;
            }
        }
        Ok(Self(frame))
    }
    #[must_use]
    pub const fn frame(&self) -> &RpcFrame {
        &self.0
    }
    /// A schema-valid call always gets INVALID_FUNCTION_CALL; unknown functions never execute.
    #[must_use]
    pub fn call_is_well_formed(&self) -> bool {
        super::schema::rpc_message(&self.0.a2ui, RpcKind::FunctionCall).is_ok()
    }
    /// Exact decoded JCS bytes are committed, including all original scope and request fields.
    /// # Errors
    /// Returns an encoding error for invalid JSON values.
    pub fn request_fingerprint(&self) -> Result<String, Reject> {
        Ok(crate::hash_base64url(crate::domain::SURFACE_RPC_REQUEST, &canonical(&self.0)?))
    }
}
impl RpcFrame {
    /// Encode a local RPC frame using the same admission rules as original-byte ingress.
    /// # Errors
    /// Refuses invalid framing, kind binding or bounds.
    pub fn wire_bytes(&self, kind: RpcKind) -> Result<Vec<u8>, Reject> {
        let bytes = canonical(self)?;
        SurfaceRpc::from_wire_bytes(&bytes, kind)?;
        Ok(bytes)
    }
}
fn call_id(id: &str) -> Result<(), Reject> {
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Reject::Encoding);
    }
    Ok(())
}
