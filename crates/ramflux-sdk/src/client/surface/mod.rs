// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned surfaces in authenticated conversation messages, independent of pair sessions.
mod backfill;
pub(crate) mod carrier;
mod fallback;
mod projection;
mod read;
pub(crate) use carrier::{Carrier, Payload, PayloadKind, command_id, invalid};
pub(crate) use read::surface_metadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSurface {
    pub surface_id: String,
    pub conversation_id: String,
    pub author_principal_id: String,
    pub author_device_id: String,
    pub checkpoint_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub fingerprint: String,
    pub result: Outcome,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub accepted: bool,
    pub fallback_text: String,
    pub renderer_error: Option<Value>,
}
impl Outcome {
    fn accepted(
        author: &str,
        state: &ramflux_protocol::SurfaceState,
    ) -> Result<Self, crate::SdkError> {
        let content = state.content().ok_or_else(|| invalid("surface content absent"))?;
        Ok(Self {
            accepted: true,
            fallback_text: fallback::render(author, &content.fallback_text),
            renderer_error: None,
        })
    }

    pub(crate) fn rejected(error: Value) -> Self {
        Self {
            accepted: false,
            fallback_text: "[Surface rejected]".into(),
            renderer_error: Some(error),
        }
    }
}
pub(crate) fn key(prefix: &str, id: &str) -> String {
    format!(
        "surface/{prefix}/{}",
        ramflux_protocol::hash_base64url("ramflux.surface.storage_key.v1", id.as_bytes())
    )
}
pub(crate) fn scoped_key(prefix: &str, parts: &[&str]) -> Result<String, crate::SdkError> {
    Ok(key(prefix, &serde_json::to_string(parts)?))
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(crate) struct SurfaceSender<'a> {
    pub principal: &'a str,
    pub device: &'a str,
}
