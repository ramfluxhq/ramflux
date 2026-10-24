// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable reply goals and conservative reconstruction from the latest scoped surface snapshot.
use crate::{Error, Intent, Result};
use ramflux_protocol::{
    A2uiConversationCommand as C, CreateSurfaceCommand, SurfaceReject, SurfaceState,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SurfacePlan {
    pub target: CreateSurfaceCommand,
    pub closed: bool,
    pub streams: BTreeMap<String, bool>,
    pub attempts: u8,
}
impl SurfacePlan {
    pub fn new(conversation: &str, intents: &[Intent]) -> Result<Self> {
        let mut state = SurfaceState::default();
        let mut streams = BTreeMap::new();
        for (index, intent) in intents.iter().enumerate() {
            let command = intent.command().ok_or(Error::State)?;
            if let C::StreamAppend(append) = &command {
                streams.insert(append.component_id.clone(), append.final_);
            }
            let version = u64::try_from(index)
                .map_err(|_| Error::Limit)?
                .checked_add(1)
                .ok_or(Error::Limit)?;
            let wire =
                ramflux_protocol::encode_a2ui_conversation_event(conversation, version, &command)
                    .map_err(|_| Error::State)?;
            state = state
                .apply(
                    &ramflux_protocol::A2uiConversationEvent::from_wire_bytes(&wire)
                        .map_err(|_| Error::State)?,
                )
                .map_err(|error| match error {
                    SurfaceReject::LimitExceeded { .. } => {
                        Error::SurfaceRefused(ramflux_sdk::SurfaceRefusalCode::TooLarge)
                    }
                    _ => Error::State,
                })?;
        }
        Ok(Self {
            target: state.content().ok_or(Error::State)?.clone(),
            closed: state.is_closed(),
            streams,
            attempts: 0,
        })
    }
    pub fn rederive(&self, view: &serde_json::Value) -> Result<Vec<Intent>> {
        use ramflux_sdk::SurfaceRefusalCode as Code;
        let mut content: CreateSurfaceCommand =
            serde_json::from_value(view["snapshot"].clone()).map_err(|_| Error::State)?;
        if ramflux_protocol::surface_snapshot_hash(&content).map_err(|_| Error::State)?.as_str()
            != view["surface_hash"].as_str().ok_or(Error::State)?
        {
            return Err(Error::State);
        }
        if content.surface_id != self.target.surface_id {
            return Err(Error::Unauthorized);
        }
        if view["closed"] == true && (!self.closed || content != self.target) {
            return Err(Error::SurfaceRefused(Code::Closed));
        }
        let mut normalized = content.clone();
        normalized.fallback_text.clone_from(&self.target.fallback_text);
        for id in self.streams.keys() {
            let wanted = text(&self.target, id)?;
            let current = text(&content, id)?;
            if !wanted.starts_with(current) {
                return Err(Error::SurfaceRefused(Code::StaleHash));
            }
            text_mut(&mut normalized, id)?.clear();
            text_mut(&mut normalized, id)?.push_str(wanted);
        }
        // Changed decisions, catalog/data or unrelated blocks are never rolled back by a reply retry.
        if normalized != self.target {
            return Err(Error::SurfaceRefused(Code::StaleHash));
        }
        let mut intents = Vec::new();
        for (id, final_) in &self.streams {
            let wanted = text(&self.target, id)?;
            let current = text(&content, id)?;
            let suffix = &wanted[current.len()..];
            let state = view["streams"][id].as_str().ok_or(Error::State)?;
            if state == "final" {
                if !suffix.is_empty() {
                    return Err(Error::SurfaceRefused(Code::Closed));
                }
                continue;
            }
            if state != "open" {
                return Err(Error::State);
            }
            let mut parts =
                crate::engine::chunks(suffix, ramflux_protocol::MAX_SURFACE_TEXT_DELTA_BYTES);
            if parts.is_empty() && *final_ {
                parts.push("");
            }
            for (index, part) in parts.iter().enumerate() {
                intents.push(Intent::StreamAppend(ramflux_protocol::StreamAppendCommand {
                    surface_id: content.surface_id.clone(),
                    component_id: id.clone(),
                    text_delta: part.to_string(),
                    final_: *final_ && index + 1 == parts.len(),
                }));
            }
            text_mut(&mut content, id)?.clear();
            text_mut(&mut content, id)?.push_str(wanted);
        }
        if content.fallback_text != self.target.fallback_text {
            let base =
                ramflux_protocol::surface_snapshot_hash(&content).map_err(|_| Error::State)?;
            content.fallback_text.clone_from(&self.target.fallback_text);
            intents.push(Intent::PatchSurface(ramflux_protocol::PatchSurfaceCommand {
                surface_id: content.surface_id.clone(),
                base_surface_hash: base,
                ops: vec![ramflux_protocol::SurfacePatchOp::SetFallbackText {
                    fallback_text: content.fallback_text.clone(),
                }],
                new_surface_hash: ramflux_protocol::surface_snapshot_hash(&content)
                    .map_err(|_| Error::State)?,
            }));
        }
        if self.closed && view["closed"] != true {
            intents.push(Intent::CloseSurface(ramflux_protocol::DeleteSurfaceCommand {
                surface_id: content.surface_id,
                reason: None,
            }));
        }
        Ok(intents)
    }
}
fn text<'a>(content: &'a CreateSurfaceCommand, id: &str) -> Result<&'a str> {
    let block = content.components.iter().find(|block| block["id"] == id).ok_or(Error::State)?;
    block
        .get("text")
        .or_else(|| block.pointer("/data/text"))
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::State)
}
fn text_mut<'a>(content: &'a mut CreateSurfaceCommand, id: &str) -> Result<&'a mut String> {
    let block =
        content.components.iter_mut().find(|block| block["id"] == id).ok_or(Error::State)?;
    let value = if block.get("text").is_some() {
        block.get_mut("text")
    } else {
        block.pointer_mut("/data/text")
    };
    match value {
        Some(serde_json::Value::String(text)) => Ok(text),
        _ => Err(Error::State),
    }
}
