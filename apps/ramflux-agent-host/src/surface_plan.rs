// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable v3 reply goals and conservative reconstruction from the current signed base.
use crate::{Error, Intent, Result};
use ramflux_protocol::{AppendText, DeleteSurface, JsonPointer, SurfaceSnapshot, SurfaceState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SurfacePlan {
    pub target: SurfaceSnapshot,
    pub closed: bool,
    pub streams: BTreeMap<String, bool>,
    pub attempts: u8,
}
impl SurfacePlan {
    pub fn new(conversation: &str, intents: &[Intent]) -> Result<Self> {
        let mut state = SurfaceState::default();
        let mut streams = BTreeMap::new();
        for intent in intents {
            if let Intent::AppendText(append) = intent {
                streams.insert(append.path.clone(), append.final_);
            }
            let frame = intent.frame(conversation, &state)?;
            let wire = frame.wire_bytes().map_err(|_| Error::State)?;
            state = state
                .apply(
                    &ramflux_protocol::SurfaceEvent::from_wire_bytes(&wire)
                        .map_err(|_| Error::State)?,
                )
                .map_err(|error| match error {
                    ramflux_protocol::SurfaceReject::Limit => {
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
        let conversation =
            view.get("conversation_id").and_then(serde_json::Value::as_str).ok_or(Error::State)?;
        let state = crate::runner_output::state_from_view(conversation, view)?;
        let content = state.content().ok_or(Error::State)?;
        if content.surface_id != self.target.surface_id {
            return Err(Error::Unauthorized);
        }
        if content.closed && content != &self.target {
            return Err(Error::SurfaceRefused(Code::Closed));
        }
        let mut normalized = content.clone();
        normalized.fallback_text.clone_from(&self.target.fallback_text);
        normalized.final_.clone_from(&self.target.final_);
        normalized.closed = self.target.closed;
        for pointer in self.streams.keys() {
            let p = JsonPointer::parse(pointer).map_err(|_| Error::State)?;
            let wanted = p.text(&self.target.data_model).map_err(|_| Error::State)?;
            let current = p.text(&content.data_model).map_err(|_| Error::State)?;
            if !wanted.starts_with(current) {
                return Err(Error::SurfaceRefused(Code::StaleHash));
            }
            p.update(&mut normalized.data_model, serde_json::json!(wanted))
                .map_err(|_| Error::State)?;
        }
        if normalized != self.target {
            return Err(Error::SurfaceRefused(Code::StaleHash));
        }
        let mut intents = Vec::new();
        for (pointer, final_) in &self.streams {
            let p = JsonPointer::parse(pointer).map_err(|_| Error::State)?;
            let wanted = p.text(&self.target.data_model).map_err(|_| Error::State)?;
            let current = p.text(&content.data_model).map_err(|_| Error::State)?;
            let suffix =
                wanted.strip_prefix(current).ok_or(Error::SurfaceRefused(Code::StaleHash))?;
            if content.closed || content.final_.iter().any(|r| r.pointer == *pointer) {
                if !suffix.is_empty() {
                    return Err(Error::SurfaceRefused(Code::Closed));
                }
                continue;
            }
            let mut parts = crate::engine::chunks(suffix, ramflux_protocol::MAX_DELTA_BYTES);
            if parts.is_empty() && *final_ {
                parts.push("");
            }
            for (index, part) in parts.iter().enumerate() {
                intents.push(Intent::AppendText(AppendText {
                    surface_id: content.surface_id.clone(),
                    path: pointer.clone(),
                    delta: (*part).into(),
                    final_: *final_ && index + 1 == parts.len(),
                }));
            }
        }
        if content.fallback_text != self.target.fallback_text {
            let mut target = self.target.clone();
            target.closed = content.closed;
            intents.push(Intent::ReplaceSurface(target));
        }
        if self.closed && !content.closed {
            intents.push(Intent::CloseSurface(DeleteSurface {
                surface_id: content.surface_id.clone(),
            }));
        }
        Ok(intents)
    }
}
