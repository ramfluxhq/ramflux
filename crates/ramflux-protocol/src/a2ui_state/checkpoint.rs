// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validated private persistence of stream finality; this is never a conversation wire payload.
use super::state::{FinalText, stream_text};
use super::{SurfaceReject, SurfaceState, limits, snapshot};
use crate::CreateSurfaceCommand;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    content: Option<CreateSurfaceCommand>,
    conversation_id: Option<String>,
    version: u64,
    closed: bool,
    final_text: Vec<FinalEntry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalEntry {
    id: String,
    nested: bool,
    text: String,
}
impl SurfaceState {
    /// Private local checkpoint. Do not send this instead of a conversation event.
    /// # Errors
    /// Returns an encoding failure if private state cannot be serialized.
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, SurfaceReject> {
        let checkpoint = Checkpoint {
            schema: "ramflux.a2ui.checkpoint.v1".into(),
            content: self.content.clone(),
            conversation_id: self.conversation_id.clone(),
            version: self.version,
            closed: self.closed,
            final_text: self
                .final_components
                .iter()
                .map(|(id, text)| FinalEntry {
                    id: id.to_string(),
                    nested: text.nested,
                    text: text.text.clone(),
                })
                .collect(),
        };
        serde_json::to_vec(&checkpoint).map_err(|_| SurfaceReject::Encoding)
    }
    /// Restore trusted account-owned persistence; never use this as remote event ingress.
    /// Author attribution and carrier signatures remain the account projection's responsibility.
    /// # Errors
    /// Rejects invalid I-JSON, schema, version, snapshot bounds or inconsistent finality records.
    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, SurfaceReject> {
        let saved: Checkpoint =
            crate::parse_i_json(bytes).map_err(|_| SurfaceReject::InvalidJson)?;
        if saved.schema != "ramflux.a2ui.checkpoint.v1"
            || saved.version > crate::MAX_SAFE_JSON_INTEGER
        {
            return Err(SurfaceReject::InvalidJson);
        }
        if saved.final_text.len() > super::MAX_SURFACE_FINALIZED_BLOCKS {
            return Err(limits::exceeded(super::SurfaceLimit::FinalizedBlocks));
        }
        if saved.content.is_none() {
            if saved.conversation_id.is_some()
                || saved.version != 0
                || saved.closed
                || !saved.final_text.is_empty()
            {
                return Err(SurfaceReject::InvalidJson);
            }
            return Ok(Self::default());
        }
        let content = saved.content.ok_or(SurfaceReject::NotCreated)?;
        if saved.version == 0 {
            return Err(SurfaceReject::InvalidJson);
        }
        let conversation = saved.conversation_id.ok_or(SurfaceReject::InvalidIdentifier)?;
        limits::identifier(&conversation)?;
        let hash = snapshot::validated_hash(&content)?;
        let mut final_components = BTreeMap::new();
        for entry in saved.final_text {
            limits::identifier(&entry.id)?;
            limits::text(&entry.text)?;
            if final_components
                .insert(
                    Arc::<str>::from(entry.id),
                    Arc::new(FinalText { nested: entry.nested, text: entry.text }),
                )
                .is_some()
            {
                return Err(SurfaceReject::DuplicateBlock);
            }
        }
        for component in &content.components {
            if let Some(text) = final_components.get(snapshot::component_id(component)?)
                && stream_text(component) != Some((text.nested, text.text.as_str()))
            {
                return Err(SurfaceReject::BlockClosed);
            }
        }
        Ok(Self {
            content: Some(content),
            hash: Some(hash),
            conversation_id: Some(conversation),
            version: saved.version,
            closed: saved.closed,
            final_components,
        })
    }
}
