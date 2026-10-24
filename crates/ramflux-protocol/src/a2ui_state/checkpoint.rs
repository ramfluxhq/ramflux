// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validated checkpoints for local persistence and authenticated full-state attestations.
use super::state::{FinalText, final_component_key};
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
    text_hash: String,
}
impl SurfaceState {
    /// Checkpoint for local persistence or a signed full-state proof, never a standalone event.
    /// # Errors
    /// Returns an encoding failure if private state cannot be serialized.
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, SurfaceReject> {
        let checkpoint = Checkpoint {
            schema: "ramflux.a2ui.checkpoint.v2".into(),
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
                    text_hash: text.text_hash.clone(),
                })
                .collect(),
        };
        crate::canonical_json_bytes(&checkpoint).map_err(|_| SurfaceReject::Encoding)
    }
    /// Restore trusted persistence. Remote snapshot proofs must use `resynchronize` after
    /// authenticating their author and decoding their original event bytes.
    /// Author attribution and carrier signatures remain the account projection's responsibility.
    /// # Errors
    /// Rejects invalid I-JSON, schema, version, snapshot bounds or inconsistent finality records.
    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, SurfaceReject> {
        if bytes.len() > 256 * 1024 {
            return Err(SurfaceReject::InvalidJson);
        }
        let saved: Checkpoint =
            crate::parse_i_json(bytes).map_err(|_| SurfaceReject::InvalidJson)?;
        if saved.schema != "ramflux.a2ui.checkpoint.v2"
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
            for digest in [&entry.id, &entry.text_hash] {
                if crate::decode_base64url(digest).map_err(|_| SurfaceReject::InvalidJson)?.len()
                    != 32
                {
                    return Err(SurfaceReject::InvalidJson);
                }
            }
            if final_components
                .insert(
                    Arc::<str>::from(entry.id),
                    Arc::new(FinalText { nested: entry.nested, text_hash: entry.text_hash }),
                )
                .is_some()
            {
                return Err(SurfaceReject::DuplicateBlock);
            }
        }
        for component in &content.components {
            if let Some(text) = final_components
                .get(final_component_key(snapshot::component_id(component)?).as_str())
                && !text.matches(component)
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
    /// Restores an authenticated author's full-state attestation without reopening known final blocks.
    /// The carrier must authenticate the author before calling this method. The event must be the
    /// original signed v2 create-shaped snapshot bytes, decoded only through `from_wire_bytes`.
    /// # Errors
    /// Rejects mismatched snapshot/checkpoint bindings, rollback, lost finality or invalid state.
    pub fn resynchronize(
        &self,
        event: &super::A2uiConversationEvent,
        checkpoint: &[u8],
    ) -> Result<Self, SurfaceReject> {
        let mut next = Self::from_checkpoint_bytes(checkpoint)?;
        let super::A2uiConversationCommand::CreateSurface(content) = event.command() else {
            return Err(SurfaceReject::WrongSurface);
        };
        if next.version != event.version()
            || next.conversation_id.as_deref() != Some(event.conversation_id())
            || next.content.as_ref() != Some(content)
        {
            return Err(SurfaceReject::WrongSurface);
        }
        if next.version < self.version
            || self.conversation_id.as_deref().is_some_and(|id| id != event.conversation_id())
            || self.content.as_ref().is_some_and(|old| old.surface_id != content.surface_id)
        {
            return Err(SurfaceReject::WrongSurface);
        }
        if self.closed && (next.version != self.version || next.hash != self.hash || !next.closed) {
            return Err(SurfaceReject::Closed);
        }
        if self.version > 0
            && next.version == self.version
            && (next.hash != self.hash || next.closed != self.closed)
        {
            return Err(SurfaceReject::Conflict);
        }
        for (id, final_text) in &self.final_components {
            if next.final_components.get(id).is_some_and(|incoming| incoming != final_text) {
                return Err(SurfaceReject::BlockClosed);
            }
            next.final_components.insert(Arc::clone(id), Arc::clone(final_text));
        }
        if next.final_components.len() > super::MAX_SURFACE_FINALIZED_BLOCKS {
            return Err(limits::exceeded(super::SurfaceLimit::FinalizedBlocks));
        }
        for component in &content.components {
            if let Some(text) = next
                .final_components
                .get(final_component_key(snapshot::component_id(component)?).as_str())
                && !text.matches(component)
            {
                return Err(SurfaceReject::BlockClosed);
            }
        }
        Ok(next)
    }
}
