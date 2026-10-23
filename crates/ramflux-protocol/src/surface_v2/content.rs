// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validated surface content; its immutable canonical bytes make hashing infallible.

use super::{SurfaceActionDefinition, SurfaceBlock, SurfaceLimit, SurfaceReject, limits};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContentFields {
    pub surface_id: String,
    pub fallback_text: String,
    pub blocks: Vec<SurfaceBlock>,
    pub actions: Vec<SurfaceActionDefinition>,
}

/// Exactly the reviewed field set: surface ID, fallback text, blocks and actions.
/// Construction and deserialization validate the limits before caching protocol JCS bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SurfaceContent {
    pub(super) fields: ContentFields,
    canonical: Vec<u8>,
}
impl std::fmt::Debug for SurfaceContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Canonical bytes duplicate the full payload, including display-redacted block data.
        formatter
            .debug_struct("SurfaceContent")
            .field("content", &self.fields)
            .finish_non_exhaustive()
    }
}
impl SurfaceContent {
    /// # Errors
    /// Rejects invalid/duplicate identifiers, absent fallback, unsupported block versions or limits.
    pub fn new(
        surface_id: String,
        fallback_text: String,
        blocks: Vec<SurfaceBlock>,
        actions: Vec<SurfaceActionDefinition>,
    ) -> Result<Self, SurfaceReject> {
        Self::from_fields(ContentFields { surface_id, fallback_text, blocks, actions })
    }
    pub(super) fn from_fields(fields: ContentFields) -> Result<Self, SurfaceReject> {
        validate(&fields)?;
        let canonical =
            crate::canonical_json_bytes(&fields).map_err(|_| SurfaceReject::Encoding)?;
        Ok(Self { fields, canonical })
    }
    #[must_use]
    pub fn surface_id(&self) -> &str {
        &self.fields.surface_id
    }
    #[must_use]
    pub fn fallback_text(&self) -> &str {
        &self.fields.fallback_text
    }
    #[must_use]
    pub fn blocks(&self) -> &[SurfaceBlock] {
        &self.fields.blocks
    }
    #[must_use]
    pub fn actions(&self) -> &[SurfaceActionDefinition] {
        &self.fields.actions
    }
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
impl Serialize for SurfaceContent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.fields.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for SurfaceContent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_fields(ContentFields::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

fn validate(content: &ContentFields) -> Result<(), SurfaceReject> {
    if content.blocks.len() > super::MAX_SURFACE_BLOCKS {
        return Err(limits::exceeded(SurfaceLimit::Blocks));
    }
    if content.actions.len() > super::MAX_SURFACE_ACTIONS {
        return Err(limits::exceeded(SurfaceLimit::Actions));
    }
    limits::identifier(&content.surface_id)?;
    limits::text(&content.fallback_text)?;
    if content.fallback_text.trim().is_empty() {
        return Err(SurfaceReject::MissingFallback);
    }
    let mut ids = BTreeSet::new();
    let mut data_bytes = 0;
    for block in &content.blocks {
        limits::identifier(&block.id)?;
        if !ids.insert(&block.id) {
            return Err(SurfaceReject::DuplicateBlock);
        }
        if block.version != 1 {
            return Err(SurfaceReject::UnsupportedBlockVersion);
        }
        data_bytes += limits::json(&block.data)?.len();
        if data_bytes > super::MAX_SURFACE_DATA_BYTES {
            return Err(limits::exceeded(SurfaceLimit::DataBytes));
        }
    }
    ids.clear();
    for action in &content.actions {
        limits::identifier(&action.id)?;
        if !ids.insert(&action.id) {
            return Err(SurfaceReject::DuplicateAction);
        }
        limits::text(&action.label)?;
        if let Some(reason) = &action.disabled_reason {
            limits::text(reason)?;
        }
    }
    Ok(())
}
