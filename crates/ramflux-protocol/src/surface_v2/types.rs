// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed wire schemas for surface content, mutations and human decisions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SURFACE_CREATE_SCHEMA: &str = "ramflux.surface.create.v1";
pub const SURFACE_PATCH_SCHEMA: &str = "ramflux.surface.patch.v1";
pub const SURFACE_STREAM_APPEND_SCHEMA: &str = "ramflux.surface.stream_append.v1";
pub const SURFACE_CLOSE_SCHEMA: &str = "ramflux.surface.close.v1";
pub const SURFACE_ACTION_SCHEMA: &str = "ramflux.surface.action.v1";

/// Declarative renderer catalog. No executable or extension block kind is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceBlockKind {
    Text,
    Markdown,
    Heading,
    KeyValue,
    Metric,
    List,
    TableFallback,
    Form,
    Input,
    Select,
    Progress,
    LogStream,
    Warning,
    Error,
    Success,
    Approval,
    ActionGroup,
    FilePreview,
    Fallback,
}

/// One declarative block. Renderer-specific data stays JSON, never executable code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceBlock {
    pub id: String,
    pub kind: SurfaceBlockKind,
    #[serde(default = "block_version")]
    pub version: u32,
    #[serde(default)]
    pub redacted: bool,
    #[serde(default)]
    pub data: Value,
}
impl std::fmt::Debug for SurfaceBlock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut block = formatter.debug_struct("SurfaceBlock");
        block
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("redacted", &self.redacted);
        if self.redacted {
            block.field("data", &"[redacted]");
        } else {
            block.field("data", &self.data);
        }
        block.finish()
    }
}
const fn block_version() -> u32 {
    1
}

/// Declared action risk; policy enforcement remains the receiving participant's job.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceActionRisk {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

/// An action offered to the reader, distinct from the reader's decision below.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceActionDefinition {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub risk: SurfaceActionRisk,
    #[serde(default)]
    pub disabled_reason: Option<String>,
}

/// A small, closed patch language. Block IDs remain stable across replacement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfacePatchOp {
    ReplaceBlock { block: SurfaceBlock },
    InsertBlock { index: usize, block: SurfaceBlock },
    RemoveBlock { block_id: String },
    SetActions { actions: Vec<SurfaceActionDefinition> },
}

/// Versioned conversation surface content events; fallback text is mandatory on create.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
pub enum SurfaceEvent {
    #[serde(rename = "ramflux.surface.create.v1")]
    Create {
        surface_id: String,
        version: u64,
        blocks: Vec<SurfaceBlock>,
        actions: Vec<SurfaceActionDefinition>,
        fallback_text: String,
    },
    #[serde(rename = "ramflux.surface.patch.v1")]
    Patch { surface_id: String, version: u64, base_hash: String, ops: Vec<SurfacePatchOp> },
    #[serde(rename = "ramflux.surface.stream_append.v1")]
    StreamAppend {
        surface_id: String,
        version: u64,
        block_id: String,
        text_delta: String,
        #[serde(rename = "final")]
        final_: bool,
    },
    #[serde(rename = "ramflux.surface.close.v1")]
    Close { surface_id: String, version: u64 },
}
impl SurfaceEvent {
    #[must_use]
    pub fn surface_id(&self) -> &str {
        match self {
            Self::Create { surface_id, .. }
            | Self::Patch { surface_id, .. }
            | Self::StreamAppend { surface_id, .. }
            | Self::Close { surface_id, .. } => surface_id,
        }
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        match self {
            Self::Create { version, .. }
            | Self::Patch { version, .. }
            | Self::StreamAppend { version, .. }
            | Self::Close { version, .. } => *version,
        }
    }
}

/// Only the v1 human-decision schema is accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceActionSchema {
    #[default]
    #[serde(rename = "ramflux.surface.action.v1")]
    V1,
}

/// Human decision bound to reviewed content and canonical arguments.
/// Authentication/author authorization must be checked by the surrounding message protocol.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceAction {
    pub schema: SurfaceActionSchema,
    pub surface_id: String,
    pub version: u64,
    pub surface_hash: String,
    pub action_id: String,
    pub values: Value,
    pub args_hash: String,
}

impl std::fmt::Debug for SurfaceAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SurfaceAction")
            .field("surface_id", &self.surface_id)
            .field("version", &self.version)
            .field("surface_hash", &self.surface_hash)
            .field("action_id", &self.action_id)
            .field("args_hash", &self.args_hash)
            .field("values", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceLimit {
    Blocks,
    Actions,
    TextCharacters,
    DataBytes,
    TextDeltaBytes,
    NestingDepth,
    PatchOperations,
    FinalizedBlocks,
}

/// Typed, payload-free rejections suitable for a later transport adapter.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "reject", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceReject {
    #[error("surface has not been created")]
    NotCreated,
    #[error("surface already exists")]
    AlreadyCreated,
    #[error("surface is closed")]
    Closed,
    #[error("surface ID mismatch")]
    WrongSurface,
    #[error("surface version mismatch: expected {expected}, got {actual}")]
    Version { expected: u64, actual: u64 },
    #[error("surface version exhausted")]
    VersionExhausted,
    #[error("patch base hash conflicts with current content")]
    Conflict,
    #[error("action references stale surface content")]
    Stale,
    #[error("surface limit exceeded: {limit:?}")]
    LimitExceeded { limit: SurfaceLimit },
    #[error("surface identifier is empty")]
    InvalidIdentifier,
    #[error("fallback text must be nonblank")]
    MissingFallback,
    #[error("block IDs must be unique")]
    DuplicateBlock,
    #[error("action IDs must be unique")]
    DuplicateAction,
    #[error("unsupported block data version")]
    UnsupportedBlockVersion,
    #[error("unknown block")]
    UnknownBlock,
    #[error("unknown action")]
    UnknownAction,
    #[error("action is disabled")]
    DisabledAction,
    #[error("block stream is final")]
    BlockClosed,
    #[error("block does not contain an appendable text stream")]
    BlockNotStreamable,
    #[error("block insertion index is out of range")]
    InvalidInsertPosition,
    #[error("action arguments hash does not match values")]
    ArgumentsHashMismatch,
    #[error("surface canonical encoding failed")]
    Encoding,
}
