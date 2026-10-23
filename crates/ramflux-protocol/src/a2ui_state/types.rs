// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Additive v2 conversation binding around the existing A2UI command contract.
use crate::A2uiCommand;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const A2UI_CONVERSATION_SCHEMA: &str = "ramflux.a2ui.conversation.v2";
pub const A2UI_ACTION_SCHEMA: &str = "ramflux.a2ui.action.v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2uiConversationSchema {
    #[serde(rename = "ramflux.a2ui.conversation.v2")]
    V2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2uiActionSchema {
    #[serde(rename = "ramflux.a2ui.action.v2")]
    V2,
}

/// Decrypted payload for a signed conversation message. The legacy signed A2UI envelope and
/// its version-1 command fields are unchanged; this v2 wrapper binds their conversation/version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct A2uiConversationEvent {
    pub schema: A2uiConversationSchema,
    pub conversation_id: String,
    pub version: u64,
    pub command: A2uiCommand,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventFields {
    schema: A2uiConversationSchema,
    conversation_id: String,
    version: u64,
    command: A2uiCommand,
}
impl<'de> Deserialize<'de> for A2uiConversationEvent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
        let v: EventFields =
            crate::parse_i_json(raw.get().as_bytes()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema: v.schema,
            conversation_id: v.conversation_id,
            version: v.version,
            command: v.command,
        })
    }
}

/// A human decision to the surface author; the signed conversation carrier authenticates it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct A2uiSurfaceAction {
    pub schema: A2uiActionSchema,
    pub conversation_id: String,
    pub surface_id: String,
    pub version: u64,
    pub surface_hash: String,
    pub action_id: String,
    pub values: Value,
    pub args_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActionFields {
    schema: A2uiActionSchema,
    conversation_id: String,
    surface_id: String,
    version: u64,
    surface_hash: String,
    action_id: String,
    values: Value,
    args_hash: String,
}
impl<'de> Deserialize<'de> for A2uiSurfaceAction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
        let v: ActionFields =
            crate::parse_i_json(raw.get().as_bytes()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema: v.schema,
            conversation_id: v.conversation_id,
            surface_id: v.surface_id,
            version: v.version,
            surface_hash: v.surface_hash,
            action_id: v.action_id,
            values: v.values,
            args_hash: v.args_hash,
        })
    }
}
impl std::fmt::Debug for A2uiSurfaceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2uiSurfaceAction")
            .field("surface_id", &self.surface_id)
            .field("version", &self.version)
            .field("values", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Extends updateComponents with ordinal insertion and action replacement, available only in v2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatchSurfaceCommand {
    pub surface_id: String,
    pub base_surface_hash: String,
    pub ops: Vec<SurfacePatchOp>,
    pub new_surface_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfacePatchOp {
    ReplaceBlock { component: Value },
    InsertBlock { index: usize, component: Value },
    RemoveBlock { component_id: String },
    SetActions { actions: Vec<Value> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamAppendCommand {
    pub surface_id: String,
    pub component_id: String,
    pub text_delta: String,
    #[serde(rename = "final")]
    pub final_: bool,
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
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "reject", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceReject {
    #[error("surface has not been created")]
    NotCreated,
    #[error("surface already exists")]
    AlreadyCreated,
    #[error("surface is closed")]
    Closed,
    #[error("surface or conversation mismatch")]
    WrongSurface,
    #[error("expected version {expected}, got {actual}")]
    Version { expected: u64, actual: u64 },
    #[error("surface version exhausted")]
    VersionExhausted,
    #[error("base surface hash conflict")]
    Conflict,
    #[error("declared resulting hash mismatch")]
    ResultHashMismatch,
    #[error("stale action")]
    Stale,
    #[error("surface limit exceeded: {limit:?}")]
    LimitExceeded { limit: SurfaceLimit },
    #[error("invalid identifier")]
    InvalidIdentifier,
    #[error("fallback text is required")]
    MissingFallback,
    #[error("duplicate component")]
    DuplicateBlock,
    #[error("duplicate action")]
    DuplicateAction,
    #[error("unknown component")]
    UnknownBlock,
    #[error("unknown action")]
    UnknownAction,
    #[error("action disabled")]
    DisabledAction,
    #[error("component stream is final")]
    BlockClosed,
    #[error("component has no text stream")]
    BlockNotStreamable,
    #[error("invalid insertion index")]
    InvalidInsertPosition,
    #[error("argument hash mismatch")]
    ArgumentsHashMismatch,
    #[error("invalid I-JSON")]
    InvalidJson,
    #[error("canonical encoding failed")]
    Encoding,
}
