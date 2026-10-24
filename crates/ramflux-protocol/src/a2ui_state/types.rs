// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Versioned commands and opaque inputs validated from original wire bytes.
use crate::{
    CreateSurfaceCommand, DeleteSurfaceCommand, ProtocolError, UpdateComponentsCommand,
    UpdateDataModelCommand,
};
use serde::{Deserialize, Serialize};
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

/// V2 reuses each legacy command DTO and adds commands inside the versioned carrier only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum A2uiConversationCommand {
    CreateSurface(CreateSurfaceCommand),
    UpdateComponents(UpdateComponentsCommand),
    UpdateDataModel(UpdateDataModelCommand),
    DeleteSurface(DeleteSurfaceCommand),
    PatchSurface(PatchSurfaceCommand),
    StreamAppend(StreamAppendCommand),
}
impl From<crate::A2uiCommand> for A2uiConversationCommand {
    fn from(command: crate::A2uiCommand) -> Self {
        match command {
            crate::A2uiCommand::CreateSurface(c) => Self::CreateSurface(c),
            crate::A2uiCommand::UpdateComponents(c) => Self::UpdateComponents(c),
            crate::A2uiCommand::UpdateDataModel(c) => Self::UpdateDataModel(c),
            crate::A2uiCommand::DeleteSurface(c) => Self::DeleteSurface(c),
        }
    }
}

/// Validated decrypted v2 payload. Feed original signed plaintext bytes to
/// [`Self::from_wire_bytes`]; never preparse through a last-wins JSON map.
/// Private contents and absence of `Deserialize` prevent unchecked `Value` ingress.
///
/// ```compile_fail
/// use ramflux_protocol::A2uiConversationEvent;
/// let dropped_duplicate: serde_json::Value = serde_json::from_str(r#"{"x":1,"x":2}"#).unwrap();
/// let event = serde_json::from_value::<A2uiConversationEvent>(dropped_duplicate).unwrap();
/// ```
/// ```compile_fail
/// use ramflux_protocol::SurfaceState;
/// let dropped_duplicate: serde_json::Value = serde_json::from_str(r#"{"x":1,"x":2}"#).unwrap();
/// SurfaceState::default().apply(&dropped_duplicate).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct A2uiConversationEvent(EventFields);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EventFields {
    pub(super) schema: A2uiConversationSchema,
    pub(super) conversation_id: String,
    pub(super) version: u64,
    pub(super) command: A2uiConversationCommand,
}
impl A2uiConversationEvent {
    /// The only ingress constructor; retains duplicate-key evidence until I-JSON validation.
    /// # Errors
    /// Rejects non-I-JSON original bytes and invalid v2 schemas/fields.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        crate::parse_i_json(bytes).map(Self)
    }
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.0.version
    }
    #[must_use]
    pub const fn command(&self) -> &A2uiConversationCommand {
        &self.0.command
    }
    pub(super) const fn fields(&self) -> &EventFields {
        &self.0
    }
}

/// Validated human decision. The signed carrier authenticates the author and deduplicates it.
/// There is deliberately no `Deserialize` or conversion from `Value`.
/// ```compile_fail
/// use ramflux_protocol::A2uiSurfaceAction;
/// let dropped_duplicate: serde_json::Value = serde_json::from_str(r#"{"x":1,"x":2}"#).unwrap();
/// let action = serde_json::from_value::<A2uiSurfaceAction>(dropped_duplicate).unwrap();
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct A2uiSurfaceAction(ActionFields);
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ActionFields {
    pub(super) schema: A2uiActionSchema,
    pub(super) conversation_id: String,
    pub(super) surface_id: String,
    pub(super) version: u64,
    pub(super) surface_hash: String,
    pub(super) action_id: String,
    pub(super) values: Value,
    pub(super) args_hash: String,
}
impl A2uiSurfaceAction {
    /// # Errors
    /// Rejects non-I-JSON original bytes and invalid v2 schemas/fields.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        crate::parse_i_json(bytes).map(Self)
    }
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub fn surface_id(&self) -> &str {
        &self.0.surface_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.0.version
    }
    #[must_use]
    pub fn surface_hash(&self) -> &str {
        &self.0.surface_hash
    }
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.0.action_id
    }
    #[must_use]
    pub fn values(&self) -> &Value {
        &self.0.values
    }
    #[must_use]
    pub fn args_hash(&self) -> &str {
        &self.0.args_hash
    }
    pub(super) const fn fields(&self) -> &ActionFields {
        &self.0
    }
}
impl std::fmt::Debug for A2uiSurfaceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2uiSurfaceAction")
            .field("surface_id", &self.surface_id())
            .field("version", &self.version())
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
    SetFallbackText { fallback_text: String },
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
    #[error("fallback text contains unsafe control characters")]
    UnsafeFallback,
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
