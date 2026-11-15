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
        let raw: Value = crate::parse_i_json(bytes)?;
        let web = raw.pointer("/command/command").and_then(Value::as_str) == Some("createSurface")
            && raw.pointer("/command/catalog").and_then(Value::as_str)
                == Some(super::web_catalog::CATALOG);
        let snapshot = if web {
            let mut value = raw["command"].clone();
            value.as_object_mut().ok_or(ProtocolError::NotObject)?.remove("command");
            super::web_catalog::validate_raw(&value).map_err(web_ingress_error)?;
            Some(value)
        } else {
            None
        };
        let event: EventFields = serde_json::from_value(raw).map_err(ProtocolError::IJson)?;
        if let (Some(snapshot), A2uiConversationCommand::CreateSurface(content)) =
            (snapshot, &event.command)
        {
            super::web_catalog::validate_received(&snapshot, content).map_err(web_ingress_error)?;
            if crate::canonical_json_bytes(&event)? != bytes {
                return Err(web_ingress_error(SurfaceReject::WebCatalog {
                    path: String::new(),
                    rule: "nonCanonicalBytes".into(),
                }));
            }
        }
        Ok(Self(event))
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

/// Task and step named by a requester-signed surface action and its creator receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceTaskBinding {
    pub task_id: String,
    pub step_id: String,
}
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) task_binding: Option<SurfaceTaskBinding>,
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
    #[must_use]
    pub const fn task_binding(&self) -> Option<&SurfaceTaskBinding> {
        self.0.task_binding.as_ref()
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

/// Typed local intent for [`encode_a2ui_surface_action`]. Schema and `argsHash` are not caller fields.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct A2uiSurfaceActionInput {
    pub surface_id: String,
    pub version: u64,
    pub surface_hash: String,
    pub action_id: String,
    pub values: Value,
    #[serde(default)]
    pub task_binding: Option<SurfaceTaskBinding>,
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
    #[error("web catalog {path}: {rule}")]
    WebCatalog { path: String, rule: String },
    #[error("canonical encoding failed")]
    Encoding,
}

/// Encodes locally authored typed commands for signing. This is an egress builder: never use it
/// to re-encode remote JSON before ingress validation. Remote events still enter exclusively via
/// `A2uiConversationEvent::from_wire_bytes` on their original bytes.
/// # Errors
/// Rejects values that cannot be represented as canonical I-JSON.
pub fn encode_a2ui_conversation_event(
    conversation_id: &str,
    version: u64,
    command: &A2uiConversationCommand,
) -> Result<Vec<u8>, ProtocolError> {
    let event = EventFields {
        schema: A2uiConversationSchema::V2,
        conversation_id: conversation_id.into(),
        version,
        command: command.clone(),
    };
    crate::canonical_json_bytes(&event)
}

/// Encodes a locally authored surface action. This is an egress builder: never use it to
/// re-encode remote JSON. Remote actions still enter via [`A2uiSurfaceAction::from_wire_bytes`].
/// The argument hash is computed here, so a caller cannot supply bytes or a hash.
/// # Errors
/// Rejects empty identifiers, values that are not bounded I-JSON, and bytes that do not
/// round-trip through action ingress.
pub fn encode_a2ui_surface_action(
    conversation_id: &str,
    input: &A2uiSurfaceActionInput,
) -> Result<Vec<u8>, ProtocolError> {
    action_identifier(conversation_id)?;
    action_identifier(&input.surface_id)?;
    action_identifier(&input.surface_hash)?;
    action_identifier(&input.action_id)?;
    if let Some(binding) = &input.task_binding {
        action_identifier(&binding.task_id)?;
        action_identifier(&binding.step_id)?;
    }
    let args_hash = super::surface_args_hash(&input.values).map_err(action_refused)?;
    let action = ActionFields {
        schema: A2uiActionSchema::V2,
        conversation_id: conversation_id.into(),
        surface_id: input.surface_id.clone(),
        version: input.version,
        surface_hash: input.surface_hash.clone(),
        action_id: input.action_id.clone(),
        values: input.values.clone(),
        args_hash,
        task_binding: input.task_binding.clone(),
    };
    let bytes = crate::canonical_json_bytes(&action)?;
    let parsed = A2uiSurfaceAction::from_wire_bytes(&bytes)?;
    if parsed.fields() != &action {
        return Err(action_refused(SurfaceReject::Encoding));
    }
    Ok(bytes)
}

fn action_identifier(value: &str) -> Result<(), ProtocolError> {
    super::limits::identifier(value).map_err(action_refused)?;
    crate::validate_i_json_value(&Value::String(value.to_owned()))
}

fn action_refused(error: SurfaceReject) -> ProtocolError {
    ProtocolError::IJson(serde::de::Error::custom(error))
}

fn web_ingress_error(error: SurfaceReject) -> ProtocolError {
    ProtocolError::IJson(serde::de::Error::custom(error))
}

#[cfg(test)]
mod tests {
    use super::{
        A2uiSurfaceAction, A2uiSurfaceActionInput, SurfaceTaskBinding, encode_a2ui_surface_action,
    };
    use crate::{parse_i_json, surface_args_hash};
    use serde_json::{Value, json};

    const OVER_DEPTH: usize = 70;

    fn input(task: bool) -> A2uiSurfaceActionInput {
        A2uiSurfaceActionInput {
            surface_id: "surface".into(),
            version: 2,
            surface_hash: "hash".into(),
            action_id: "choose".into(),
            values: json!({"choice": "yes"}),
            task_binding: task
                .then(|| SurfaceTaskBinding { task_id: "task".into(), step_id: "step".into() }),
        }
    }

    #[test]
    fn surface_action_round_trips_with_and_without_a_task_binding() {
        for task in [false, true] {
            let intent = input(task);
            let first = encode_a2ui_surface_action("conversation", &intent)
                .expect("test: typed action encodes");
            let second = encode_a2ui_surface_action("conversation", &intent)
                .expect("test: typed action encodes again");
            assert_eq!(first, second, "egress encoding must be stable");
            let parsed = A2uiSurfaceAction::from_wire_bytes(&first)
                .expect("test: encoded action is ingress");
            assert_eq!(parsed.conversation_id(), "conversation", "conversation id");
            assert_eq!(parsed.surface_id(), intent.surface_id, "surface id");
            assert_eq!(parsed.version(), intent.version, "version");
            assert_eq!(parsed.surface_hash(), intent.surface_hash, "surface hash");
            assert_eq!(parsed.action_id(), intent.action_id, "action id");
            assert_eq!(parsed.values(), &intent.values, "values");
            assert_eq!(parsed.task_binding(), intent.task_binding.as_ref(), "task binding");
            let hash = surface_args_hash(&intent.values).expect("test: args hash");
            assert_eq!(parsed.args_hash(), hash, "encoder owns the argument hash");
        }
    }

    #[test]
    fn surface_action_refuses_empty_identifiers() {
        let intent = input(false);
        assert!(
            encode_a2ui_surface_action("", &intent).is_err(),
            "empty conversation id must be refused"
        );
        for (label, broken) in [
            ("surface", A2uiSurfaceActionInput { surface_id: String::new(), ..intent.clone() }),
            ("hash", A2uiSurfaceActionInput { surface_hash: String::new(), ..intent.clone() }),
            ("action", A2uiSurfaceActionInput { action_id: String::new(), ..intent.clone() }),
        ] {
            assert!(
                encode_a2ui_surface_action("conversation", &broken).is_err(),
                "empty {label} must be refused"
            );
        }
        let bound = A2uiSurfaceActionInput {
            task_binding: Some(SurfaceTaskBinding {
                task_id: String::new(),
                step_id: "step".into(),
            }),
            ..intent
        };
        assert!(
            encode_a2ui_surface_action("conversation", &bound).is_err(),
            "empty task id must be refused"
        );
    }

    #[test]
    fn surface_action_refuses_values_outside_i_json_and_depth_limits() {
        let mut intent = input(false);
        intent.values = json!({"text": "\u{fffe}"});
        assert!(
            encode_a2ui_surface_action("conversation", &intent).is_err(),
            "a noncharacter in values must be refused"
        );
        let mut nested = Value::Object(serde_json::Map::new());
        for _ in 0..OVER_DEPTH {
            nested = json!({"n": nested});
        }
        intent.values = nested;
        assert!(
            encode_a2ui_surface_action("conversation", &intent).is_err(),
            "values nested past the surface depth limit must be refused"
        );
    }

    #[test]
    fn surface_action_refuses_hand_built_wire_fields() {
        let duplicate = br#"{"surfaceId":"s","version":1,"surfaceHash":"h","actionId":"a","values":{},"surfaceId":"other"}"#;
        assert!(
            parse_i_json::<A2uiSurfaceActionInput>(duplicate).is_err(),
            "duplicate action fields must be refused"
        );
        let supplied_hash = br#"{"surfaceId":"s","version":1,"surfaceHash":"h","actionId":"a","values":{},"argsHash":"caller"}"#;
        assert!(
            parse_i_json::<A2uiSurfaceActionInput>(supplied_hash).is_err(),
            "a caller-supplied argsHash must be refused"
        );
    }
}
