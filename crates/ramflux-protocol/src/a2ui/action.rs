// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Action frames and the author-literal/raw-owned-input egress grammar.
use super::graph::validate_input;
use super::resolve::Resolution;
use super::wire::{canonical, decode_canonical, validate_identifier, validate_metadata};
use super::{
    ACTION_SCHEMA, JsonPointer, MAX_CONTEXT_ENTRIES, MAX_DELTA_BYTES, MAX_STATE_BYTES, Metadata,
    Reject, ResolvedActionKind, ResolvedContextSource, SurfaceSnapshot, SurfaceState,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBinding {
    pub task_id: String,
    pub step_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Action {
    pub name: String,
    pub surface_id: String,
    pub source_component_id: String,
    pub timestamp: String,
    pub context: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionMessage {
    pub version: String,
    pub action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionFrame {
    pub schema: String,
    pub conversation_id: String,
    pub surface_version: u64,
    pub surface_hash: String,
    pub source_instance: Vec<String>,
    pub args_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_binding: Option<TaskBinding>,
    pub a2ui: ActionMessage,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SurfaceAction(ActionFrame);
impl SurfaceAction {
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.0.surface_version
    }
    #[must_use]
    pub fn surface_id(&self) -> &str {
        &self.0.a2ui.action.surface_id
    }
    #[must_use]
    pub fn surface_hash(&self) -> &str {
        &self.0.surface_hash
    }
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.0.a2ui.action.name
    }
    #[must_use]
    pub fn source_component_id(&self) -> &str {
        &self.0.a2ui.action.source_component_id
    }
    #[must_use]
    pub fn source_instance(&self) -> &[String] {
        &self.0.source_instance
    }
    #[must_use]
    pub fn values(&self) -> &Map<String, Value> {
        &self.0.a2ui.action.context
    }
    #[must_use]
    pub fn args_hash(&self) -> &str {
        &self.0.args_hash
    }
    #[must_use]
    pub fn task_binding(&self) -> Option<&TaskBinding> {
        self.0.task_binding.as_ref()
    }

    /// Admit only original canonical bytes; no last-wins Value constructor exists.
    /// # Errors
    /// Refuses extra fields, invalid version/schema, identifiers and argument commitments.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, Reject> {
        let raw: Value = decode_canonical(bytes, MAX_STATE_BYTES * 2 + MAX_DELTA_BYTES)?;
        super::wire::reject_null_fields(&raw, &["taskBinding"])?;
        if let Some(action) = raw.pointer("/a2ui/action") {
            super::wire::reject_null_fields(action, &["userMessage", "metadata"])?;
        }
        let frame: ActionFrame = serde_json::from_value(raw).map_err(|_| Reject::Encoding)?;
        if time::OffsetDateTime::parse(
            &frame.a2ui.action.timestamp,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            return Err(Reject::Encoding);
        }
        if frame.task_binding.as_ref().is_some_and(|b| {
            [&b.task_id, &b.step_id].iter().any(|id| id.is_empty() || id.len() > 256)
        }) {
            return Err(Reject::Encoding);
        }

        if frame.schema != ACTION_SCHEMA
            || frame.a2ui.version != "1.0"
            || frame.conversation_id.is_empty()
            || frame.conversation_id.len() > 256
            || !(1..=crate::MAX_SAFE_JSON_INTEGER).contains(&frame.surface_version)
            || frame.source_instance.len() > 2
            || frame.a2ui.action.context.len() > MAX_CONTEXT_ENTRIES
        {
            return Err(Reject::Encoding);
        }
        for id in [
            &frame.a2ui.action.surface_id,
            &frame.a2ui.action.source_component_id,
            &frame.a2ui.action.name,
        ] {
            validate_identifier(id)?;
        }
        for pointer in &frame.source_instance {
            JsonPointer::parse(pointer)?;
        }
        for key in frame.a2ui.action.context.keys() {
            validate_identifier(key)?;
        }
        validate_metadata(frame.a2ui.action.metadata.as_ref())?;
        if frame.args_hash != frame.arguments_hash()? {
            return Err(Reject::Integrity);
        }
        Ok(Self(frame))
    }
    #[must_use]
    pub const fn frame(&self) -> &ActionFrame {
        &self.0
    }
}
impl ActionFrame {
    /// Pinned hash of exactly the source instance, name, context and optional userMessage.
    /// # Errors
    /// Refuses non-I-JSON values and serialization failure.
    pub fn arguments_hash(&self) -> Result<String, Reject> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Args<'a> {
            source_instance: &'a [String],
            name: &'a str,
            context: &'a Map<String, Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            user_message: &'a Option<String>,
        }
        let a = &self.a2ui.action;
        Ok(crate::hash_base64url(
            "ramflux.a2ui.action_args.v2",
            &canonical(&Args {
                source_instance: &self.source_instance,
                name: &a.name,
                context: &a.context,
                user_message: &a.user_message,
            })?,
        ))
    }
    /// Validate locally constructed action bytes before carrier signing.
    /// # Errors
    /// Refuses invalid framing or argument hash.
    pub fn wire_bytes(&self) -> Result<Vec<u8>, Reject> {
        let bytes = canonical(self)?;
        SurfaceAction::from_wire_bytes(&bytes)?;
        Ok(bytes)
    }
}
pub(super) fn validate_components(snapshot: &mut SurfaceSnapshot) -> Result<(), Reject> {
    let reached = Resolution::new(snapshot)?.graph.reached;
    snapshot.components.retain(|component| {
        component.get("id").and_then(Value::as_str).is_some_and(|id| reached.contains(id))
    });
    Ok(())
}
impl SurfaceState {
    /// Author-side validation reconstructs only explicit raw context inputs before checking.
    /// # Errors
    /// Refuses stale actions, mismatched instances/literals/types/checks and forged arguments.
    pub fn validate_action(&self, action: &SurfaceAction) -> Result<(), Reject> {
        let frame = action.frame();
        if self.is_closed() {
            return Err(Reject::Closed);
        }
        let snapshot = self.content().ok_or(Reject::NotCreated)?;
        if self.version() != frame.surface_version
            || self.hash() != Some(frame.surface_hash.as_str())
            || self.conversation_id() != Some(frame.conversation_id.as_str())
            || snapshot.surface_id != frame.a2ui.action.surface_id
        {
            return Err(Reject::Conflict);
        }
        let resolution = Resolution::new(snapshot)?;
        let submitted = &frame.a2ui.action;
        let (source, declared) =
            resolution.action(&submitted.source_component_id, &frame.source_instance)?;
        let ResolvedActionKind::Event { name, user_message, context, .. } = declared else {
            return Err(Reject::Expression);
        };
        if submitted.metadata.is_some() {
            return Err(Reject::Validation("action metadata has no declared egress source".into()));
        }
        if *name != submitted.name
            || user_message.as_deref() != submitted.user_message.as_deref()
            || context.len() != submitted.context.len()
            || context.keys().any(|key| !submitted.context.contains_key(key))
        {
            return Err(Reject::Integrity);
        }
        let mut overlay = snapshot.data_model.clone();
        let mut witness = Map::new();
        for (key, declared) in context {
            let value = submitted.context.get(key).ok_or(Reject::Integrity)?;
            match declared {
                ResolvedContextSource::Literal { value: literal } => {
                    if canonical(literal)? != canonical(value)? {
                        return Err(Reject::Integrity);
                    }
                }
                ResolvedContextSource::Input { pointer } => {
                    let input =
                        resolution.input(pointer, &source.scope).ok_or(Reject::Expression)?;
                    validate_input(
                        input.instance.component,
                        value,
                        &snapshot.data_model,
                        &input.instance.prefix,
                    )?;
                    input.pointer.update(&mut overlay, value.clone())?;
                    witness.insert(key.clone(), value.clone());
                }
            }
        }
        if canonical(&witness)?.len() > MAX_DELTA_BYTES {
            return Err(Reject::Limit);
        }
        super::expression::checks(source.component.get("@checks"), &overlay, &source.prefix)?;
        if frame.arguments_hash()? != frame.args_hash {
            return Err(Reject::Integrity);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SurfaceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurfaceAction")
            .field("surface_id", &self.surface_id())
            .field("version", &self.version())
            .field("context", &"[redacted]")
            .finish_non_exhaustive()
    }
}
