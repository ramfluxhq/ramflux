// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic projection and optimistic concurrency for conversation-bound A2UI commands.
use super::{
    A2uiConversationEvent, A2uiSurfaceAction, MAX_SURFACE_FINALIZED_BLOCKS, MAX_SURFACE_PATCH_OPS,
    MAX_SURFACE_TEXT_CHARS, MAX_SURFACE_TEXT_DELTA_BYTES, SurfaceLimit, SurfacePatchOp,
    SurfaceReject, limits, snapshot, surface_args_hash,
};
use crate::{A2uiConversationCommand as A2uiCommand, CreateSurfaceCommand, MAX_SAFE_JSON_INTEGER};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SurfaceState {
    pub(super) content: Option<CreateSurfaceCommand>,
    pub(super) hash: Option<String>,
    pub(super) conversation_id: Option<String>,
    pub(super) version: u64,
    pub(super) closed: bool,
    pub(super) final_components: BTreeMap<Arc<str>, Arc<FinalText>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FinalText {
    pub(super) nested: bool,
    pub(super) text_hash: String,
}
pub(super) fn final_component_key(id: &str) -> String {
    crate::hash_base64url(crate::domain::A2UI_FINAL_COMPONENT, id.as_bytes())
}
pub(super) fn final_text_hash(text: &str) -> String {
    crate::hash_base64url(crate::domain::A2UI_FINAL_TEXT, text.as_bytes())
}
impl FinalText {
    pub(super) fn matches(&self, component: &Value) -> bool {
        stream_text(component).is_some_and(|(nested, text)| {
            nested == self.nested && final_text_hash(text) == self.text_hash
        })
    }
}
pub(super) fn stream_text(component: &Value) -> Option<(bool, &str)> {
    if let Some(value) = component.get("text") {
        value.as_str().map(|text| (false, text))
    } else {
        component.pointer("/data/text").and_then(Value::as_str).map(|text| (true, text))
    }
}
impl SurfaceState {
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    #[must_use]
    pub const fn content(&self) -> Option<&CreateSurfaceCommand> {
        self.content.as_ref()
    }
    #[must_use]
    pub fn conversation_id(&self) -> Option<&str> {
        self.conversation_id.as_deref()
    }
    #[must_use]
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    /// Return the next state without mutating this state on either success or rejection.
    /// # Errors
    /// Rejects invalid versions, conversation bindings, hashes, operations and resource limits.
    pub fn apply(&self, event: &A2uiConversationEvent) -> Result<Self, SurfaceReject> {
        let event = event.fields();
        if self.closed {
            return Err(SurfaceReject::Closed);
        }
        if self.version >= MAX_SAFE_JSON_INTEGER {
            return Err(SurfaceReject::VersionExhausted);
        }
        let expected = self.version + 1;
        if event.version != expected {
            return Err(SurfaceReject::Version { expected, actual: event.version });
        }
        limits::identifier(&event.conversation_id)?;
        let mut next = self.clone();
        let declared_hash = match (&self.content, &event.command) {
            (None, A2uiCommand::CreateSurface(content)) => {
                next.content = Some(content.clone());
                next.conversation_id = Some(event.conversation_id.clone());
                None
            }
            (None, _) => return Err(SurfaceReject::NotCreated),
            (Some(_), A2uiCommand::CreateSurface(_)) => return Err(SurfaceReject::AlreadyCreated),
            (Some(content), command) => {
                if self.conversation_id.as_deref() != Some(&event.conversation_id)
                    || command_id(command) != content.surface_id
                {
                    return Err(SurfaceReject::WrongSurface);
                }
                self.update(&mut next, command)?
            }
        };
        let content = next.content.as_ref().ok_or(SurfaceReject::NotCreated)?;
        for component in &content.components {
            let id = snapshot::component_id(component)?;
            if let Some(final_text) = next.final_components.get(final_component_key(id).as_str())
                && !final_text.matches(component)
            {
                return Err(SurfaceReject::BlockClosed);
            }
        }
        let hash = snapshot::validated_hash(content)?;
        if declared_hash.is_some_and(|declared| declared != hash) {
            return Err(SurfaceReject::ResultHashMismatch);
        }
        next.version = event.version;
        next.hash = Some(hash);
        Ok(next)
    }

    fn update<'a>(
        &self,
        next: &mut Self,
        command: &'a A2uiCommand,
    ) -> Result<Option<&'a str>, SurfaceReject> {
        let content = next.content.as_mut().ok_or(SurfaceReject::NotCreated)?;
        let declared_hash = match command {
            A2uiCommand::UpdateComponents(update) => {
                self.base(&update.base_surface_hash)?;
                if update.components.len().saturating_add(update.remove_component_ids.len())
                    > MAX_SURFACE_PATCH_OPS
                {
                    return Err(limits::exceeded(SurfaceLimit::PatchOperations));
                }
                let mut ids = BTreeSet::new();
                for id in &update.remove_component_ids {
                    if !ids.insert(id.as_str()) {
                        return Err(SurfaceReject::DuplicateBlock);
                    }
                    remove(content, id)?;
                }
                for component in &update.components {
                    let id = snapshot::component_id(component)?;
                    if !ids.insert(id) {
                        return Err(SurfaceReject::DuplicateBlock);
                    }
                    if let Some(index) = position(content, id) {
                        content.components[index] = component.clone();
                    } else {
                        content.components.push(component.clone());
                    }
                }
                Some(update.new_surface_hash.as_str())
            }
            A2uiCommand::UpdateDataModel(update) => {
                self.base(&update.base_surface_hash)?;
                // Top-level merge: null removes a member, nested values replace atomically.
                for (key, value) in &update.data_patch {
                    if value.is_null() {
                        content.data_model.remove(key);
                    } else {
                        content.data_model.insert(key.clone(), value.clone());
                    }
                }
                Some(update.new_surface_hash.as_str())
            }
            A2uiCommand::PatchSurface(patch) => {
                self.base(&patch.base_surface_hash)?;
                if patch.ops.len() > MAX_SURFACE_PATCH_OPS {
                    return Err(limits::exceeded(SurfaceLimit::PatchOperations));
                }
                for op in &patch.ops {
                    patch_one(content, op)?;
                }
                Some(patch.new_surface_hash.as_str())
            }
            A2uiCommand::StreamAppend(append) => {
                append_text(content, append, &mut next.final_components)?;
                None
            }
            A2uiCommand::DeleteSurface(_) => {
                next.closed = true;
                None
            }
            A2uiCommand::CreateSurface(_) => return Err(SurfaceReject::AlreadyCreated),
        };
        Ok(declared_hash)
    }

    fn base(&self, hash: &str) -> Result<(), SurfaceReject> {
        if self.hash.as_deref() == Some(hash) { Ok(()) } else { Err(SurfaceReject::Conflict) }
    }

    /// Validate a decision against the current snapshot without consuming a version.
    /// # Errors
    /// Rejects closed, stale, mismatched, disabled or unbound decisions and invalid arguments.
    pub fn validate_action(&self, action: &A2uiSurfaceAction) -> Result<(), SurfaceReject> {
        let action = action.fields();
        if self.closed {
            return Err(SurfaceReject::Closed);
        }
        let content = self.content.as_ref().ok_or(SurfaceReject::NotCreated)?;
        if action.surface_id != content.surface_id
            || self.conversation_id.as_deref() != Some(&action.conversation_id)
        {
            return Err(SurfaceReject::WrongSurface);
        }
        if action.version != self.version || self.hash.as_deref() != Some(&action.surface_hash) {
            return Err(SurfaceReject::Stale);
        }
        let descriptor = content
            .allowed_actions
            .iter()
            .find(|v| snapshot::action_id(v).ok() == Some(&action.action_id))
            .ok_or(SurfaceReject::UnknownAction)?;
        if descriptor
            .get("disabledReason")
            .or_else(|| descriptor.get("disabled_reason"))
            .is_some_and(|v| !v.is_null())
        {
            return Err(SurfaceReject::DisabledAction);
        }
        if surface_args_hash(&action.values)? != action.args_hash {
            return Err(SurfaceReject::ArgumentsHashMismatch);
        }
        Ok(())
    }
}
fn command_id(command: &A2uiCommand) -> &str {
    match command {
        A2uiCommand::CreateSurface(c) => &c.surface_id,
        A2uiCommand::UpdateComponents(c) => &c.surface_id,
        A2uiCommand::UpdateDataModel(c) => &c.surface_id,
        A2uiCommand::DeleteSurface(c) => &c.surface_id,
        A2uiCommand::PatchSurface(c) => &c.surface_id,
        A2uiCommand::StreamAppend(c) => &c.surface_id,
    }
}
fn position(content: &CreateSurfaceCommand, id: &str) -> Option<usize> {
    content.components.iter().position(|v| snapshot::component_id(v).ok() == Some(id))
}
fn remove(content: &mut CreateSurfaceCommand, id: &str) -> Result<(), SurfaceReject> {
    let index = position(content, id).ok_or(SurfaceReject::UnknownBlock)?;
    content.components.remove(index);
    Ok(())
}
fn patch_one(content: &mut CreateSurfaceCommand, op: &SurfacePatchOp) -> Result<(), SurfaceReject> {
    #[cfg(test)]
    super::work::operation();
    match op {
        SurfacePatchOp::ReplaceBlock { component } => {
            let index = position(content, snapshot::component_id(component)?)
                .ok_or(SurfaceReject::UnknownBlock)?;
            content.components[index] = component.clone();
        }
        SurfacePatchOp::InsertBlock { index, component } => {
            let id = snapshot::component_id(component)?;
            if position(content, id).is_some() {
                return Err(SurfaceReject::DuplicateBlock);
            }
            if *index > content.components.len() {
                return Err(SurfaceReject::InvalidInsertPosition);
            }
            content.components.insert(*index, component.clone());
        }
        SurfacePatchOp::RemoveBlock { component_id } => remove(content, component_id)?,
        SurfacePatchOp::SetActions { actions } => content.allowed_actions.clone_from(actions),
        SurfacePatchOp::SetFallbackText { fallback_text } => {
            content.fallback_text.clone_from(fallback_text);
        }
    }
    Ok(())
}

fn append_text(
    content: &mut CreateSurfaceCommand,
    append: &crate::StreamAppendCommand,
    final_components: &mut BTreeMap<Arc<str>, Arc<FinalText>>,
) -> Result<(), SurfaceReject> {
    if final_components.contains_key(final_component_key(&append.component_id).as_str()) {
        return Err(SurfaceReject::BlockClosed);
    }
    if append.text_delta.len() > MAX_SURFACE_TEXT_DELTA_BYTES {
        return Err(limits::exceeded(SurfaceLimit::TextDeltaBytes));
    }
    let index = position(content, &append.component_id).ok_or(SurfaceReject::UnknownBlock)?;
    let component = &mut content.components[index];
    let nested = component.get("text").is_none();
    let field = if component.get("text").is_some() {
        component.get_mut("text")
    } else {
        component.get_mut("data").and_then(|v| v.get_mut("text"))
    };
    let Some(Value::String(text)) = field else {
        return Err(SurfaceReject::BlockNotStreamable);
    };
    // Bound allocation before appending; scalar count is checked below.
    if text.len().saturating_add(append.text_delta.len()) > super::MAX_SURFACE_DATA_BYTES {
        return Err(limits::exceeded(SurfaceLimit::DataBytes));
    }
    if text.chars().count() + append.text_delta.chars().count() > MAX_SURFACE_TEXT_CHARS {
        return Err(limits::exceeded(SurfaceLimit::TextCharacters));
    }
    text.push_str(&append.text_delta);
    if append.final_ {
        if final_components.len() >= MAX_SURFACE_FINALIZED_BLOCKS {
            return Err(limits::exceeded(SurfaceLimit::FinalizedBlocks));
        }
        final_components.insert(
            Arc::<str>::from(final_component_key(&append.component_id)),
            Arc::new(FinalText { nested, text_hash: final_text_hash(text) }),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_exhaustion_never_wraps() -> Result<(), crate::ProtocolError> {
        let state = SurfaceState { version: MAX_SAFE_JSON_INTEGER, ..SurfaceState::default() };
        let event=A2uiConversationEvent::from_wire_bytes(br#"{"schema":"ramflux.a2ui.conversation.v2","conversationId":"c","version":1,"command":{"command":"deleteSurface","surfaceId":"s"}}"#)?;
        assert_eq!(state.apply(&event), Err(SurfaceReject::VersionExhausted));
        Ok(())
    }
}
