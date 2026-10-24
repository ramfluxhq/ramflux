// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed deterministic reply planning; no approvals, tasks or external execution.
use crate::{Config, Error, Result, Rule};
use ramflux_protocol::{
    A2uiConversationCommand as Command, A2uiSurfaceAction, CreateSurfaceCommand,
    DeleteSurfaceCommand, PatchSurfaceCommand, StreamAppendCommand, SurfacePatchOp, SurfaceType,
};
use serde_json::json;

pub struct ConversationInput<'a> {
    pub conversation_id: &'a str,
    pub message_id: &'a str,
    pub text: &'a str,
}
/// An action already accepted by rfd, plus the latest explicitly read surface snapshot.
pub struct ActionInput<'a> {
    pub action: &'a A2uiSurfaceAction,
    pub snapshot: &'a CreateSurfaceCommand,
    pub closed: bool,
}
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Intent {
    ReplyText(String),
    CreateSurface(CreateSurfaceCommand),
    StreamAppend(StreamAppendCommand),
    PatchSurface(PatchSurfaceCommand),
    CloseSurface(DeleteSurfaceCommand),
}
impl Intent {
    pub(crate) fn command(&self) -> Option<Command> {
        Some(match self {
            Self::ReplyText(_) => return None,
            Self::CreateSurface(c) => Command::CreateSurface(c.clone()),
            Self::StreamAppend(c) => Command::StreamAppend(c.clone()),
            Self::PatchSurface(c) => Command::PatchSurface(c.clone()),
            Self::CloseSurface(c) => Command::DeleteSurface(c.clone()),
        })
    }
}
pub trait EngineProvider {
    /// # Errors
    /// Reports provider failures without exposing input text.
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>>;
    /// # Errors
    /// Rejects invalid plans. The default provider has no action behavior.
    fn action(&mut self, _input: &ActionInput<'_>) -> Result<Vec<Intent>> {
        Ok(Vec::new())
    }
}
pub struct RuleEngine {
    rules: Vec<Rule>,
}
impl RuleEngine {
    /// # Errors
    /// Rejects configurations exceeding the host's finite rule/reply bounds.
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self { rules: config.rules.clone() })
    }
}
impl EngineProvider for RuleEngine {
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>> {
        let Some(rule) = self.rules.iter().find(|rule| input.text.trim() == rule.pattern) else {
            return Ok(Vec::new());
        };
        let Some(surface) = &rule.surface else {
            return Ok(vec![Intent::ReplyText(rule.reply.clone())]);
        };
        let id =
            format!("agent-{}", ramflux_sdk::new_surface_message_id().map_err(|_| Error::State)?);
        let mut content = CreateSurfaceCommand {
            surface_id: id.clone(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Working".into(),
            fallback_markdown: None,
            components: vec![
                json!({"id":"reply","type":"Text","text":""}),
                json!({"id":"result","type":"Text","text":""}),
            ],
            data_model: serde_json::Map::from_iter([
                ("rule".into(), json!(rule.pattern)),
                ("agent_host".into(), json!("ramflux.agent.rule.v1")),
            ]),
            allowed_actions: surface
                .choices
                .iter()
                .map(|choice| json!({"name":choice.id,"label":choice.label}))
                .collect(),
        };
        let mut intents = vec![Intent::CreateSurface(content.clone())];
        let parts = chunks(&rule.reply, surface.chunk_bytes);
        for (index, part) in parts.iter().enumerate() {
            intents.push(Intent::StreamAppend(StreamAppendCommand {
                surface_id: id.clone(),
                component_id: "reply".into(),
                text_delta: part.to_string(),
                final_: index + 1 == parts.len(),
            }));
        }
        content.components[0]["text"] = json!(rule.reply);
        let base = ramflux_protocol::surface_snapshot_hash(&content).map_err(|_| Error::Limit)?;
        content.fallback_text.clone_from(&rule.reply);
        intents.push(Intent::PatchSurface(PatchSurfaceCommand {
            surface_id: id.clone(),
            base_surface_hash: base,
            ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: rule.reply.clone() }],
            new_surface_hash: ramflux_protocol::surface_snapshot_hash(&content)
                .map_err(|_| Error::Limit)?,
        }));
        if surface.choices.is_empty() {
            intents
                .push(Intent::CloseSurface(DeleteSurfaceCommand { surface_id: id, reason: None }));
        }
        Ok(intents)
    }
    fn action(&mut self, input: &ActionInput<'_>) -> Result<Vec<Intent>> {
        if input.closed
            || input.snapshot.catalog != "basic"
            || input.snapshot.data_model.get("agent_host").and_then(serde_json::Value::as_str)
                != Some("ramflux.agent.rule.v1")
        {
            return Ok(Vec::new());
        }
        let Some(rule) = self.rules.iter().find(|rule| {
            input.snapshot.data_model.get("rule").and_then(serde_json::Value::as_str)
                == Some(rule.pattern.as_str())
        }) else {
            return Ok(Vec::new());
        };
        let Some(surface) = &rule.surface else { return Ok(Vec::new()) };
        let Some(choice) =
            surface.choices.iter().find(|choice| choice.id == input.action.action_id())
        else {
            return Ok(Vec::new());
        };
        if !input.snapshot.allowed_actions.iter().any(|action| action["name"] == choice.id) {
            let expected = format!("You chose {}.", choice.label);
            if surface.close_on_action
                && input.snapshot.allowed_actions.is_empty()
                && input.snapshot.fallback_text == expected
                && input
                    .snapshot
                    .components
                    .iter()
                    .any(|block| block["id"] == "result" && block["text"] == expected)
            {
                return Ok(vec![Intent::CloseSurface(DeleteSurfaceCommand {
                    surface_id: input.snapshot.surface_id.clone(),
                    reason: None,
                })]);
            }
            return Ok(Vec::new());
        }
        let result = format!("You chose {}.", choice.label);
        let mut content = input.snapshot.clone();
        let base = ramflux_protocol::surface_snapshot_hash(&content).map_err(|_| Error::State)?;
        let component = json!({"id":"result","type":"Text","text":result});
        let block =
            content.components.iter_mut().find(|b| b["id"] == "result").ok_or(Error::State)?;
        *block = component.clone();
        content.fallback_text.clone_from(&result);
        content.allowed_actions.clear();
        let mut intents = vec![Intent::PatchSurface(PatchSurfaceCommand {
            surface_id: content.surface_id.clone(),
            base_surface_hash: base,
            ops: vec![
                SurfacePatchOp::ReplaceBlock { component },
                SurfacePatchOp::SetActions { actions: Vec::new() },
                SurfacePatchOp::SetFallbackText { fallback_text: result },
            ],
            new_surface_hash: ramflux_protocol::surface_snapshot_hash(&content)
                .map_err(|_| Error::State)?,
        })];
        if surface.close_on_action {
            intents.push(Intent::CloseSurface(DeleteSurfaceCommand {
                surface_id: content.surface_id,
                reason: None,
            }));
        }
        Ok(intents)
    }
}
pub(crate) fn chunks(text: &str, bytes: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut tail = text;
    while !tail.is_empty() {
        let mut end = tail.len().min(bytes.max(4));
        while !tail.is_char_boundary(end) {
            end -= 1;
        }
        parts.push(&tail[..end]);
        tail = &tail[end..];
    }
    parts
}
