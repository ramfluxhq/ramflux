// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed rule planning and detached-provider events with human approval metadata.
use crate::{Config, Error, Result, Rule};
use ramflux_protocol::{
    A2uiConversationCommand as Command, A2uiSurfaceAction, CreateSurfaceCommand,
    DeleteSurfaceCommand, PatchSurfaceCommand, StreamAppendCommand, SurfacePatchOp, SurfaceType,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::future::Future;

#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Bounded failure classes safe to persist and show without provider diagnostics.
pub enum EngineFailure {
    #[default]
    Rejected,
    Busy,
    RequestTimeout,
    TurnTimeout,
    ApprovalUnavailable,
    ApprovalTimeout,
    ApprovalDeclined,
    AuthorizationMismatch,
}
impl EngineFailure {
    /// Short visible status with a stable failure code and no remote response text.
    #[must_use]
    pub const fn reply(&self) -> &'static str {
        match self {
            Self::Rejected => "The agent engine could not complete this request. [engine_rejected]",
            Self::Busy => "The agent is waiting for the current turn or approval. [engine_busy]",
            Self::RequestTimeout => "The engine request timed out. [engine_request_timeout]",
            Self::TurnTimeout => "The agent turn timed out. [engine_turn_timeout]",
            Self::ApprovalUnavailable => {
                "The approval is expired or unavailable. [approval_unavailable]"
            }
            Self::ApprovalTimeout => "The approval request timed out. [approval_timeout]",
            Self::ApprovalDeclined => "The requested operation was declined. [approval_declined]",
            Self::AuthorizationMismatch => {
                "PRX requested approval in full authorization mode. [authorization_mismatch]"
            }
        }
    }
}

/// Authoritative, redacted PRX decision metadata bound into the human grant.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineApproval {
    pub tool: String,
    pub arguments_summary: serde_json::Value,
    pub effect: String,
    pub call_digest: String,
    pub deadline_ms: u64,
}

pub struct ConversationInput<'a> {
    pub conversation_id: &'a str,
    pub message_id: &'a str,
    pub text: &'a str,
}
pub struct EngineInput<'a> {
    pub conversation: ConversationInput<'a>,
    pub sender_display_name: &'a str,
    pub chat_kind: &'a str,
    pub mentioned: bool,
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
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineEvent {
    Intents {
        conversation_id: String,
        message_id: String,
        intents: Vec<Intent>,
    },
    ApprovalRequired {
        conversation_id: String,
        message_id: String,
        decision_id: String,
        approval: EngineApproval,
    },
    VisibleFailure {
        conversation_id: String,
        message_id: String,
        reason: EngineFailure,
    },
}
pub trait EngineProvider {
    /// Whether a conversation has provider work that needs a busy hint rather than a new turn.
    #[must_use]
    fn is_busy(&self, _conversation_id: &str) -> bool {
        false
    }
    /// # Errors
    /// Reports provider failures without exposing input text.
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>>;
    /// Submit one accepted inbound message without waiting for a remote model turn.
    ///
    /// # Errors
    /// Rejects invalid provider state or exhausted bounds.
    fn submit<'a>(
        &'a mut self,
        input: EngineInput<'a>,
        _now_ms: u64,
    ) -> impl Future<Output = Result<Vec<EngineEvent>>> + 'a {
        async move {
            let conversation_id = input.conversation.conversation_id.to_owned();
            let message_id = input.conversation.message_id.to_owned();
            let intents = self.intents(&input.conversation)?;
            Ok((!intents.is_empty())
                .then_some(EngineEvent::Intents { conversation_id, message_id, intents })
                .into_iter()
                .collect())
        }
    }
    /// Poll detached provider work.
    ///
    /// # Errors
    /// Rejects corrupt provider state or exhausted bounds.
    fn poll(&mut self, _now_ms: u64) -> impl Future<Output = Result<Vec<EngineEvent>>> {
        async { Ok(Vec::new()) }
    }
    /// Apply a human-authenticated approval decision.
    ///
    /// # Errors
    /// Rejects unknown or stale provider decisions.
    fn decide<'a>(
        &'a mut self,
        _conversation_id: &'a str,
        _message_id: &'a str,
        _decision_id: &'a str,
        _approved: bool,
        _now_ms: u64,
    ) -> impl Future<Output = Result<()>> + 'a {
        async { Err(Error::State) }
    }
    /// Cancel detached work after conversation access is removed.
    ///
    /// # Errors
    /// Reports only invalid local provider state; remote cancellation is best effort.
    fn cancel<'a>(
        &'a mut self,
        _conversation_id: &'a str,
    ) -> impl Future<Output = Result<()>> + 'a {
        async { Ok(()) }
    }
    /// Restore provider-owned durable state from the agent-host checkpoint.
    ///
    /// # Errors
    /// Rejects state belonging to another provider or invalid bounded data.
    fn restore(&mut self, state: Option<&serde_json::Value>) -> Result<()> {
        if state.is_some_and(|state| !state.is_null()) {
            return Err(Error::State);
        }
        Ok(())
    }
    /// Return provider state suitable for the token-free host checkpoint.
    ///
    /// # Errors
    /// Rejects state that cannot be serialized safely.
    fn checkpoint(&self) -> Result<Option<serde_json::Value>> {
        Ok(None)
    }
    /// Conversations with provider sessions or detached work that require revocation cleanup.
    #[must_use]
    fn active_conversations(&self) -> Vec<String> {
        Vec::new()
    }
    /// Retire one durably handled provider event.
    ///
    /// # Errors
    /// Rejects an acknowledgement that conflicts with provider state.
    fn acknowledge(&mut self, _event: &EngineEvent) -> Result<()> {
        Ok(())
    }
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
