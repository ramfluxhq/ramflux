// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed rule planning and detached-provider events with human approval metadata.
use crate::{Config, Error, Result, Rule};
use ramflux_protocol::{
    AppendText, CATALOG_ID, DeleteSurface, EVENT_SCHEMA, EventFrame, Mutation, MutationMessage,
    SurfaceAction, SurfaceSnapshot, SurfaceState,
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
    pub action: &'a SurfaceAction,
    pub snapshot: &'a SurfaceSnapshot,
    pub closed: bool,
}
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Intent {
    ReplyText(String),
    CreateSurface(SurfaceSnapshot),
    AppendText(AppendText),
    ReplaceSurface(SurfaceSnapshot),
    CloseSurface(DeleteSurface),
}
impl Intent {
    pub(crate) fn surface_id(&self) -> Option<&str> {
        Some(match self {
            Self::ReplyText(_) => return None,
            Self::CreateSurface(s) | Self::ReplaceSurface(s) => &s.surface_id,
            Self::AppendText(a) => &a.surface_id,
            Self::CloseSurface(c) => &c.surface_id,
        })
    }
    pub(crate) fn frame(&self, conversation: &str, state: &SurfaceState) -> Result<EventFrame> {
        if let Self::ReplaceSurface(snapshot) = self {
            let mut frame = state.resync_frame().map_err(|_| Error::State)?;
            frame.surface_version = state.version().checked_add(1).ok_or(Error::Limit)?;
            frame.new_surface_hash = snapshot.hash().map_err(|_| Error::Limit)?;
            frame.fallback_text = Some(snapshot.fallback_text.clone());
            frame.final_ = Some(snapshot.final_.clone());
            frame.closed = Some(snapshot.closed);
            frame.metadata = snapshot.metadata.clone();
            frame.resync = Some(ramflux_protocol::Resync {
                a2ui: MutationMessage::new(Mutation::CreateSurface(snapshot.create())),
            });
            return Ok(frame);
        }
        let mut frame = EventFrame {
            schema: EVENT_SCHEMA.into(),
            conversation_id: conversation.into(),
            surface_version: state.version().checked_add(1).ok_or(Error::Limit)?,
            base_surface_hash: state.hash().map(str::to_owned),
            new_surface_hash: String::new(),
            fallback_text: None,
            close_reason: None,
            a2ui: None,
            append_text: None,
            resync: None,
            final_: None,
            closed: None,
            metadata: None,
        };
        match self {
            Self::CreateSurface(s) => {
                frame.a2ui = Some(MutationMessage::new(Mutation::CreateSurface(s.create())));
                frame.fallback_text = Some(s.fallback_text.clone());
            }
            Self::AppendText(a) => frame.append_text = Some(a.clone()),
            Self::CloseSurface(c) => {
                frame.a2ui = Some(MutationMessage::new(Mutation::DeleteSurface(c.clone())))
            }
            Self::ReplyText(_) | Self::ReplaceSurface(_) => return Err(Error::State),
        }
        state.prepare_event(frame).map_err(|_| Error::State)
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
        let random = ramflux_sdk::new_surface_message_id().map_err(|_| Error::State)?;
        let suffix: String = random.bytes().map(|b| format!("{b:02x}")).collect();
        let id = format!("agent_{suffix}");
        let mut components = vec![
            json!({"id":"root","component":"Column","children":["reply","result"]}),
            json!({"id":"reply","component":"Text","text":{"@path":"/reply"}}),
            json!({"id":"result","component":"Text","text":{"@path":"/result"}}),
        ];
        let mut children = vec![json!("reply"), json!("result")];
        for (index, choice) in surface.choices.iter().enumerate() {
            let button = format!("choice{index}");
            let label = format!("label{index}");
            children.push(json!(button));
            components.push(json!({"id":button,"component":"Button","child":label,"action":{"event":{"name":choice.id,"context":{"decision":choice.id}}}}));
            components.push(json!({"id":label,"component":"Text","text":choice.label}));
        }
        if let Some(root) = components.first_mut() {
            root["children"] = json!(children);
        }
        let content = SurfaceSnapshot {
            surface_id: id.clone(),
            catalog_id: CATALOG_ID.into(),
            fallback_text: rule.reply.clone(),
            metadata: None,
            components,
            data_model: json!({"reply":"","result":"","rule":rule.pattern,"agent_host":"ramflux.agent.rule.v1"}),
            final_: Vec::new(),
            closed: false,
        };
        let mut intents = vec![Intent::CreateSurface(content)];
        let mut parts = chunks(&rule.reply, surface.chunk_bytes);
        if parts.is_empty() {
            parts.push("");
        }
        for (index, part) in parts.iter().enumerate() {
            intents.push(Intent::AppendText(AppendText {
                surface_id: id.clone(),
                path: "/reply".into(),
                delta: (*part).into(),
                final_: index + 1 == parts.len(),
            }));
        }
        if surface.choices.is_empty() {
            intents.push(Intent::CloseSurface(DeleteSurface { surface_id: id }));
        }
        Ok(intents)
    }
    fn action(&mut self, input: &ActionInput<'_>) -> Result<Vec<Intent>> {
        if input.closed
            || input.snapshot.catalog_id != CATALOG_ID
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
        let Some(surface) = &rule.surface else {
            return Ok(Vec::new());
        };
        let Some(choice) =
            surface.choices.iter().find(|choice| choice.id == input.action.action_id())
        else {
            return Ok(Vec::new());
        };
        let result = format!("You chose {}.", choice.label);
        let mut snapshot = input.snapshot.clone();
        let root = snapshot
            .components
            .iter_mut()
            .find(|c| c.get("id").and_then(serde_json::Value::as_str) == Some("root"))
            .ok_or(Error::State)?;
        if let Some(map) = root.as_object_mut() {
            map.insert("children".into(), json!(["reply", "result"]));
        }
        snapshot.components.retain(|c| {
            matches!(
                c.get("id").and_then(serde_json::Value::as_str),
                Some("root" | "reply" | "result")
            )
        });
        let model = snapshot.data_model.as_object_mut().ok_or(Error::State)?;
        model.insert("result".into(), json!(result));
        snapshot.fallback_text = result;
        let mut intents = vec![Intent::ReplaceSurface(snapshot)];
        if surface.close_on_action {
            intents.push(Intent::CloseSurface(DeleteSurface {
                surface_id: input.snapshot.surface_id.clone(),
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
