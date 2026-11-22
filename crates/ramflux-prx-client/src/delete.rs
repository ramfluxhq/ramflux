// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message deletes (`message_delete_v1`): one message, a batch of messages, or the reply of one
//! run. A delete tombstones the content; the id stays. A deleted key replays `409 message_deleted`.
//!
//! Each call is a single request. A repeat of the same delete answers the same `200`.

use crate::capabilities::{Capabilities, MESSAGE_DELETE_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use crate::history::target_from_label;
use crate::message::Target;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// What one message delete removed: the runs of each agent partition the message reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeleted {
    pub message_id: String,
    pub agents: Vec<AgentRuns>,
}

/// One partition of a deleted message and the runs whose rows were deleted (empty for a
/// `context` message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRuns {
    pub agent: Target,
    pub runs: Vec<String>,
}

/// The answer of a reply delete: the assistant side of one run is gone; its input stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyDeleted {
    pub run_id: String,
}

/// One item of a batch delete, in request order: deleted, or refused with its code
/// (`message_unknown` for an id with no record in this session for this agent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchItem {
    Deleted(MessageDeleted),
    Refused { message_id: String, code: ApiCode },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAgentRuns {
    agent: String,
    runs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDeleted {
    message_id: String,
    status: String,
    agents: Vec<WireAgentRuns>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReplyDeleted {
    run_id: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireItemError {
    code: String,
    #[serde(rename = "message")]
    _message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBatchItem {
    message_id: String,
    #[serde(default, deserialize_with = "present")]
    status: Option<String>,
    #[serde(default, deserialize_with = "present")]
    agents: Option<Vec<WireAgentRuns>>,
    #[serde(default, deserialize_with = "present")]
    error: Option<WireItemError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBatch {
    results: Vec<WireBatchItem>,
}

/// A message id is PRX's `client_message_id` grammar: `[A-Za-z0-9_.:-]`, 1 to 128 characters.
fn message_id_is_safe(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

fn session_safe(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn run_id_safe(run_id: &str) -> bool {
    !run_id.is_empty() && run_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn single_path(session_id: &str, message_id: &str) -> Result<String, PrxError> {
    if session_safe(session_id) && message_id_is_safe(message_id) {
        Ok(format!("/api/sessions/{session_id}/messages/{message_id}/delete"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

fn reply_path(session_id: &str, run_id: &str) -> Result<String, PrxError> {
    if session_safe(session_id) && run_id_safe(run_id) {
        Ok(format!("/api/sessions/{session_id}/runs/{run_id}/reply/delete"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

fn batch_path(session_id: &str) -> Result<String, PrxError> {
    if session_safe(session_id) {
        Ok(format!("/api/sessions/{session_id}/messages/delete"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

/// The `agent` member: omitted for "every agent"; otherwise the partition's label.
fn agent_label(agent: &Target) -> &str {
    match agent {
        Target::Main => "main",
        Target::Named(name) => name.as_str(),
    }
}

fn decode_deleted(wire: WireDeleted) -> Result<MessageDeleted, PrxError> {
    if wire.status != "deleted" {
        return Err(protocol("delete answer status is not deleted"));
    }
    let agents = wire
        .agents
        .into_iter()
        .map(|row| Ok(AgentRuns { agent: target_from_label(&row.agent)?, runs: row.runs }))
        .collect::<Result<Vec<_>, PrxError>>()?;
    Ok(MessageDeleted { message_id: wire.message_id, agents })
}

fn decode_batch_item(item: WireBatchItem) -> Result<BatchItem, PrxError> {
    match (item.status, item.agents, item.error) {
        (Some(status), Some(agents), None) => {
            let deleted =
                decode_deleted(WireDeleted { message_id: item.message_id, status, agents })?;
            Ok(BatchItem::Deleted(deleted))
        }
        (None, None, Some(error)) => {
            if error.code != "message_unknown" {
                return Err(protocol("batch item error is not message_unknown"));
            }
            Ok(BatchItem::Refused { message_id: item.message_id, code: ApiCode::MessageUnknown })
        }
        _ => Err(protocol("batch item is neither a deleted answer nor a refusal")),
    }
}

impl PrxClient {
    /// Deletes one message. `agent: None` deletes it for every agent it reached in this session;
    /// `Some` deletes it for that agent only. Needs `message_delete_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`message_unknown` 404 when this session has no record of the
    /// id for that agent, `field_invalid` 400, `session_unknown` 404), or a transport or contract
    /// error.
    pub async fn delete_message(
        &self,
        caps: &Capabilities,
        session_id: &str,
        client_message_id: &str,
        agent: Option<&Target>,
    ) -> Result<MessageDeleted, PrxError> {
        require(caps, MESSAGE_DELETE_V1)?;
        let path = single_path(session_id, client_message_id)?;
        let mut body = Map::new();
        if let Some(agent) = agent {
            body.insert("agent".to_owned(), json!(agent_label(agent)));
        }
        let raw =
            self.transport.call(Method::POST, &path, None, Some(&Value::Object(body))).await?;
        decode_deleted(decode_ok(&raw.body)?)
    }

    /// Deletes the assistant side of one run (its reply, tool and working rows). A run still
    /// running is `409 run_active`. Needs `message_delete_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`run_active` 409, `run_unknown` 404), or a transport or
    /// contract error.
    pub async fn delete_reply(
        &self,
        caps: &Capabilities,
        session_id: &str,
        run_id: &str,
    ) -> Result<ReplyDeleted, PrxError> {
        require(caps, MESSAGE_DELETE_V1)?;
        let path = reply_path(session_id, run_id)?;
        let raw = self.transport.call(Method::POST, &path, None, None).await?;
        let wire: WireReplyDeleted = decode_ok(&raw.body)?;
        if wire.status != "deleted" || wire.run_id != run_id {
            return Err(protocol("reply delete answer does not name the run as deleted"));
        }
        Ok(ReplyDeleted { run_id: wire.run_id })
    }

    /// Deletes several messages in one request (1 to 100 ids; the daemon refuses others with
    /// `field_invalid`). The answer is not all-or-nothing: one item per id, in request order.
    /// Needs `message_delete_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`field_invalid` 400 for an empty or oversize list), or a
    /// transport or contract error. An item count that differs from the request is a contract
    /// violation.
    pub async fn delete_messages(
        &self,
        caps: &Capabilities,
        session_id: &str,
        client_message_ids: &[String],
        agent: Option<&Target>,
    ) -> Result<Vec<BatchItem>, PrxError> {
        require(caps, MESSAGE_DELETE_V1)?;
        let path = batch_path(session_id)?;
        let mut body = Map::new();
        body.insert("ids".to_owned(), json!(client_message_ids));
        if let Some(agent) = agent {
            body.insert("agent".to_owned(), json!(agent_label(agent)));
        }
        let raw =
            self.transport.call(Method::POST, &path, None, Some(&Value::Object(body))).await?;
        let wire: WireBatch = decode_ok(&raw.body)?;
        if wire.results.len() != client_message_ids.len() {
            return Err(protocol("batch delete answer does not match the request"));
        }
        wire.results.into_iter().map(decode_batch_item).collect()
    }
}
