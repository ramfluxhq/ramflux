// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message deletes (`message_delete_v1`): one message, a batch of messages, or the reply of one
//! run. A delete tombstones the content; the id stays. A deleted key replays `409 message_deleted`.
//!
//! Each call is a single request. A repeat of the same delete answers the same `200`.
//!
//! `message_forget_writes_v1` adds `"forget_writes": true` on the same three routes. The field is
//! never sent unless that token is advertised. Erase-for-everyone sends it by default when the
//! token is advertised.

use crate::capabilities::{Capabilities, MESSAGE_DELETE_V1, MESSAGE_FORGET_WRITES_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use crate::history::target_from_label;
use crate::message::Target;
use reqwest::Method;
use serde::{Deserialize, Deserializer};
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
    /// Present only when this delete asked to forget the partition's writes.
    pub forget: Option<ForgetReport>,
}

/// The answer of a reply delete: the assistant side of one run is gone; its input stays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyDeleted {
    pub run_id: String,
    /// Present only when this delete asked to forget the run's writes.
    pub forget: Option<ForgetReport>,
}

/// Whether the delete body carries `"forget_writes": true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgetWrites {
    /// Omit the field. The answer has no forget report.
    Plain,
    /// Send the field. Refused locally when `message_forget_writes_v1` is not advertised.
    Forget,
}

/// How many memories or documents a forget removed. `created` were inserted by the run family;
/// `touched` were only updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgetCounts {
    pub created: u64,
    pub touched: u64,
}

/// Memories and documents removed for one agent (or for the one run of a reply delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forgotten {
    pub memories: ForgetCounts,
    pub documents: ForgetCounts,
}

/// The forget half of a delete answer. `forgotten` is `None` and `pending` is true while a live
/// run's forget waits for the run to end. A repeat returns the counts recorded the first time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForgetReport {
    pub forgotten: Option<Forgotten>,
    pub writes_traceable: bool,
    pub pending: bool,
}

/// What erase-for-everyone tells its caller, besides the delete itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseNotice {
    /// The daemon does not advertise `message_forget_writes_v1`. The delete was plain.
    MemoryNotForgotten,
    /// `422 forget_family_too_large`. Nothing was forgotten; the same delete was retried plain.
    FamilyTooLarge,
}

impl EraseNotice {
    /// The sentence the caller shows the user.
    #[must_use]
    pub const fn user_text(self) -> &'static str {
        match self {
            Self::MemoryNotForgotten => "tool-written memory was not forgotten",
            Self::FamilyTooLarge => {
                "the run wrote too much to forget in one erase; the message was deleted and tool-written memory was not forgotten"
            }
        }
    }
}

/// Erase-for-everyone: the message is deleted for every agent it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraseForEveryone {
    pub deleted: MessageDeleted,
    /// Set when tool-written memory was not forgotten. `None` when a forget was asked and accepted.
    pub notice: Option<EraseNotice>,
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
struct WireCounts {
    created: i64,
    touched: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireForgotten {
    memories: WireCounts,
    documents: WireCounts,
}

/// Three wire states of `forgotten`: absent, JSON null (a live run), or counts.
#[derive(Default)]
enum WireForgetValue {
    #[default]
    Absent,
    Pending,
    Counts(WireForgotten),
}

fn wire_forget_value<'de, D>(deserializer: D) -> Result<WireForgetValue, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<WireForgotten>::deserialize(deserializer)? {
        None => Ok(WireForgetValue::Pending),
        Some(counts) => Ok(WireForgetValue::Counts(counts)),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAgentRuns {
    agent: String,
    runs: Vec<String>,
    #[serde(default, deserialize_with = "wire_forget_value")]
    forgotten: WireForgetValue,
    #[serde(default, deserialize_with = "present")]
    writes_traceable: Option<bool>,
    #[serde(default)]
    forget_pending: bool,
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
    #[serde(default, deserialize_with = "wire_forget_value")]
    forgotten: WireForgetValue,
    #[serde(default, deserialize_with = "present")]
    writes_traceable: Option<bool>,
    #[serde(default)]
    forget_pending: bool,
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

fn admit(caps: &Capabilities, forget: ForgetWrites) -> Result<(), PrxError> {
    require(caps, MESSAGE_DELETE_V1)?;
    if forget == ForgetWrites::Forget {
        require(caps, MESSAGE_FORGET_WRITES_V1)?;
    }
    Ok(())
}

fn counts(raw: &WireCounts) -> Result<ForgetCounts, PrxError> {
    let created = u64::try_from(raw.created).map_err(|_| protocol("forget count is negative"))?;
    let touched = u64::try_from(raw.touched).map_err(|_| protocol("forget count is negative"))?;
    Ok(ForgetCounts { created, touched })
}

fn forgotten_of(raw: &WireForgotten) -> Result<Forgotten, PrxError> {
    Ok(Forgotten { memories: counts(&raw.memories)?, documents: counts(&raw.documents)? })
}

/// `None` when the delete did not ask to forget. A present `forgotten` (including JSON null)
/// must come with `writes_traceable`. Null `forgotten` is the pending marker and nothing else.
fn forget_of(
    forgotten: WireForgetValue,
    writes_traceable: Option<bool>,
    pending: bool,
) -> Result<Option<ForgetReport>, PrxError> {
    match (forgotten, writes_traceable, pending) {
        (WireForgetValue::Absent, None, false) => Ok(None),
        (WireForgetValue::Counts(raw), Some(writes_traceable), false) => Ok(Some(ForgetReport {
            forgotten: Some(forgotten_of(&raw)?),
            writes_traceable,
            pending: false,
        })),
        (WireForgetValue::Pending, Some(writes_traceable), true) => {
            Ok(Some(ForgetReport { forgotten: None, writes_traceable, pending: true }))
        }
        _ => Err(protocol("forget fields do not match a counts answer or a pending answer")),
    }
}

fn decode_agent(row: WireAgentRuns) -> Result<AgentRuns, PrxError> {
    Ok(AgentRuns {
        agent: target_from_label(&row.agent)?,
        runs: row.runs,
        forget: forget_of(row.forgotten, row.writes_traceable, row.forget_pending)?,
    })
}

fn decode_deleted(wire: WireDeleted) -> Result<MessageDeleted, PrxError> {
    if wire.status != "deleted" {
        return Err(protocol("delete answer status is not deleted"));
    }
    let agents = wire.agents.into_iter().map(decode_agent).collect::<Result<Vec<_>, PrxError>>()?;
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
            let code = match error.code.as_str() {
                "message_unknown" => ApiCode::MessageUnknown,
                "forget_family_too_large" => ApiCode::ForgetFamilyTooLarge,
                _ => return Err(protocol("batch item error is not a delete refusal")),
            };
            Ok(BatchItem::Refused { message_id: item.message_id, code })
        }
        _ => Err(protocol("batch item is neither a deleted answer nor a refusal")),
    }
}

fn message_body(agent: Option<&Target>, forget: ForgetWrites) -> Value {
    let mut body = Map::new();
    if let Some(agent) = agent {
        body.insert("agent".to_owned(), json!(agent_label(agent)));
    }
    if forget == ForgetWrites::Forget {
        body.insert("forget_writes".to_owned(), json!(true));
    }
    Value::Object(body)
}

fn reply_body(forget: ForgetWrites) -> Option<Value> {
    match forget {
        ForgetWrites::Plain => None,
        ForgetWrites::Forget => Some(json!({ "forget_writes": true })),
    }
}

impl PrxClient {
    /// Deletes one message. `agent: None` deletes it for every agent it reached in this session;
    /// `Some` deletes it for that agent only. Needs `message_delete_v1`. `ForgetWrites::Forget`
    /// also needs `message_forget_writes_v1` and is not sent without it.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`message_unknown` 404 when this session has no record of the
    /// id for that agent, `field_invalid` 400, `session_unknown` 404, `forget_family_too_large`
    /// 422), or a transport or contract error.
    pub async fn delete_message(
        &self,
        caps: &Capabilities,
        session_id: &str,
        client_message_id: &str,
        agent: Option<&Target>,
        forget: ForgetWrites,
    ) -> Result<MessageDeleted, PrxError> {
        admit(caps, forget)?;
        let path = single_path(session_id, client_message_id)?;
        let body = message_body(agent, forget);
        let raw = self.transport.call(Method::POST, &path, None, Some(&body)).await?;
        decode_deleted(decode_ok(&raw.body)?)
    }

    /// Deletes the assistant side of one run (its reply, tool and working rows). A run still
    /// running is `409 run_active`. Needs `message_delete_v1`. `ForgetWrites::Forget` also needs
    /// `message_forget_writes_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`run_active` 409, `run_unknown` 404,
    /// `forget_family_too_large` 422), or a transport or contract error.
    pub async fn delete_reply(
        &self,
        caps: &Capabilities,
        session_id: &str,
        run_id: &str,
        forget: ForgetWrites,
    ) -> Result<ReplyDeleted, PrxError> {
        admit(caps, forget)?;
        let path = reply_path(session_id, run_id)?;
        let raw =
            self.transport.call(Method::POST, &path, None, reply_body(forget).as_ref()).await?;
        let wire: WireReplyDeleted = decode_ok(&raw.body)?;
        if wire.status != "deleted" || wire.run_id != run_id {
            return Err(protocol("reply delete answer does not name the run as deleted"));
        }
        Ok(ReplyDeleted {
            run_id: wire.run_id,
            forget: forget_of(wire.forgotten, wire.writes_traceable, wire.forget_pending)?,
        })
    }

    /// Deletes several messages in one request (1 to 100 ids; the daemon refuses others with
    /// `field_invalid`). The answer is not all-or-nothing: one item per id, in request order.
    /// Needs `message_delete_v1`. `ForgetWrites::Forget` also needs `message_forget_writes_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`field_invalid` 400 for an empty or oversize list), or a
    /// transport or contract error. An item count that differs from the request is a contract
    /// violation. A per-item `forget_family_too_large` is that item's refusal; nothing in that
    /// item was deleted.
    pub async fn delete_messages(
        &self,
        caps: &Capabilities,
        session_id: &str,
        client_message_ids: &[String],
        agent: Option<&Target>,
        forget: ForgetWrites,
    ) -> Result<Vec<BatchItem>, PrxError> {
        admit(caps, forget)?;
        let path = batch_path(session_id)?;
        let mut body = Map::new();
        body.insert("ids".to_owned(), json!(client_message_ids));
        if let Some(agent) = agent {
            body.insert("agent".to_owned(), json!(agent_label(agent)));
        }
        if forget == ForgetWrites::Forget {
            body.insert("forget_writes".to_owned(), json!(true));
        }
        let raw =
            self.transport.call(Method::POST, &path, None, Some(&Value::Object(body))).await?;
        let wire: WireBatch = decode_ok(&raw.body)?;
        if wire.results.len() != client_message_ids.len() {
            return Err(protocol("batch delete answer does not match the request"));
        }
        wire.results.into_iter().map(decode_batch_item).collect()
    }

    /// Erase-for-everyone. When `message_forget_writes_v1` is advertised, the delete sends
    /// `forget_writes: true`. Without the token the delete is plain and [`EraseNotice`] tells
    /// the caller that tool-written memory was not forgotten. `422 forget_family_too_large`
    /// deletes nothing; the caller is told, and the same delete is retried once without the field.
    ///
    /// # Errors
    /// Returns `Unsupported`, the delete's `Api` error (other than the one family-too-large
    /// answer, which is retried), or a transport or contract error. A failed plain retry is
    /// returned as that error; the notice is not attached to a failed delete.
    pub async fn erase_for_everyone(
        &self,
        caps: &Capabilities,
        session_id: &str,
        client_message_id: &str,
    ) -> Result<EraseForEveryone, PrxError> {
        let forget = if caps.has(MESSAGE_FORGET_WRITES_V1) {
            ForgetWrites::Forget
        } else {
            ForgetWrites::Plain
        };
        match self.delete_message(caps, session_id, client_message_id, None, forget).await {
            Ok(deleted) => Ok(finished(deleted, forget)),
            Err(PrxError::Api { status: 422, code: ApiCode::ForgetFamilyTooLarge, .. })
                if forget == ForgetWrites::Forget =>
            {
                let deleted = self
                    .delete_message(caps, session_id, client_message_id, None, ForgetWrites::Plain)
                    .await?;
                Ok(EraseForEveryone { deleted, notice: Some(EraseNotice::FamilyTooLarge) })
            }
            Err(error) => Err(error),
        }
    }
}

fn finished(deleted: MessageDeleted, forget: ForgetWrites) -> EraseForEveryone {
    let notice = match forget {
        ForgetWrites::Plain => Some(EraseNotice::MemoryNotForgotten),
        ForgetWrites::Forget => None,
    };
    EraseForEveryone { deleted, notice }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    const COUNTS: &str = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":["run-1"],"forgotten":{"memories":{"created":1,"touched":2},"documents":{"created":3,"touched":4}},"writes_traceable":true}]}"#;

    fn deleted(body: &str) -> Result<MessageDeleted, PrxError> {
        decode_deleted(decode_ok(body.as_bytes()).expect("test: body decodes"))
    }

    #[test]
    fn plain_delete_has_no_forget_report() {
        let body =
            r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":[]}]}"#;
        let row = deleted(body).expect("test: plain delete decodes");
        assert!(row.agents[0].forget.is_none(), "a plain answer carries no forget report");
    }

    #[test]
    fn forget_counts_decode() {
        let row = deleted(COUNTS).expect("test: counts decode");
        let report = row.agents[0].forget.expect("test: forget report");
        assert!(!report.pending, "a counts answer is not pending");
        assert!(report.writes_traceable, "writes_traceable is kept");
        let forgotten = report.forgotten.expect("test: counts");
        assert_eq!(forgotten.memories, ForgetCounts { created: 1, touched: 2 });
        assert_eq!(forgotten.documents, ForgetCounts { created: 3, touched: 4 });
    }

    #[test]
    fn pending_forget_is_null_with_the_marker() {
        let body = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":["run-1"],"forgotten":null,"writes_traceable":true,"forget_pending":true}]}"#;
        let row = deleted(body).expect("test: pending decodes");
        let report = row.agents[0].forget.expect("test: pending report");
        assert!(report.pending && report.forgotten.is_none(), "pending is null forgotten");
    }

    #[test]
    fn forgotten_without_writes_traceable_is_refused() {
        let body = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":[],"forgotten":{"memories":{"created":0,"touched":0},"documents":{"created":0,"touched":0}}}]}"#;
        assert!(
            matches!(deleted(body), Err(PrxError::Protocol { .. })),
            "writes_traceable is required"
        );
    }

    #[test]
    fn null_forgotten_without_the_pending_marker_is_refused() {
        let body = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":[],"forgotten":null,"writes_traceable":true}]}"#;
        assert!(
            matches!(deleted(body), Err(PrxError::Protocol { .. })),
            "null forgotten needs the marker"
        );
    }

    #[test]
    fn pending_marker_with_counts_is_refused() {
        let body = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":[],"forgotten":{"memories":{"created":0,"touched":0},"documents":{"created":0,"touched":0}},"writes_traceable":false,"forget_pending":true}]}"#;
        assert!(
            matches!(deleted(body), Err(PrxError::Protocol { .. })),
            "counts and pending cannot combine"
        );
    }

    #[test]
    fn a_negative_forget_count_is_refused() {
        let body = r#"{"message_id":"rf-1","status":"deleted","agents":[{"agent":"main","runs":[],"forgotten":{"memories":{"created":-1,"touched":0},"documents":{"created":0,"touched":0}},"writes_traceable":true}]}"#;
        assert!(
            matches!(deleted(body), Err(PrxError::Protocol { .. })),
            "a negative count is not a count"
        );
    }

    #[tokio::test]
    async fn forget_without_the_token_sends_nothing() {
        let (_dir, client) = offline_client();
        let caps = caps_with(&[MESSAGE_DELETE_V1]);
        let result = client
            .delete_message(&caps, "rf-session", "rf-msg-1", None, ForgetWrites::Forget)
            .await;
        assert!(
            matches!(result, Err(PrxError::Unsupported { ref token, .. }) if token == MESSAGE_FORGET_WRITES_V1),
            "the field must not be sent without the token, got {result:?}"
        );
    }
}
