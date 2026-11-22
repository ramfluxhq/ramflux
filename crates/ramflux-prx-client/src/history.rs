// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `GET /api/sessions/{session_id}/messages` on a caller-keyed session: the history with the
//! agent that owns each row (`targeted_agents_v1`). Each row belongs to exactly one partition:
//! Main or one named agent. `agent` filters to one partition; a configured agent with no row
//! yet gives an empty list, and an unknown name is `404 agent_unknown`.

use crate::capabilities::{Capabilities, TARGETED_AGENTS_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, protocol};
use crate::message::Target;
use crate::name::AgentName;
use reqwest::Method;
use serde::Deserialize;

/// The wire label of Main.
const MAIN_LABEL: &str = "main";

/// One history row. `agent` is always present on a caller-keyed session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRow {
    pub message_id: Option<String>,
    pub agent: Target,
    pub timestamp: String,
    pub body: RowBody,
}

/// What a row holds: its text, or a tombstone once the message was deleted (`message_delete_v1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowBody {
    Text { role: String, content: String },
    Deleted,
}

impl HistoryRow {
    /// The row's text, or `None` for a deleted tombstone.
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        match &self.body {
            RowBody::Text { content, .. } => Some(content),
            RowBody::Deleted => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRow {
    #[serde(default, deserialize_with = "crate::error::present")]
    role: Option<String>,
    #[serde(default, deserialize_with = "crate::error::present")]
    content: Option<String>,
    timestamp: String,
    #[serde(default, deserialize_with = "crate::error::present")]
    message_id: Option<String>,
    #[serde(default, deserialize_with = "crate::error::present")]
    agent: Option<String>,
    #[serde(default, deserialize_with = "crate::error::present")]
    deleted: Option<bool>,
}

/// The label of a row's agent: `main` for Main, otherwise a name that passes the name grammar.
pub(crate) fn target_from_label(label: &str) -> Result<Target, PrxError> {
    if label == MAIN_LABEL {
        Ok(Target::Main)
    } else {
        AgentName::parse(label).map(Target::Named).map_err(|_| protocol("row agent is not a name"))
    }
}

fn session_path(session_id: &str) -> Result<String, PrxError> {
    let safe = !session_id.is_empty()
        && session_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if safe {
        Ok(format!("/api/sessions/{session_id}/messages"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

/// A live row carries `role` and `content`; a tombstone carries exactly `deleted: true`, with
/// neither. Anything else is refused.
fn decode_row(row: WireRow) -> Result<HistoryRow, PrxError> {
    let label = row.agent.ok_or(protocol("caller-keyed session row carries no agent"))?;
    let body = match (row.deleted, row.role, row.content) {
        (Some(true), None, None) => RowBody::Deleted,
        (None, Some(role), Some(content)) => RowBody::Text { role, content },
        _ => return Err(protocol("row is neither a live row nor an exact tombstone")),
    };
    Ok(HistoryRow {
        message_id: row.message_id,
        agent: target_from_label(&label)?,
        timestamp: row.timestamp,
        body,
    })
}

impl PrxClient {
    /// Reads a caller-keyed session's history. `agent: None` returns every row with its label;
    /// `Some(target)` returns only that partition's rows. Needs `targeted_agents_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (`session_unknown` 404 for a session of another owner or a
    /// missing key, `agent_unknown` 404 for a filter name that is not configured), or a
    /// transport or contract error. A row without its `agent` label is a contract violation.
    pub async fn session_messages(
        &self,
        caps: &Capabilities,
        session_id: &str,
        agent: Option<&Target>,
    ) -> Result<Vec<HistoryRow>, PrxError> {
        require(caps, TARGETED_AGENTS_V1)?;
        let mut path = session_path(session_id)?;
        match agent {
            None => {}
            Some(Target::Main) => path.push_str("?agent=main"),
            Some(Target::Named(name)) => {
                path.push_str("?agent=");
                path.push_str(name.as_str());
            }
        }
        let raw = self.transport.call(Method::GET, &path, None, None).await?;
        let wire: Vec<WireRow> = decode_ok(&raw.body)?;
        wire.into_iter().map(decode_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    #[test]
    fn labels_map_to_partitions() {
        assert_eq!(target_from_label("main"), Ok(Target::Main));
        assert_eq!(
            target_from_label("worker-1"),
            Ok(Target::Named(AgentName::parse("worker-1").expect("test: name")))
        );
        assert!(target_from_label("main ").is_err());
    }

    #[test]
    fn row_without_agent_label_is_refused() {
        let row: WireRow =
            decode_ok(br#"{"role":"user","content":"x","timestamp":"t","message_id":"m"}"#)
                .expect("test: row decodes");
        assert!(decode_row(row).is_err(), "a caller-keyed row must carry agent");
    }

    #[test]
    fn row_shape_is_strict() {
        let extra = decode_ok::<WireRow>(
            br#"{"role":"user","content":"x","timestamp":"t","agent":"main","x":1}"#,
        );
        assert!(extra.is_err(), "unknown field refused");
        let null_id = decode_ok::<WireRow>(
            br#"{"role":"user","content":"x","timestamp":"t","agent":"main","message_id":null}"#,
        );
        assert!(null_id.is_err(), "explicit null message_id refused");
    }

    #[test]
    fn session_path_admits_only_the_key_grammar() {
        assert!(session_path("rf-s_1").is_ok());
        assert!(session_path("a/b").is_err());
        assert!(session_path("").is_err());
    }

    #[test]
    fn read_without_the_token_is_refused_before_any_request() {
        let (_dir, client) = offline_client();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test: runtime");
        let caps = caps_with(&[]);
        assert!(matches!(
            runtime.block_on(client.session_messages(&caps, "rf-s-1", None)),
            Err(PrxError::Unsupported { .. })
        ));
    }
}
