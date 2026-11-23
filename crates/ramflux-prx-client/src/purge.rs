// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent memory purge (`agent_memory_purge_v1`). Purge is never part of `DELETE`.
//! A purge of an agent that is still active is `409 agent_not_retired`.

use crate::agent::check_uuid;
use crate::capabilities::{AGENT_CRUD_V1, AGENT_MEMORY_PURGE_V1, Capabilities, require};
use crate::client::PrxClient;
use crate::erase::require_idempotency_key;
use crate::error::{PrxError, decode_ok, protocol};
use crate::name::AgentName;
use crate::revision::ConfigRevision;
use reqwest::Method;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Manifest stores a purge receipt must count. Extra keys are kept.
pub const PURGE_STORES: [&str; 40] = [
    "conversation_turns",
    "message_events",
    "memories",
    "documents",
    "document_chunks",
    "embedding_cache",
    "memory_events",
    "memory_drafts",
    "memory_trash",
    "memory_links",
    "retrieval_traces",
    "compaction_runs",
    "topics",
    "topic_participants",
    "topic_aliases",
    "router_history_v1",
    "router_learning_state",
    "router_learning_receipts",
    "chat_profiles",
    "chat_sessions",
    "chat_assignments",
    "chat_results",
    "engine_outcomes",
    "access_audit_log",
    "approval_grants",
    "approval_grant_events",
    "approval_grant_revocations",
    "ingress_recovery",
    "recovery_attestations",
    "ramflux_blobs",
    "prx_mailbox_messages",
    "prx_mailbox_receipts",
    "prx_mailbox_outbox",
    "prx_mailbox_parents",
    "prx_mailbox_seq",
    "child_sessions",
    "engine_analyses",
    "memory_write_log",
    "rf_message_attempts",
    "prx_remote_trees",
];

/// The permanent purge receipt. `completed_at` is `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReceipt {
    pub name: AgentName,
    pub incarnations: Vec<String>,
    pub counts: BTreeMap<String, u64>,
    pub completed_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReceipt {
    name: String,
    incarnations: Vec<String>,
    counts: BTreeMap<String, u64>,
    completed_at: String,
}

fn completed_at_ok(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    let is = |index: usize, expected: u8| bytes.get(index) == Some(&expected);
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    is(4, b'-')
        && is(7, b'-')
        && is(10, b'T')
        && is(13, b':')
        && is(16, b':')
        && is(19, b'Z')
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18].into_iter().all(digit)
}

fn decode_receipt(body: &[u8], expected: &AgentName) -> Result<PurgeReceipt, PrxError> {
    let wire: WireReceipt = decode_ok(body)?;
    if wire.name != expected.as_str() || wire.incarnations.is_empty() {
        return Err(protocol("purge receipt does not name this agent's incarnations"));
    }
    for incarnation in &wire.incarnations {
        check_uuid(incarnation)?;
    }
    if !completed_at_ok(&wire.completed_at) {
        return Err(protocol("purge completed_at is not UTC second precision"));
    }
    if PURGE_STORES.iter().any(|store| !wire.counts.contains_key(*store)) {
        return Err(protocol("purge receipt is missing a manifest store"));
    }
    let name = AgentName::parse(&wire.name)
        .map_err(|_| protocol("purge receipt name is not an agent name"))?;
    Ok(PurgeReceipt {
        name,
        incarnations: wire.incarnations,
        counts: wire.counts,
        completed_at: wire.completed_at,
    })
}

impl PrxClient {
    /// Purges a retired named agent. Needs `agent_memory_purge_v1`. Sends no body.
    /// `revision` is the config revision (`If-Match`). An active agent is
    /// `409 agent_not_retired` and nothing is purged.
    ///
    /// # Errors
    /// Returns `Unsupported` or a local `idempotency_key_required` before any request, or the
    /// API error (`agent_not_retired`, `revision_conflict`, `purge_pending`, `agent_unknown`).
    pub async fn purge(
        &self,
        caps: &Capabilities,
        name: &AgentName,
        revision: &ConfigRevision,
        idempotency_key: &str,
    ) -> Result<PurgeReceipt, PrxError> {
        require(caps, AGENT_MEMORY_PURGE_V1)?;
        require_idempotency_key(idempotency_key)?;
        let path = format!("/api/agents/{}/purge", name.as_str());
        let raw = self
            .transport
            .call_keyed(Method::POST, &path, Some(revision.as_str()), Some(idempotency_key), None)
            .await?;
        decode_receipt(&raw.body, name)
    }

    /// Retires the agent, then purges it, and returns the permanent receipt.
    /// Both `agent_crud_v1` and `agent_memory_purge_v1` are required before `DELETE`.
    /// A bad idempotency key also sends nothing, so a refused key does not retire the agent.
    ///
    /// If retire succeeds and purge fails, the agent is already retired. Retry `purge` with the
    /// revision `retire` returned and the same key. PRX stores the receipt permanently; a later
    /// key returns that receipt.
    ///
    /// # Errors
    /// Returns `Unsupported` or a local key refusal before retire, or the error of retire or purge.
    pub async fn retire_and_purge(
        &self,
        caps: &Capabilities,
        name: &AgentName,
        revision: &ConfigRevision,
        idempotency_key: &str,
    ) -> Result<PurgeReceipt, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        require(caps, AGENT_MEMORY_PURGE_V1)?;
        require_idempotency_key(idempotency_key)?;
        let retired = self.retire(caps, name, revision).await?;
        self.purge(caps, name, &retired.revision, idempotency_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ApiCode;
    use crate::test_support::{caps_with, offline_client};

    #[tokio::test]
    async fn missing_token_or_bad_key_does_not_retire() {
        let (_dir, client) = offline_client();
        let name = AgentName::parse("worker").expect("test: name");
        let revision = ConfigRevision::parse(
            "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
        )
        .expect("test: revision");
        let bare = caps_with(&[AGENT_CRUD_V1]);
        let missing =
            client.retire_and_purge(&bare, &name, &revision, "unit-a-purge-key-0001").await;
        assert!(matches!(
            &missing,
            Err(PrxError::Unsupported { token, .. }) if token == AGENT_MEMORY_PURGE_V1
        ));
        let caps = caps_with(&[AGENT_CRUD_V1, AGENT_MEMORY_PURGE_V1]);
        let short = client.purge(&caps, &name, &revision, "short").await;
        assert!(matches!(short, Err(PrxError::Api { code: ApiCode::IdempotencyKeyRequired, .. })));
    }

    #[test]
    fn receipt_requires_every_store_and_keeps_extras() {
        let name = AgentName::parse("worker").expect("test: name");
        let uuid = "5f1c2a3e-8b4d-4c6a-9e7f-0a1b2c3d4e5f";
        let mut counts = serde_json::Map::new();
        for store in PURGE_STORES {
            counts.insert((*store).to_owned(), serde_json::json!(0));
        }
        counts.insert("ramflux_erase_index".to_owned(), serde_json::json!(3));
        let body = serde_json::json!({
            "name": "worker",
            "incarnations": [uuid],
            "counts": counts,
            "completed_at": "2026-11-23T00:00:00Z",
        });
        let bytes = serde_json::to_vec(&body).expect("test: encode");
        let receipt = decode_receipt(&bytes, &name).expect("test: receipt decodes");
        assert_eq!(receipt.counts.get("ramflux_erase_index"), Some(&3));
        assert_eq!(receipt.incarnations, vec![uuid.to_owned()]);
        let bad_time =
            body.to_string().replace("2026-11-23T00:00:00Z", "2026-11-23T00:00:00+00:00");
        assert!(matches!(
            decode_receipt(bad_time.as_bytes(), &name),
            Err(PrxError::Protocol { .. })
        ));
    }
}
