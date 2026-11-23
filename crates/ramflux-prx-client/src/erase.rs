// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! History erase (`history_erase_v1`): one agent's partition, or every agent that has a row in
//! a caller-keyed session plus Main. Each call checks its token before any request.

use crate::agent::check_uuid;
use crate::capabilities::{
    AGENT_CRUD_V1, AGENT_MAIN_READBACK_V1, Capabilities, HISTORY_ERASE_V1,
    MESSAGE_FORGET_WRITES_V1, TARGETED_AGENTS_V1, require,
};
use crate::client::PrxClient;
use crate::delete::ForgetWrites;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use crate::message::Target;
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

/// One history erase. `incarnation` is the agent's current incarnation (`If-Match`).
/// `idempotency_key` is 16..=128 printable ASCII bytes.
#[derive(Debug, Clone, Copy)]
pub struct EraseHistory<'a> {
    pub session_id: &'a str,
    pub agent: &'a Target,
    pub incarnation: &'a str,
    pub idempotency_key: &'a str,
    pub forget: ForgetWrites,
}

/// The scope a receipt certifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryScope {
    pub session: String,
    pub agent: String,
    pub incarnation: String,
}

/// Writes forgotten with the erase. Present only when `forget_writes` was sent.
/// `created` and `touched` sum memories and documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryForgotten {
    pub created: u64,
    pub touched: u64,
}

/// A successful erase. `remaining` is 0. `generation` starts at 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryErased {
    pub erase_id: String,
    pub generation: u64,
    pub remaining: u64,
    pub incarnation: String,
    pub scope: HistoryScope,
    pub forgotten: Option<HistoryForgotten>,
}

/// Refuses a key PRX would refuse with `idempotency_key_required`. Nothing is sent.
pub(crate) fn require_idempotency_key(raw: &str) -> Result<(), PrxError> {
    let ok =
        (16..=128).contains(&raw.len()) && raw.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if ok { Ok(()) } else { Err(local_refusal(ApiCode::IdempotencyKeyRequired)) }
}

fn require_prefix(raw: &str) -> Result<(), PrxError> {
    // `{prefix}:{label}` must stay within 128. A name is at most 64 bytes.
    let ok =
        (16..=62).contains(&raw.len()) && raw.bytes().all(|byte| (0x20..=0x7e).contains(&byte));
    if ok { Ok(()) } else { Err(local_refusal(ApiCode::IdempotencyKeyRequired)) }
}

fn agent_label(agent: &Target) -> &str {
    match agent {
        Target::Main => "main",
        Target::Named(name) => name.as_str(),
    }
}

fn history_path(session_id: &str, agent: &Target) -> Result<String, PrxError> {
    let safe = !session_id.is_empty()
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    if safe {
        Ok(format!("/api/sessions/{session_id}/agents/{}/history", agent_label(agent)))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScope {
    session: String,
    agent: String,
    incarnation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireForgotten {
    created: u64,
    touched: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReceipt {
    status: String,
    scope: WireScope,
    erase_id: String,
    generation: u64,
    remaining: u64,
    incarnation: String,
    #[serde(default, deserialize_with = "present")]
    forgotten: Option<WireForgotten>,
}

fn decode_receipt(body: &[u8], request: &EraseHistory<'_>) -> Result<HistoryErased, PrxError> {
    let wire: WireReceipt = decode_ok(body)?;
    let label = agent_label(request.agent);
    check_uuid(&wire.erase_id)?;
    check_uuid(&wire.incarnation)?;
    let scope_ok = wire.status == "erased"
        && wire.remaining == 0
        && wire.generation >= 1
        && wire.scope.session == request.session_id
        && wire.scope.agent == label
        && wire.scope.incarnation == request.incarnation
        && wire.incarnation == request.incarnation;
    if !scope_ok {
        return Err(protocol("history erase receipt does not match the request"));
    }
    let forgotten = match (request.forget, wire.forgotten) {
        (ForgetWrites::Forget, Some(counts)) => {
            Some(HistoryForgotten { created: counts.created, touched: counts.touched })
        }
        (ForgetWrites::Plain, None) => None,
        _ => return Err(protocol("history erase receipt forget shape does not match the request")),
    };
    Ok(HistoryErased {
        erase_id: wire.erase_id,
        generation: wire.generation,
        remaining: wire.remaining,
        incarnation: wire.incarnation,
        scope: HistoryScope {
            session: wire.scope.session,
            agent: wire.scope.agent,
            incarnation: wire.scope.incarnation,
        },
        forgotten,
    })
}

impl PrxClient {
    /// Erases one agent's history in a caller-keyed session. Needs `history_erase_v1`.
    /// `ForgetWrites::Forget` also needs `message_forget_writes_v1`. A missing token, a bad key,
    /// a bad session id or a bad incarnation sends nothing.
    ///
    /// # Errors
    /// Returns `Unsupported`, a local `idempotency_key_required` or `field_invalid`, or the API
    /// error (`incarnation_mismatch`, `history_pending`, `idempotency_conflict`, `agent_unknown`).
    pub async fn erase_agent_history(
        &self,
        caps: &Capabilities,
        request: &EraseHistory<'_>,
    ) -> Result<HistoryErased, PrxError> {
        require(caps, HISTORY_ERASE_V1)?;
        if request.forget == ForgetWrites::Forget {
            require(caps, MESSAGE_FORGET_WRITES_V1)?;
        }
        require_idempotency_key(request.idempotency_key)?;
        check_uuid(request.incarnation)?;
        let path = history_path(request.session_id, request.agent)?;
        let body = match request.forget {
            ForgetWrites::Forget => Some(json!({"forget_writes": true})),
            ForgetWrites::Plain => None,
        };
        let raw = self
            .transport
            .call_keyed(
                Method::DELETE,
                &path,
                Some(request.incarnation),
                Some(request.idempotency_key),
                body.as_ref(),
            )
            .await?;
        decode_receipt(&raw.body, request)
    }

    /// Erases Main and every agent that has a row in the session. Needs `history_erase_v1`,
    /// `targeted_agents_v1`, `agent_main_readback_v1` and `agent_crud_v1` before any request.
    /// `forget_writes` is sent only when `message_forget_writes_v1` is advertised.
    ///
    /// `idempotency_prefix` is 16..=62 printable ASCII bytes. Each agent uses
    /// `{prefix}:{label}`. Agents are erased one after another, Main first. If a later agent
    /// fails, earlier receipts are already stored by PRX and this call returns that error.
    ///
    /// # Errors
    /// Returns `Unsupported` before any request when a required token is missing, a local
    /// refusal for a bad prefix or session id, or the error of the read or of the erase that
    /// failed.
    pub async fn erase_session_history(
        &self,
        caps: &Capabilities,
        session_id: &str,
        idempotency_prefix: &str,
    ) -> Result<Vec<HistoryErased>, PrxError> {
        require(caps, HISTORY_ERASE_V1)?;
        require(caps, TARGETED_AGENTS_V1)?;
        require(caps, AGENT_MAIN_READBACK_V1)?;
        require(caps, AGENT_CRUD_V1)?;
        require_prefix(idempotency_prefix)?;
        let forget = if caps.has(MESSAGE_FORGET_WRITES_V1) {
            ForgetWrites::Forget
        } else {
            ForgetWrites::Plain
        };
        let rows = self.session_messages(caps, session_id, None).await?;
        let mut agents = BTreeSet::new();
        agents.insert(Target::Main);
        for row in rows {
            agents.insert(row.agent);
        }
        let mut erased = Vec::with_capacity(agents.len());
        for agent in &agents {
            erased.push(self.erase_one(caps, session_id, idempotency_prefix, agent, forget).await?);
        }
        Ok(erased)
    }

    async fn erase_one(
        &self,
        caps: &Capabilities,
        session_id: &str,
        prefix: &str,
        agent: &Target,
        forget: ForgetWrites,
    ) -> Result<HistoryErased, PrxError> {
        let incarnation = match agent {
            Target::Main => self.main(caps).await?.incarnation,
            Target::Named(name) => self.get(caps, name).await?.incarnation,
        };
        let key = format!("{prefix}:{}", agent_label(agent));
        require_idempotency_key(&key)?;
        self.erase_agent_history(
            caps,
            &EraseHistory {
                session_id,
                agent,
                incarnation: &incarnation,
                idempotency_key: &key,
                forget,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    const UUID: &str = "5f1c2a3e-8b4d-4c6a-9e7f-0a1b2c3d4e5f";

    fn request<'a>(agent: &'a Target, key: &'a str, forget: ForgetWrites) -> EraseHistory<'a> {
        EraseHistory {
            session_id: "rf-session-0001",
            agent,
            incarnation: UUID,
            idempotency_key: key,
            forget,
        }
    }

    #[tokio::test]
    async fn missing_token_or_bad_key_sends_nothing() {
        let (_dir, client) = offline_client();
        let main = Target::Main;
        let bare = caps_with(&[]);
        let missing = client
            .erase_agent_history(&bare, &request(&main, "unit-a-erase-key-01", ForgetWrites::Plain))
            .await;
        assert!(matches!(missing, Err(PrxError::Unsupported { .. })));
        let caps = caps_with(&[HISTORY_ERASE_V1]);
        let short = client
            .erase_agent_history(&caps, &request(&main, "too-short", ForgetWrites::Plain))
            .await;
        assert!(matches!(short, Err(PrxError::Api { code: ApiCode::IdempotencyKeyRequired, .. })));
        let forget = client
            .erase_agent_history(
                &caps,
                &request(&main, "unit-a-erase-key-01", ForgetWrites::Forget),
            )
            .await;
        assert!(matches!(
            &forget,
            Err(PrxError::Unsupported { token, .. }) if token == MESSAGE_FORGET_WRITES_V1
        ));
        let session =
            client.erase_session_history(&caps, "rf-session-0001", "unit-a-erase-key-01").await;
        assert!(matches!(session, Err(PrxError::Unsupported { .. })));
    }

    #[test]
    fn receipt_matches_the_request_and_refuses_a_wrong_forget_shape() {
        let main = Target::Main;
        let body = format!(
            r#"{{"status":"erased","scope":{{"session":"rf-session-0001","agent":"main","incarnation":"{UUID}"}},"erase_id":"{UUID}","generation":1,"remaining":0,"incarnation":"{UUID}","forgotten":{{"created":0,"touched":2}}}}"#
        );
        let decoded = decode_receipt(
            body.as_bytes(),
            &request(&main, "unit-a-erase-key-01", ForgetWrites::Forget),
        )
        .expect("test: documented receipt decodes");
        assert_eq!(decoded.remaining, 0);
        assert_eq!(decoded.forgotten, Some(HistoryForgotten { created: 0, touched: 2 }));
        let plain = decode_receipt(
            body.as_bytes(),
            &request(&main, "unit-a-erase-key-01", ForgetWrites::Plain),
        );
        assert!(matches!(plain, Err(PrxError::Protocol { .. })));
    }
}
