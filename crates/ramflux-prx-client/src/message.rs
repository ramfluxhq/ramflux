// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `POST /api/sessions/{session_id}/message` for rf messages: a `turn` (starts a run) or a
//! `context` (records the input, starts nothing). Needs `message_target_v1` and
//! `message_context_delivery_v1`.
//!
//! The client sends each post exactly once and never retries it. A post whose answer is lost,
//! or whose storage outcome PRX reports as unknown, comes back as `PrxError::OutcomeUnknown`;
//! the caller decides what to do next. PRX does not deduplicate yet (`message_idempotency_v1`
//! is not advertised at this pin), so a deliberate resend would run again.
//!
//! Field bounds (ids, message size, names, mentions) are PRX's to enforce: the client sends what
//! the caller gives and the daemon's `400 field_invalid` is what a caller sees.

use crate::capabilities::{Capabilities, MESSAGE_CONTEXT_DELIVERY_V1, MESSAGE_TARGET_V1, require};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_api_error, decode_ok, local_refusal, rate_limited};
use crate::name::AgentName;
use crate::transport::Raw;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Who answers the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Main. Sent as an omitted `agent`; `"main"` is the same key on PRX's side.
    Main,
    /// A configured named agent.
    Named(AgentName),
}

/// Kind of chat the input comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatKind {
    Dm,
    Group,
}

/// The chat of the input (`chat` in the rf body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    pub id: String,
    pub kind: ChatKind,
    pub title: Option<String>,
    pub member_count: u32,
}

/// The sender of the input (`sender` in the rf body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sender {
    pub principal_id: String,
    pub display: String,
}

/// One rf message body. Every field the token document lists is typed; nothing else is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfMessage {
    /// The rf message id. PRX validates the grammar and uses it in the caller-context block.
    pub client_message_id: String,
    pub target: Target,
    pub message: String,
    pub chat: Chat,
    pub sender: Sender,
    pub mentions: Vec<String>,
    pub reply_to: Option<String>,
}

/// `202 {"run_id","job_id"}`: a turn was admitted and runs as a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnAccepted {
    pub run_id: String,
    pub job_id: String,
}

/// `200 {"message_id","status":"recorded"}`: a context input was stored; no run started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRecorded {
    pub message_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTurn {
    run_id: String,
    job_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContext {
    message_id: String,
    status: String,
}

impl ChatKind {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Group => "group",
        }
    }
}

impl RfMessage {
    /// The JSON body for `deliver`. Only the documented fields; `agent` is omitted for Main.
    fn to_body(&self, deliver: &'static str) -> Value {
        let mut body = Map::new();
        body.insert("client_message_id".to_owned(), json!(self.client_message_id));
        if let Target::Named(name) = &self.target {
            body.insert("agent".to_owned(), json!(name.as_str()));
        }
        body.insert("deliver".to_owned(), json!(deliver));
        body.insert("message".to_owned(), json!(self.message));
        let mut chat = Map::new();
        chat.insert("id".to_owned(), json!(self.chat.id));
        chat.insert("kind".to_owned(), json!(self.chat.kind.as_wire()));
        if let Some(title) = &self.chat.title {
            chat.insert("title".to_owned(), json!(title));
        }
        chat.insert("member_count".to_owned(), json!(self.chat.member_count));
        body.insert("chat".to_owned(), Value::Object(chat));
        body.insert(
            "sender".to_owned(),
            json!({ "principal_id": self.sender.principal_id, "display": self.sender.display }),
        );
        body.insert("mentions".to_owned(), json!(self.mentions));
        if let Some(reply_to) = &self.reply_to {
            body.insert("reply_to".to_owned(), json!(reply_to));
        }
        Value::Object(body)
    }
}

/// The session path. Only the key grammar's characters can reach the path; anything else is
/// refused locally before a request is made, so a caller value cannot change the route.
fn message_path(session_id: &str) -> Result<String, PrxError> {
    let safe = !session_id.is_empty()
        && session_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if safe {
        Ok(format!("/api/sessions/{session_id}/message"))
    } else {
        Err(local_refusal(ApiCode::FieldInvalid))
    }
}

/// A transport failure after the request may have left: the outcome is unknown. A
/// configuration refusal happens before anything is sent, so it stays as it is.
fn sent_unknown(error: PrxError) -> PrxError {
    match error {
        PrxError::Config { .. } => error,
        _ => PrxError::OutcomeUnknown { http_status: None },
    }
}

/// Maps a post's HTTP answer. A 2xx is returned. A refusal PRX answers in the coded shape keeps
/// its code; `storage_unavailable` and any 5xx leave the outcome unknown (PRX: "treat the outcome
/// as unknown"). An uncoded 4xx is a refusal and stays a `Protocol` error.
fn post_answer(raw: Raw) -> Result<Raw, PrxError> {
    let status = raw.status;
    if (200..300).contains(&status) {
        return Ok(raw);
    }
    if status == 429 {
        // No built-in retry: the caller decides (card D4).
        return Err(rate_limited(raw.retry_after, &raw.body));
    }
    match decode_api_error(status, &raw.body) {
        PrxError::Api { code: ApiCode::StorageUnavailable, .. } => {
            Err(PrxError::OutcomeUnknown { http_status: Some(status) })
        }
        PrxError::Protocol { .. } if status >= 500 => {
            Err(PrxError::OutcomeUnknown { http_status: Some(status) })
        }
        other => Err(other),
    }
}

/// A 2xx answer whose body does not match the documented shape: the post may have been
/// admitted or recorded, so the outcome is unknown.
fn decoded_or_unknown<T: serde::de::DeserializeOwned>(
    body: &[u8],
    status: u16,
) -> Result<T, PrxError> {
    decode_ok(body).map_err(|_| PrxError::OutcomeUnknown { http_status: Some(status) })
}

impl PrxClient {
    /// Admits a turn: PRX runs it as a job. Sent once; the client never resends it.
    ///
    /// # Errors
    /// Returns `Unsupported`; `PrxError::OutcomeUnknown` when the admission may have happened
    /// but its answer was lost, not decodable, or a storage failure; `ProviderNotReady`,
    /// `RateLimited`, `Protocol` (uncoded 4xx) or the API error (for example `field_invalid`,
    /// `agent_targeting_disabled`, `session_busy`), each of which means the turn was not admitted.
    pub async fn post_turn(
        &self,
        caps: &Capabilities,
        session_id: &str,
        message: &RfMessage,
    ) -> Result<TurnAccepted, PrxError> {
        require(caps, MESSAGE_TARGET_V1)?;
        require(caps, MESSAGE_CONTEXT_DELIVERY_V1)?;
        let path = message_path(session_id)?;
        let body = message.to_body("turn");
        let raw = self
            .transport
            .send_single(Method::POST, &path, Some(&body))
            .await
            .map_err(sent_unknown)?;
        let status = raw.status;
        let raw = post_answer(raw)?;
        if status != 202 {
            return Err(PrxError::OutcomeUnknown { http_status: Some(status) });
        }
        let wire: WireTurn = decoded_or_unknown(&raw.body, status)?;
        Ok(TurnAccepted { run_id: wire.run_id, job_id: wire.job_id })
    }

    /// Records a context input for the target. No run starts. Sent once; never resent.
    ///
    /// # Errors
    /// Returns `Unsupported`; `PrxError::OutcomeUnknown` when the input may have been stored but
    /// the answer was lost, not decodable, or a storage failure; otherwise the API error that
    /// means nothing was stored.
    pub async fn post_context(
        &self,
        caps: &Capabilities,
        session_id: &str,
        message: &RfMessage,
    ) -> Result<ContextRecorded, PrxError> {
        require(caps, MESSAGE_TARGET_V1)?;
        require(caps, MESSAGE_CONTEXT_DELIVERY_V1)?;
        let path = message_path(session_id)?;
        let body = message.to_body("context");
        let raw = self
            .transport
            .send_single(Method::POST, &path, Some(&body))
            .await
            .map_err(sent_unknown)?;
        let status = raw.status;
        let raw = post_answer(raw)?;
        if status != 200 {
            return Err(PrxError::OutcomeUnknown { http_status: Some(status) });
        }
        let wire: WireContext = decoded_or_unknown(&raw.body, status)?;
        if wire.status != "recorded" {
            return Err(PrxError::OutcomeUnknown { http_status: Some(status) });
        }
        Ok(ContextRecorded { message_id: wire.message_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    fn message(target: Target) -> RfMessage {
        RfMessage {
            client_message_id: "rf-msg-0001".to_owned(),
            target,
            message: "hello".to_owned(),
            chat: Chat {
                id: "chat-1".to_owned(),
                kind: ChatKind::Group,
                title: None,
                member_count: 3,
            },
            sender: Sender { principal_id: "p-1".to_owned(), display: "Ann".to_owned() },
            mentions: Vec::new(),
            reply_to: None,
        }
    }

    #[test]
    fn main_target_omits_agent_and_optional_fields() {
        let body = message(Target::Main).to_body("turn");
        assert_eq!(body["deliver"], "turn");
        assert!(body.get("agent").is_none(), "Main is an omitted agent");
        assert!(body["chat"].get("title").is_none(), "absent title is omitted");
        assert!(body.get("reply_to").is_none(), "absent reply_to is omitted");
        assert_eq!(body["mentions"], serde_json::json!([]));
        assert_eq!(body["chat"]["kind"], "group");
    }

    #[test]
    fn named_target_and_optional_fields_are_sent_when_set() {
        let mut msg = message(Target::Named(AgentName::parse("worker-1").expect("test: name")));
        msg.chat.title = Some("Team".to_owned());
        msg.reply_to = Some("rf-msg-0000".to_owned());
        msg.mentions = vec!["p-2".to_owned()];
        let body = msg.to_body("context");
        assert_eq!(body["agent"], "worker-1");
        assert_eq!(body["deliver"], "context");
        assert_eq!(body["chat"]["title"], "Team");
        assert_eq!(body["reply_to"], "rf-msg-0000");
        assert_eq!(body["mentions"], serde_json::json!(["p-2"]));
    }

    #[test]
    fn message_path_admits_only_the_key_grammar() {
        assert_eq!(
            message_path("rf-session_1").expect("path"),
            "/api/sessions/rf-session_1/message"
        );
        for bad in ["", "a/b", "a?x=1", "a b", "a%2Fb", "a#"] {
            assert_eq!(
                message_path(bad),
                Err(local_refusal(ApiCode::FieldInvalid)),
                "refused locally, nothing sent: {bad:?}"
            );
        }
    }

    fn answer(status: u16, body: &str) -> Raw {
        Raw { status, body: body.as_bytes().to_vec(), retry_after: None }
    }

    #[test]
    fn transport_failure_after_send_is_unknown_and_config_is_not() {
        assert_eq!(sent_unknown(PrxError::Timeout), PrxError::OutcomeUnknown { http_status: None });
        assert_eq!(
            sent_unknown(PrxError::Unavailable),
            PrxError::OutcomeUnknown { http_status: None }
        );
        let config = PrxError::Config { reason: "refused before sending" };
        assert_eq!(sent_unknown(config.clone()), config);
    }

    #[test]
    fn storage_and_5xx_answers_are_unknown_while_refusals_stay_definite() {
        let storage = r#"{"error":{"code":"storage_unavailable","message":"x"}}"#;
        assert_eq!(
            post_answer(answer(500, storage)).err(),
            Some(PrxError::OutcomeUnknown { http_status: Some(500) })
        );
        assert_eq!(
            post_answer(answer(409, storage)).err(),
            Some(PrxError::OutcomeUnknown { http_status: Some(409) }),
            "PRX also answers storage_unavailable with 409 for an input already stored"
        );
        let busy = r#"{"error":{"code":"session_busy","message":"x"}}"#;
        assert!(matches!(
            post_answer(answer(409, busy)).err(),
            Some(PrxError::Api { status: 409, code: ApiCode::SessionBusy, .. })
        ));
        let not_ready = r#"{"error":{"code":"provider_not_ready","message":"x","reason":"missing_provider_credential"}}"#;
        assert!(matches!(
            post_answer(answer(503, not_ready)).err(),
            Some(PrxError::ProviderNotReady { status: 503, .. })
        ));
        assert!(
            matches!(post_answer(answer(413, "")).err(), Some(PrxError::Protocol { .. })),
            "an uncoded 4xx is a definite refusal, not an unknown outcome"
        );
        assert!(
            matches!(
                post_answer(answer(502, "<html>")).err(),
                Some(PrxError::OutcomeUnknown { http_status: Some(502) })
            ),
            "an uncoded 5xx is unknown"
        );
        assert!(post_answer(answer(202, "")).is_ok(), "2xx passes through");
    }

    #[test]
    fn turn_body_decodes_strictly() {
        let ok: WireTurn =
            decode_ok(br#"{"run_id":"r-1","job_id":"j-1"}"#).expect("test: documented 202 body");
        assert_eq!((ok.run_id.as_str(), ok.job_id.as_str()), ("r-1", "j-1"));
        assert!(decode_ok::<WireTurn>(br#"{"run_id":"r-1"}"#).is_err(), "missing job_id");
        assert!(
            decode_ok::<WireTurn>(br#"{"run_id":"r-1","job_id":"j-1","x":1}"#).is_err(),
            "unknown field"
        );
    }

    #[test]
    fn posts_are_refused_before_sending_without_the_capability() {
        let (_dir, client) = offline_client();
        let caps = caps_with(&[MESSAGE_TARGET_V1]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test: runtime");
        let msg = message(Target::Main);
        let turn = runtime.block_on(client.post_turn(&caps, "rf-s-1", &msg));
        assert!(
            matches!(turn, Err(PrxError::Unsupported { .. })),
            "no context-delivery token: refused before any request"
        );
        let context = runtime.block_on(client.post_context(&caps, "rf-s-1", &msg));
        assert!(matches!(context, Err(PrxError::Unsupported { .. })));
    }
}
