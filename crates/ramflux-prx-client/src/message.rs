// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `POST /api/sessions/{session_id}/message` for rf messages: a `turn` (starts a run) or a
//! `context` (records the input, starts nothing). Needs `message_target_v1` and
//! `message_context_delivery_v1`.
//!
//! The client sends each post exactly once and never retries it. A post whose answer is lost,
//! or whose storage outcome PRX reports as unknown, comes back as `PrxError::OutcomeUnknown`;
//! the caller decides what to do next. A deliberate resend of the same key is answered by PRX
//! (`message_idempotency_v1`): a replay, a restart attempt, or `409 message_deleted`. The
//! client itself never resends.
//!
//! Field bounds (ids, message size, names, mentions) are PRX's to enforce: the client sends what
//! the caller gives and the daemon's `400 field_invalid` is what a caller sees.

use crate::capabilities::{
    Capabilities, MESSAGE_CONTEXT_DELIVERY_V1, MESSAGE_IDEMPOTENCY_V1, MESSAGE_TARGET_V1, require,
};
use crate::client::PrxClient;
use crate::error::{
    ApiCode, PrxError, decode_api_error, decode_ok, limit_or_rate, local_refusal, present, protocol,
};
use crate::name::AgentName;
use crate::run::{RunCode, RunState, run_state};
use crate::transport::Raw;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Who answers the message. `Main` sorts before every named agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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

/// What PRX did with a turn post. Only `Admitted` and `Restarted` started a run in this call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnDisposition {
    /// `202`: the first admission of this key; a new run started.
    Admitted,
    /// `202` after PRX stopped mid-turn: a new attempt started. `previous_run_id` names the
    /// interrupted attempt, which may have executed tools; rf shows "interrupted, retried".
    Restarted { attempt: u32, previous_run_id: String },
    /// `200` with `replayed:true`: the same key and body were seen before. No run started.
    /// `status` is the durable state (`running` while the first attempt still runs).
    Replayed { status: RunState, code: Option<RunCode> },
}

/// A turn post that PRX admitted or answered as a replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnAccepted {
    pub run_id: String,
    pub job_id: String,
    pub disposition: TurnDisposition,
}

/// `200 {"message_id","status":"recorded"}`: a context input was stored; no run started.
/// `replayed` is true when the same key and body had been recorded before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRecorded {
    pub message_id: String,
    pub replayed: bool,
}

/// Every turn answer in one strict shape. Which fields are present is checked by `turn_answer`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTurn {
    run_id: String,
    job_id: String,
    #[serde(default, deserialize_with = "present")]
    status: Option<String>,
    #[serde(default, deserialize_with = "present")]
    code: Option<String>,
    #[serde(default, deserialize_with = "present")]
    replayed: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    attempt: Option<u32>,
    #[serde(default, deserialize_with = "present")]
    previous_run_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContext {
    message_id: String,
    status: String,
    #[serde(default, deserialize_with = "present")]
    replayed: Option<bool>,
}

/// Checks a turn answer against the documented shapes: `202` is a first admission (no replay
/// fields) or a restart (`attempt` ≥ 2 with `previous_run_id`); `200` is a replay (`replayed`
/// true, a durable `status`). Any other combination is not a documented answer.
fn turn_answer(status: u16, wire: WireTurn) -> Result<TurnAccepted, PrxError> {
    let WireTurn { run_id, job_id, status: state, code, replayed, attempt, previous_run_id } = wire;
    let disposition = match (status, state, replayed, attempt, previous_run_id) {
        (202, None, None, None, None) if code.is_none() => TurnDisposition::Admitted,
        (202, None, None, Some(attempt), Some(previous_run_id))
            if attempt >= 2 && code.is_none() && previous_run_id != run_id =>
        {
            TurnDisposition::Restarted { attempt, previous_run_id }
        }
        (200, Some(state), Some(true), None, None) => {
            let (status, code) = run_state(&state, code.as_deref())?;
            TurnDisposition::Replayed { status, code }
        }
        _ => return Err(protocol("turn answer is not one of the documented shapes")),
    };
    Ok(TurnAccepted { run_id, job_id, disposition })
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
        // No built-in retry: the caller decides (card D4). `agent_busy` and
        // `agent_budget_exhausted` stay admission refusals; other 429s stay the shared limit.
        return Err(limit_or_rate(raw.retry_after, &raw.body));
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
    /// `RateLimited`, `AgentBusy`, `AgentBudgetExhausted`, `Protocol` (uncoded 4xx) or the API
    /// error (for example `field_invalid`, `agent_targeting_disabled`, `session_busy`), each of
    /// which means the turn was not admitted.
    pub async fn post_turn(
        &self,
        caps: &Capabilities,
        session_id: &str,
        message: &RfMessage,
    ) -> Result<TurnAccepted, PrxError> {
        require(caps, MESSAGE_TARGET_V1)?;
        require(caps, MESSAGE_CONTEXT_DELIVERY_V1)?;
        require(caps, MESSAGE_IDEMPOTENCY_V1)?;
        let path = message_path(session_id)?;
        let body = message.to_body("turn");
        let raw = self
            .transport
            .send_single(Method::POST, &path, Some(&body))
            .await
            .map_err(sent_unknown)?;
        let status = raw.status;
        let raw = post_answer(raw)?;
        let wire: WireTurn = decoded_or_unknown(&raw.body, status)?;
        turn_answer(status, wire)
            .map_err(|_| PrxError::OutcomeUnknown { http_status: Some(status) })
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
        require(caps, MESSAGE_IDEMPOTENCY_V1)?;
        let path = message_path(session_id)?;
        let body = message.to_body("context");
        let raw = self
            .transport
            .send_single(Method::POST, &path, Some(&body))
            .await
            .map_err(sent_unknown)?;
        let status = raw.status;
        let raw = post_answer(raw)?;
        let unknown = PrxError::OutcomeUnknown { http_status: Some(status) };
        if status != 200 {
            return Err(unknown);
        }
        let wire: WireContext = decoded_or_unknown(&raw.body, status)?;
        if wire.status != "recorded" || wire.replayed == Some(false) {
            return Err(unknown);
        }
        Ok(ContextRecorded { message_id: wire.message_id, replayed: wire.replayed == Some(true) })
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

    fn turn(text: &str) -> WireTurn {
        decode_ok(text.as_bytes()).expect("test: wire turn decodes")
    }

    #[test]
    fn turn_answers_follow_the_documented_shapes() {
        let first = turn(r#"{"run_id":"r-1","job_id":"j-1"}"#);
        assert_eq!(turn_answer(202, first).map(|t| t.disposition), Ok(TurnDisposition::Admitted));

        let restarted =
            turn(r#"{"run_id":"r-2","job_id":"j-2","attempt":2,"previous_run_id":"r-1"}"#);
        assert_eq!(
            turn_answer(202, restarted).map(|t| t.disposition),
            Ok(TurnDisposition::Restarted { attempt: 2, previous_run_id: "r-1".to_owned() })
        );

        let running = turn(r#"{"run_id":"r-1","job_id":"j-1","status":"running","replayed":true}"#);
        assert_eq!(
            turn_answer(200, running).map(|t| t.disposition),
            Ok(TurnDisposition::Replayed { status: RunState::Running, code: None })
        );

        let interrupted = turn(
            r#"{"run_id":"r-1","job_id":"j-1","status":"failed","code":"interrupted","replayed":true}"#,
        );
        assert_eq!(
            turn_answer(200, interrupted).map(|t| t.disposition),
            Ok(TurnDisposition::Replayed {
                status: RunState::Failed,
                code: Some(RunCode::Interrupted)
            })
        );
    }

    #[test]
    fn turn_answers_outside_the_documented_shapes_are_refused() {
        // A 200 replay without replayed:true, a 202 that carries replay fields, attempt 1 as a
        // restart, and a restart that names its own run are all refused.
        let cases = [
            (200, r#"{"run_id":"r-1","job_id":"j-1","status":"running"}"#),
            (202, r#"{"run_id":"r-1","job_id":"j-1","status":"running","replayed":true}"#),
            (202, r#"{"run_id":"r-2","job_id":"j-2","attempt":1,"previous_run_id":"r-1"}"#),
            (202, r#"{"run_id":"r-2","job_id":"j-2","attempt":2}"#),
            (202, r#"{"run_id":"r-2","job_id":"j-2","attempt":2,"previous_run_id":"r-2"}"#),
            (200, r#"{"run_id":"r-1","job_id":"j-1","status":"queued","replayed":true}"#),
            (
                200,
                r#"{"run_id":"r-1","job_id":"j-1","status":"running","replayed":true,"code":"interrupted"}"#,
            ),
        ];
        for (status, text) in cases {
            assert!(turn_answer(status, turn(text)).is_err(), "must be refused: {text}");
        }
    }

    #[test]
    fn context_replay_flag_is_strict() {
        let first: WireContext =
            decode_ok(br#"{"message_id":"m-1","status":"recorded"}"#).expect("test: first context");
        assert_eq!(first.replayed, None);
        let replay: WireContext =
            decode_ok(br#"{"message_id":"m-1","status":"recorded","replayed":true}"#)
                .expect("test: replayed context");
        assert_eq!(replay.replayed, Some(true));
        assert!(
            decode_ok::<WireContext>(
                br#"{"message_id":"m-1","status":"recorded","replayed":null}"#
            )
            .is_err(),
            "an explicit null replayed is refused"
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
