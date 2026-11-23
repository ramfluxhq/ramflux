// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one error type of the client, and the decoding of PRX's coded error shape.

use crate::revision::ConfigRevision;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Every failure of a client call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrxError {
    /// PRX answered with its coded error shape, or the client refused locally with the
    /// same code PRX would have returned (nothing was sent).
    #[error("PRX returned {code:?} (HTTP {status})")]
    Api {
        status: u16,
        code: ApiCode,
        current_revision: Option<ConfigRevision>,
        revision: Option<ConfigRevision>,
        /// Set on `409 incarnation_mismatch`.
        current_incarnation: Option<String>,
    },
    /// The answer does not match the documented contract. Fail closed.
    #[error("PRX response violates the contract: {reason}")]
    Protocol { reason: &'static str },
    /// The daemon could not be reached.
    #[error("PRX is unreachable")]
    Unavailable,
    /// PRX answered HTTP 429 with `rate_limited` (the shared API limit), or a 429 whose body
    /// is not an admission refusal. `retry_after_ms` is the body's `error.retry_after_ms`, else
    /// the `Retry-After` header in milliseconds. No retry is built in; the caller decides.
    #[error("PRX rate-limited the request")]
    RateLimited { retry_after_ms: Option<u64> },
    /// HTTP 429 `agent_busy`: the named agent's concurrency limit refused a new turn.
    /// `retry_after_secs` is the `Retry-After` header in seconds (PRX sends 1). The turn was
    /// not admitted. This is not the shared API rate limit.
    #[error("PRX refused the turn because the agent is at its concurrency limit")]
    AgentBusy { retry_after_secs: Option<u64> },
    /// HTTP 429 `agent_budget_exhausted`: the named agent's daily cost limit refused a new turn.
    /// `retry_after_secs` is the `Retry-After` header in seconds, until the next UTC midnight.
    /// The turn was not admitted. Subscription usage costs nothing, so this cannot fire for a
    /// provider whose reported cost is zero.
    #[error("PRX refused the turn because the agent is over its daily cost limit")]
    AgentBudgetExhausted { retry_after_secs: Option<u64> },
    /// PRX answered `503 provider_not_ready`: the turn runtime has no usable provider
    /// credential. Management routes still answer; only turn routes refuse.
    #[error("PRX turn runtime is not ready: {reason:?} (HTTP {status})")]
    ProviderNotReady { status: u16, reason: NotReadyReason },
    /// The per-request deadline passed.
    #[error("PRX did not answer before the deadline")]
    Timeout,
    /// A turn or context post whose outcome is unknown: the request may have reached PRX
    /// (transport failure after sending, or `storage_unavailable` on the message route, which
    /// PRX documents as "treat the outcome as unknown"). `http_status` is `None` for a transport
    /// failure. The client never resends the post; the caller decides and checks first.
    #[error("the outcome of the message post is unknown (HTTP {http_status:?})")]
    OutcomeUnknown { http_status: Option<u16> },
    /// The client configuration was refused before any request.
    #[error("client configuration refused: {reason}")]
    Config { reason: &'static str },
    /// The PRX build does not advertise the route's capability token.
    #[error("PRX does not advertise {token}")]
    Unsupported { token: String, available_but_off: bool },
}

/// Why the PRX turn runtime is not ready. `Unknown` keeps a reason this client does not know yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotReadyReason {
    /// The default provider has no usable credential (the only value so far).
    MissingProviderCredential,
    Unknown(String),
}

impl NotReadyReason {
    fn from_wire(reason: &str) -> Self {
        match reason {
            "missing_provider_credential" => Self::MissingProviderCredential,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// The error codes the token document names (the session and targeting codes are the ones the
/// rf message routes answer at the pinned commit), plus `Unknown` for any other string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiCode {
    AgentInvalid,
    AgentToolsInvalid,
    FieldInvalid,
    AuthFailed,
    AgentUnknown,
    MethodNotAllowed,
    RevisionConflict,
    AgentDisabled,
    AgentBackendUnsupported,
    NotApplied,
    ConfirmationRequired,
    StorageUnavailable,
    RateLimited,
    SessionUnknown,
    SessionOwnerConflict,
    SessionBusy,
    AgentTargetingDisabled,
    AgentScopeRefused,
    IdempotencyConflict,
    RunUnknown,
    RunActive,
    JobUnknown,
    MessageUnknown,
    MessageDeleted,
    /// `422 forget_family_too_large`: the run family logged more writes than one forget can
    /// remove. Nothing was deleted.
    ForgetFamilyTooLarge,
    /// `409 agent_not_retired`: purge was called before `DELETE` retired the agent.
    AgentNotRetired,
    /// `409 incarnation_mismatch`: history erase `If-Match` is not the agent's incarnation.
    IncarnationMismatch,
    /// `503 history_pending`: the erase did not finish. Retry the same idempotency key.
    HistoryPending,
    /// `503 purge_pending`: the purge did not finish. Retry the same idempotency key.
    PurgePending,
    /// The idempotency key is missing or outside 16..=128 printable ASCII bytes.
    IdempotencyKeyRequired,
    Unknown(String),
}

impl ApiCode {
    fn from_wire(code: &str) -> Self {
        match code {
            "agent_invalid" => Self::AgentInvalid,
            "agent_tools_invalid" => Self::AgentToolsInvalid,
            "field_invalid" => Self::FieldInvalid,
            "auth_failed" => Self::AuthFailed,
            "agent_unknown" => Self::AgentUnknown,
            "method_not_allowed" => Self::MethodNotAllowed,
            "revision_conflict" => Self::RevisionConflict,
            "agent_disabled" => Self::AgentDisabled,
            "agent_backend_unsupported" => Self::AgentBackendUnsupported,
            "not_applied" => Self::NotApplied,
            "confirmation_required" => Self::ConfirmationRequired,
            "storage_unavailable" => Self::StorageUnavailable,
            "rate_limited" => Self::RateLimited,
            "session_unknown" => Self::SessionUnknown,
            "session_owner_conflict" => Self::SessionOwnerConflict,
            "session_busy" => Self::SessionBusy,
            "agent_targeting_disabled" => Self::AgentTargetingDisabled,
            "agent_scope_refused" => Self::AgentScopeRefused,
            "idempotency_conflict" => Self::IdempotencyConflict,
            "run_unknown" => Self::RunUnknown,
            "job_unknown" => Self::JobUnknown,
            "run_active" => Self::RunActive,
            "message_unknown" => Self::MessageUnknown,
            "message_deleted" => Self::MessageDeleted,
            "forget_family_too_large" => Self::ForgetFamilyTooLarge,
            "agent_not_retired" => Self::AgentNotRetired,
            "incarnation_mismatch" => Self::IncarnationMismatch,
            "history_pending" => Self::HistoryPending,
            "purge_pending" => Self::PurgePending,
            "idempotency_key_required" => Self::IdempotencyKeyRequired,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// Shorthand for a contract violation.
pub(crate) fn protocol(reason: &'static str) -> PrxError {
    PrxError::Protocol { reason }
}

/// Shorthand for a refused configuration.
pub(crate) fn config(reason: &'static str) -> PrxError {
    PrxError::Config { reason }
}

/// A refusal the client makes locally, with the code PRX would return (HTTP 400).
pub(crate) fn local_refusal(code: ApiCode) -> PrxError {
    PrxError::Api {
        status: 400,
        code,
        current_revision: None,
        revision: None,
        current_incarnation: None,
    }
}

/// Decodes a 2xx body through the strict I-JSON decoder (duplicate names, unsafe integers,
/// invalid UTF-8 and trailing input are refused). A wrong type or an unknown field also fails closed.
pub(crate) fn decode_ok<T: DeserializeOwned>(body: &[u8]) -> Result<T, PrxError> {
    ramflux_protocol::parse_i_json::<T>(body)
        .map_err(|_| protocol("body does not match the documented shape"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodedTop {
    error: CodedBody,
}

/// Deserializes a field that is present. JSON `null` is refused (fail closed); an absent key
/// is handled by `#[serde(default)]`.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct CodedBody {
    code: String,
    // Present by contract; never parsed for meaning.
    #[serde(rename = "message")]
    _message: String,
    #[serde(default, deserialize_with = "present")]
    current_revision: Option<ConfigRevision>,
    #[serde(default, deserialize_with = "present")]
    revision: Option<ConfigRevision>,
    /// Present on `provider_not_ready` only.
    #[serde(default, deserialize_with = "present")]
    reason: Option<String>,
    /// Present on `incarnation_mismatch`.
    #[serde(default, deserialize_with = "present")]
    current_incarnation: Option<String>,
}

/// Builds the rate-limit error for an HTTP 429. The body's `error.retry_after_ms` wins; the
/// `Retry-After` header (seconds, converted to milliseconds) is the fallback.
pub(crate) fn rate_limited(header_seconds: Option<u64>, body: &[u8]) -> PrxError {
    let body_ms = ramflux_protocol::parse_i_json::<Value>(body)
        .ok()
        .and_then(|value| value.pointer("/error/retry_after_ms").and_then(Value::as_u64));
    let header_ms = header_seconds.map(|seconds| seconds.saturating_mul(1000));
    PrxError::RateLimited { retry_after_ms: body_ms.or(header_ms) }
}

/// Maps an HTTP 429. `agent_busy` and `agent_budget_exhausted` are admission refusals with the
/// `Retry-After` header in seconds. Every other 429, including `rate_limited`, stays the shared
/// rate limit.
#[must_use]
pub fn limit_or_rate(header_seconds: Option<u64>, body: &[u8]) -> PrxError {
    let code = ramflux_protocol::parse_i_json::<Value>(body)
        .ok()
        .and_then(|value| value.pointer("/error/code").and_then(Value::as_str).map(str::to_owned));
    match code.as_deref() {
        Some("agent_busy") => PrxError::AgentBusy { retry_after_secs: header_seconds },
        Some("agent_budget_exhausted") => {
            PrxError::AgentBudgetExhausted { retry_after_secs: header_seconds }
        }
        _ => rate_limited(header_seconds, body),
    }
}

/// Decodes a non-2xx body. A body that is not the coded shape is a contract violation.
pub(crate) fn decode_api_error(status: u16, body: &[u8]) -> PrxError {
    match decode_ok::<CodedTop>(body) {
        Ok(top) if top.error.code == "provider_not_ready" => match top.error.reason {
            Some(reason) => {
                PrxError::ProviderNotReady { status, reason: NotReadyReason::from_wire(&reason) }
            }
            None => protocol("provider_not_ready without its reason"),
        },
        Ok(top) => PrxError::Api {
            status,
            code: ApiCode::from_wire(&top.error.code),
            current_revision: top.error.current_revision,
            revision: top.error.revision,
            current_incarnation: top.error.current_incarnation,
        },
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_A: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const HEX_B: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

    #[test]
    fn rate_limit_documented_body_gives_body_retry_after_ms() {
        // PRX token document, General errors: 429 rate_limited with retry_after_ms and Retry-After.
        let body = br#"{"error":{"code":"rate_limited","message":"Too many API requests. Please retry later.","retry_after_ms":60000}}"#;
        assert_eq!(
            rate_limited(Some(60), body),
            PrxError::RateLimited { retry_after_ms: Some(60_000) },
            "the body value wins over the header"
        );
        assert_eq!(ApiCode::from_wire("rate_limited"), ApiCode::RateLimited);
        let busy = br#"{"error":{"code":"agent_busy","message":"at the concurrency limit"}}"#;
        assert_eq!(
            limit_or_rate(Some(1), busy),
            PrxError::AgentBusy { retry_after_secs: Some(1) },
            "429 agent_busy keeps Retry-After in seconds"
        );
        let budget = br#"{"error":{"code":"agent_budget_exhausted","message":"daily cost limit"}}"#;
        assert_eq!(
            limit_or_rate(Some(3600), budget),
            PrxError::AgentBudgetExhausted { retry_after_secs: Some(3600) }
        );
        assert_eq!(
            limit_or_rate(Some(60), body),
            PrxError::RateLimited { retry_after_ms: Some(60_000) },
            "429 rate_limited stays the shared limit"
        );
    }

    #[test]
    fn rate_limit_falls_back_to_the_header_in_milliseconds() {
        assert_eq!(
            rate_limited(Some(60), br#"{"code":"rate_limited","error":"upstream"}"#),
            PrxError::RateLimited { retry_after_ms: Some(60_000) },
            "a 429 in another shape keeps the header value"
        );
        assert_eq!(
            rate_limited(Some(7), b"not json"),
            PrxError::RateLimited { retry_after_ms: Some(7_000) }
        );
    }

    #[test]
    fn rate_limit_with_neither_value_is_still_rate_limited() {
        assert_eq!(rate_limited(None, b""), PrxError::RateLimited { retry_after_ms: None });
        assert_eq!(
            rate_limited(None, br#"{"error":{"code":"rate_limited","message":"m"}}"#),
            PrxError::RateLimited { retry_after_ms: None }
        );
    }

    #[test]
    fn provider_not_ready_decodes_its_reason() {
        let body = br#"{"error":{"code":"provider_not_ready","message":"store its credential","reason":"missing_provider_credential"}}"#;
        assert_eq!(
            decode_api_error(503, body),
            PrxError::ProviderNotReady {
                status: 503,
                reason: NotReadyReason::MissingProviderCredential,
            }
        );
    }

    #[test]
    fn provider_not_ready_keeps_an_unknown_reason() {
        let body =
            br#"{"error":{"code":"provider_not_ready","message":"m","reason":"future_reason"}}"#;
        assert_eq!(
            decode_api_error(503, body),
            PrxError::ProviderNotReady {
                status: 503,
                reason: NotReadyReason::Unknown("future_reason".to_owned()),
            }
        );
    }

    #[test]
    fn provider_not_ready_without_reason_or_with_null_reason_fails_closed() {
        let absent = br#"{"error":{"code":"provider_not_ready","message":"m"}}"#;
        assert!(matches!(decode_api_error(503, absent), PrxError::Protocol { .. }));
        let null = br#"{"error":{"code":"provider_not_ready","message":"m","reason":null}}"#;
        assert!(matches!(decode_api_error(503, null), PrxError::Protocol { .. }));
    }

    #[test]
    fn revision_conflict_decodes_current_revision() {
        let body = format!(
            r#"{{"error":{{"code":"revision_conflict","message":"stale","current_revision":"{HEX_A}"}}}}"#
        );
        let error = decode_api_error(409, body.as_bytes());
        assert_eq!(
            error,
            PrxError::Api {
                status: 409,
                code: ApiCode::RevisionConflict,
                current_revision: Some(
                    ConfigRevision::parse(HEX_A).expect("test: literal revision")
                ),
                revision: None,
                current_incarnation: None,
            }
        );
    }

    #[test]
    fn confirmation_required_decodes_revision() {
        let body = format!(
            r#"{{"error":{{"code":"confirmation_required","message":"high risk","revision":"{HEX_B}"}}}}"#
        );
        match decode_api_error(428, body.as_bytes()) {
            PrxError::Api { code, revision, current_revision, .. } => {
                assert_eq!(
                    code,
                    ApiCode::ConfirmationRequired,
                    "428 must map to confirmation_required"
                );
                assert_eq!(revision.map(|r| r.as_str().to_owned()), Some(HEX_B.to_owned()));
                assert_eq!(current_revision, None, "428 carries no current_revision");
            }
            other => panic!("test: expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn every_documented_code_maps_to_its_variant() {
        let cases = [
            ("agent_invalid", ApiCode::AgentInvalid),
            ("agent_tools_invalid", ApiCode::AgentToolsInvalid),
            ("field_invalid", ApiCode::FieldInvalid),
            ("auth_failed", ApiCode::AuthFailed),
            ("agent_unknown", ApiCode::AgentUnknown),
            ("method_not_allowed", ApiCode::MethodNotAllowed),
            ("revision_conflict", ApiCode::RevisionConflict),
            ("agent_disabled", ApiCode::AgentDisabled),
            ("agent_backend_unsupported", ApiCode::AgentBackendUnsupported),
            ("not_applied", ApiCode::NotApplied),
            ("confirmation_required", ApiCode::ConfirmationRequired),
            ("storage_unavailable", ApiCode::StorageUnavailable),
            ("idempotency_conflict", ApiCode::IdempotencyConflict),
            ("run_unknown", ApiCode::RunUnknown),
            ("job_unknown", ApiCode::JobUnknown),
            ("forget_family_too_large", ApiCode::ForgetFamilyTooLarge),
            ("agent_not_retired", ApiCode::AgentNotRetired),
            ("incarnation_mismatch", ApiCode::IncarnationMismatch),
            ("history_pending", ApiCode::HistoryPending),
            ("purge_pending", ApiCode::PurgePending),
            ("idempotency_key_required", ApiCode::IdempotencyKeyRequired),
        ];
        for (wire, expected) in cases {
            let body = format!(r#"{{"error":{{"code":"{wire}","message":"m"}}}}"#);
            match decode_api_error(400, body.as_bytes()) {
                PrxError::Api { code, .. } => {
                    assert_eq!(code, expected, "wire code {wire} must map");
                }
                other => panic!("test: {wire} must decode as Api, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_code_is_kept_not_rejected() {
        let body = br#"{"error":{"code":"future_code","message":"m"}}"#;
        match decode_api_error(418, body) {
            PrxError::Api { code, .. } => {
                assert_eq!(
                    code,
                    ApiCode::Unknown("future_code".to_owned()),
                    "unknown code is tolerated"
                );
            }
            other => panic!("test: expected Api error, got {other:?}"),
        }
    }

    #[test]
    fn extra_fields_inside_error_are_tolerated() {
        let body = br#"{"error":{"code":"field_invalid","message":"m","field":"prompt"}}"#;
        assert!(matches!(
            decode_api_error(400, body),
            PrxError::Api { code: ApiCode::FieldInvalid, .. }
        ));
    }

    #[test]
    fn non_coded_bodies_fail_closed() {
        let cases: [&[u8]; 6] = [
            b"Too many requests",
            br#"{"error":"Too many pairing requests","retry_after":60}"#,
            br#"{"error":{"code":"auth_failed"}}"#,
            br#"{"error":{"code":"auth_failed","message":"m"},"extra":1}"#,
            br#"{"error":{"code":"revision_conflict","message":"m","current_revision":"NOT-HEX"}}"#,
            &[0xff, 0xfe, 0x00],
        ];
        for body in cases {
            assert!(
                matches!(decode_api_error(500, body), PrxError::Protocol { .. }),
                "body must be a Protocol error: {body:?}"
            );
        }
    }

    #[test]
    fn message_text_is_never_parsed_for_meaning() {
        let body = br#"{"error":{"code":"storage_unavailable","message":"code: auth_failed, revision_conflict"}}"#;
        assert_eq!(
            decode_api_error(500, body),
            PrxError::Api {
                status: 500,
                code: ApiCode::StorageUnavailable,
                current_revision: None,
                revision: None,
                current_incarnation: None,
            }
        );
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        #[allow(dead_code)]
        ok: bool,
    }

    #[test]
    fn decode_ok_refuses_unknown_top_level_field() {
        let parsed: Result<serde_json::Value, _> = decode_ok(br#"{"ok":true}"#);
        assert!(parsed.is_ok(), "control: a plain object decodes");
        assert!(matches!(
            decode_ok::<Strict>(br#"{"ok":true,"x":1}"#),
            Err(PrxError::Protocol { .. })
        ));
        assert!(matches!(decode_ok::<Strict>(br#"{"ok":"true"}"#), Err(PrxError::Protocol { .. })));
    }

    #[test]
    fn null_current_revision_is_refused() {
        let body = r#"{"error":{"code":"revision_conflict","message":"m","current_revision":"d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"}}"#;
        crate::test_support::assert_null_refused(body, "/error/current_revision", |b| {
            match decode_api_error(409, b) {
                e @ PrxError::Protocol { .. } => Err(e),
                _ => Ok(()),
            }
        });
    }

    #[test]
    fn null_revision_is_refused() {
        let body = r#"{"error":{"code":"confirmation_required","message":"m","revision":"d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"}}"#;
        crate::test_support::assert_null_refused(
            body,
            "/error/revision",
            |b| match decode_api_error(428, b) {
                e @ PrxError::Protocol { .. } => Err(e),
                _ => Ok(()),
            },
        );
    }

    #[test]
    fn duplicate_member_names_fail_closed_in_a_2xx_body() {
        let body = br#"{"revision":"x","revision":"y"}"#;
        let parsed: Result<serde_json::Value, _> = decode_ok(body);
        assert!(
            matches!(parsed, Err(PrxError::Protocol { .. })),
            "strict decoding refuses duplicate names"
        );
    }
}
