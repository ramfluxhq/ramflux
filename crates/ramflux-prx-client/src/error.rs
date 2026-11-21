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
    },
    /// The answer does not match the documented contract. Fail closed.
    #[error("PRX response violates the contract: {reason}")]
    Protocol { reason: &'static str },
    /// The daemon could not be reached.
    #[error("PRX is unreachable")]
    Unavailable,
    /// PRX answered HTTP 429 (shared API rate limit). Any 429 maps here, whatever its body.
    /// No retry is built in; the caller decides.
    #[error("PRX rate-limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    /// The per-request deadline passed.
    #[error("PRX did not answer before the deadline")]
    Timeout,
    /// The client configuration was refused before any request.
    #[error("client configuration refused: {reason}")]
    Config { reason: &'static str },
    /// The PRX build does not advertise the route's capability token.
    #[error("PRX does not advertise {token}")]
    Unsupported { token: String, available_but_off: bool },
}

/// The closed list of error codes in the token document, plus `Unknown` for any other string.
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
    PrxError::Api { status: 400, code, current_revision: None, revision: None }
}

/// Decodes a 2xx body. Invalid UTF-8, a wrong type and an unknown field all fail closed.
pub(crate) fn decode_ok<T: DeserializeOwned>(body: &[u8]) -> Result<T, PrxError> {
    let text = std::str::from_utf8(body).map_err(|_| protocol("body is not UTF-8"))?;
    serde_json::from_str(text).map_err(|_| protocol("body does not match the documented shape"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodedTop {
    error: CodedBody,
}

#[derive(Deserialize)]
struct CodedBody {
    code: String,
    // Present by contract; never parsed for meaning.
    #[serde(rename = "message")]
    _message: String,
    #[serde(default)]
    current_revision: Option<ConfigRevision>,
    #[serde(default)]
    revision: Option<ConfigRevision>,
}

/// Builds the rate-limit error for an HTTP 429. `Retry-After` (seconds) wins over a numeric
/// `retry_after` in the body, top level or inside `error` (the future coded shape).
pub(crate) fn rate_limited(header_seconds: Option<u64>, body: &[u8]) -> PrxError {
    let body_seconds = std::str::from_utf8(body)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| {
            value
                .get("retry_after")
                .or_else(|| value.pointer("/error/retry_after"))
                .and_then(Value::as_u64)
        });
    PrxError::RateLimited { retry_after_seconds: header_seconds.or(body_seconds) }
}

/// Decodes a non-2xx body. A body that is not the coded shape is a contract violation.
pub(crate) fn decode_api_error(status: u16, body: &[u8]) -> PrxError {
    match decode_ok::<CodedTop>(body) {
        Ok(top) => PrxError::Api {
            status,
            code: ApiCode::from_wire(&top.error.code),
            current_revision: top.error.current_revision,
            revision: top.error.revision,
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
    fn rate_limit_today_body_gives_body_retry_after() {
        let body = br#"{"error":"Too many API requests. Please retry later.","retry_after":60}"#;
        assert_eq!(
            rate_limited(None, body),
            PrxError::RateLimited { retry_after_seconds: Some(60) }
        );
    }

    #[test]
    fn rate_limit_future_coded_body_decodes_to_same_variant() {
        let body = br#"{"error":{"code":"rate_limited","message":"slow down","retry_after":30}}"#;
        assert_eq!(
            rate_limited(None, body),
            PrxError::RateLimited { retry_after_seconds: Some(30) }
        );
        assert_eq!(ApiCode::from_wire("rate_limited"), ApiCode::RateLimited);
    }

    #[test]
    fn rate_limit_header_wins_over_body() {
        let body = br#"{"error":"x","retry_after":60}"#;
        assert_eq!(
            rate_limited(Some(5), body),
            PrxError::RateLimited { retry_after_seconds: Some(5) }
        );
    }

    #[test]
    fn rate_limit_with_only_header_or_nothing() {
        assert_eq!(
            rate_limited(Some(7), b"not json"),
            PrxError::RateLimited { retry_after_seconds: Some(7) }
        );
        assert_eq!(rate_limited(None, b""), PrxError::RateLimited { retry_after_seconds: None });
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
}
