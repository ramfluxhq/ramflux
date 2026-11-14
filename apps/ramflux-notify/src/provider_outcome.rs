// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed provider outcomes and the pure retry decision.
//!
//! The send loop consults [`next_attempt`] and [`attempt_timeout`]. A truncated or
//! partial error body is never trusted as a token-invalid reason. Expired is local.

use std::time::Duration;

/// Largest provider error body whose reason codes may be trusted.
pub const MAX_PROVIDER_ERROR_BODY: usize = 16 * 1024;
/// Attempts per route, including the first send and reconnects.
pub const MAX_PROVIDER_ATTEMPTS: u32 = 3;
/// Per-attempt timeout cap.
pub const ATTEMPT_TIMEOUT_CAP: Duration = Duration::from_secs(5);
/// Minimum wait after an FCM quota response.
pub const FCM_QUOTA_MIN_DELAY: Duration = Duration::from_secs(60);

/// Provider family used to interpret a status and body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFamily {
    /// APNs alert and `VoIP` share reason codes.
    Apns,
    /// FCM HTTP v1.
    Fcm,
    /// Web Push.
    WebPush,
}

/// Closed result of one provider attempt or a local admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    /// The provider accepted the request.
    Accepted,
    /// This exact token or subscription is dead.
    InvalidToken,
    /// Credentials or authorization failed. The token stays.
    PermanentConfig,
    /// The request itself will not succeed on retry. The token stays.
    PermanentPayload,
    /// A later attempt inside the original deadline may succeed.
    Transient,
    /// The deadline has passed or the next attempt would miss it.
    Expired,
}

/// What the send loop should do after one observed outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptStep {
    /// Do not send this route again for this wake.
    Stop(ProviderOutcome),
    /// Wait, then try again, still inside the original deadline.
    Wait { delay: Duration, outcome: ProviderOutcome },
}

/// Clock and budget the decision function may see. Tests inject both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptClock {
    /// Attempts already performed, including the one that just finished.
    pub attempts_used: u32,
    /// Current Unix seconds.
    pub now: u64,
    /// Original absolute deadline. Retries must not move it.
    pub expires_at: u64,
}

/// Classify one HTTP response. Transport failures are [`ProviderOutcome::Transient`]
/// and do not call this function.
#[must_use]
pub fn classify_provider_response(
    family: ProviderFamily,
    status: u16,
    body: &[u8],
    body_truncated: bool,
    retry_after: Option<&str>,
) -> (ProviderOutcome, Option<u64>, bool) {
    let retry_after_seconds = retry_after.and_then(retry_after_delta_seconds);
    if (200..300).contains(&status) {
        return (ProviderOutcome::Accepted, retry_after_seconds, false);
    }
    if let Some(trusted) = trusted_body(body, body_truncated) {
        match family {
            ProviderFamily::Apns => {
                if let Some(outcome) = apns_outcome(trusted) {
                    return (outcome, retry_after_seconds, false);
                }
            }
            ProviderFamily::Fcm => {
                if let Some((outcome, quota)) = fcm_outcome(trusted) {
                    return (outcome, retry_after_seconds, quota);
                }
            }
            ProviderFamily::WebPush => {}
        }
    }
    (status_fallback(family, status), retry_after_seconds, false)
}

/// Parse a Retry-After delta-seconds value. HTTP-dates are ignored.
#[must_use]
pub fn retry_after_delta_seconds(header: &str) -> Option<u64> {
    let trimmed = header.trim();
    if trimmed.is_empty()
        || trimmed.len() > 10
        || !trimmed.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    trimmed.parse().ok()
}

/// Result of one provider send, including the only outcome that may delete a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderSendStatus {
    Accepted,
    Failed,
    InvalidToken,
}

impl ProviderSendStatus {
    /// Whether the provider accepted the push.
    #[must_use]
    pub const fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Whether this outcome may delete the snapshotted route.
#[must_use]
pub const fn invalidates_token(outcome: ProviderOutcome) -> bool {
    matches!(outcome, ProviderOutcome::InvalidToken)
}

/// Timeout for one request: the lesser of five seconds and the remaining lifetime.
#[must_use]
pub fn attempt_timeout(now: u64, expires_at: u64) -> Duration {
    if now >= expires_at {
        return Duration::ZERO;
    }
    Duration::from_secs(expires_at.saturating_sub(now).min(ATTEMPT_TIMEOUT_CAP.as_secs()))
}

/// Decide the next attempt. Jitter is a caller-supplied draw in basis points, capped at 20%.
#[must_use]
pub fn next_attempt(
    clock: AttemptClock,
    outcome: ProviderOutcome,
    retry_after_seconds: Option<u64>,
    quota_exceeded: bool,
    jitter_bps: u16,
) -> AttemptStep {
    if clock.now >= clock.expires_at {
        return AttemptStep::Stop(ProviderOutcome::Expired);
    }
    if outcome != ProviderOutcome::Transient {
        return AttemptStep::Stop(outcome);
    }
    if clock.attempts_used >= MAX_PROVIDER_ATTEMPTS {
        return AttemptStep::Stop(outcome);
    }
    let Some(delay) =
        retry_delay(clock.attempts_used, retry_after_seconds, quota_exceeded, jitter_bps)
    else {
        return AttemptStep::Stop(outcome);
    };
    let remaining_ms = clock.expires_at.saturating_sub(clock.now).saturating_mul(1_000);
    if u64::try_from(delay.as_millis()).unwrap_or(u64::MAX) >= remaining_ms {
        return AttemptStep::Stop(ProviderOutcome::Expired);
    }
    AttemptStep::Wait { delay, outcome }
}

fn retry_delay(
    attempts_used: u32,
    retry_after_seconds: Option<u64>,
    quota_exceeded: bool,
    jitter_bps: u16,
) -> Option<Duration> {
    let base_ms = match attempts_used {
        1 => 1_000_u64,
        2 => 2_000,
        _ => return None,
    };
    let bps = u64::from(jitter_bps.min(2_000));
    let mut delay_ms = base_ms.saturating_add(base_ms.saturating_mul(bps) / 10_000);
    if let Some(seconds) = retry_after_seconds {
        delay_ms = delay_ms.max(seconds.saturating_mul(1_000));
    }
    if quota_exceeded {
        delay_ms = delay_ms.max(u64::try_from(FCM_QUOTA_MIN_DELAY.as_millis()).unwrap_or(60_000));
    }
    Some(Duration::from_millis(delay_ms))
}

fn trusted_body(body: &[u8], truncated: bool) -> Option<&[u8]> {
    if truncated || body.len() > MAX_PROVIDER_ERROR_BODY { None } else { Some(body) }
}

fn apns_outcome(body: &[u8]) -> Option<ProviderOutcome> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let reason = value.get("reason")?.as_str()?;
    if reason.len() > 64 { None } else { apns_reason_outcome(reason) }
}

fn apns_reason_outcome(reason: &str) -> Option<ProviderOutcome> {
    Some(match reason {
        "BadDeviceToken" | "Unregistered" | "DeviceTokenNotForTopic" | "ExpiredToken" => {
            ProviderOutcome::InvalidToken
        }
        "PayloadTooLarge" | "BadMessageId" | "BadCollapseId" | "BadExpirationDate"
        | "BadPriority" | "BadTopic" | "MissingTopic" | "TopicDisallowed" | "InvalidPushType"
        | "PayloadEmpty" | "MissingDeviceToken" | "DuplicateHeaders" | "BadPath"
        | "MethodNotAllowed" => ProviderOutcome::PermanentPayload,
        "BadCertificate"
        | "BadCertificateEnvironment"
        | "ExpiredProviderToken"
        | "InvalidProviderToken"
        | "MissingProviderToken"
        | "Forbidden" => ProviderOutcome::PermanentConfig,
        "TooManyRequests" | "InternalServerError" | "ServiceUnavailable" | "Shutdown" => {
            ProviderOutcome::Transient
        }
        _ => return None,
    })
}

fn fcm_outcome(body: &[u8]) -> Option<(ProviderOutcome, bool)> {
    let value: serde_json::Value = ramflux_protocol::parse_i_json(body).ok()?;
    let error = value.get("error")?;
    let code = fcm_typed_error_code(error)
        .or_else(|| error.get("status").and_then(serde_json::Value::as_str))?;
    if code.len() > 64 { None } else { fcm_status_outcome(code) }
}

fn fcm_typed_error_code(error: &serde_json::Value) -> Option<&str> {
    let details = error.get("details")?.as_array()?;
    details.iter().find_map(|detail| {
        let kind = detail.get("@type").and_then(serde_json::Value::as_str)?;
        kind.contains("FcmError")
            .then(|| detail.get("errorCode").and_then(serde_json::Value::as_str))?
    })
}

fn fcm_status_outcome(status: &str) -> Option<(ProviderOutcome, bool)> {
    Some(match status {
        "UNREGISTERED" => (ProviderOutcome::InvalidToken, false),
        "INVALID_ARGUMENT" | "UNSPECIFIED_ERROR" => (ProviderOutcome::PermanentPayload, false),
        "SENDER_ID_MISMATCH" | "THIRD_PARTY_AUTH_ERROR" => {
            (ProviderOutcome::PermanentConfig, false)
        }
        "QUOTA_EXCEEDED" | "RESOURCE_EXHAUSTED" => (ProviderOutcome::Transient, true),
        "UNAVAILABLE" | "INTERNAL" => (ProviderOutcome::Transient, false),
        _ => return None,
    })
}

fn status_fallback(family: ProviderFamily, status: u16) -> ProviderOutcome {
    match (family, status) {
        (ProviderFamily::WebPush, 404 | 410) => ProviderOutcome::InvalidToken,
        (_, 401 | 403) => ProviderOutcome::PermanentConfig,
        (_, 429 | 500..=599) => ProviderOutcome::Transient,
        _ => ProviderOutcome::PermanentPayload,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptClock, AttemptStep, ProviderFamily, ProviderOutcome, classify_provider_response,
        invalidates_token, next_attempt, retry_after_delta_seconds,
    };

    fn clock(attempts: u32, now: u64, expires_at: u64) -> AttemptClock {
        AttemptClock { attempts_used: attempts, now, expires_at }
    }

    #[test]
    fn token_invalid_is_provider_specific_and_truncation_does_not_delete() {
        let (outcome, _, _) = classify_provider_response(
            ProviderFamily::Apns,
            400,
            br#"{"reason":"BadDeviceToken"}"#,
            false,
            None,
        );
        assert_eq!(outcome, ProviderOutcome::InvalidToken);
        assert!(invalidates_token(outcome));
        let (truncated, _, _) = classify_provider_response(
            ProviderFamily::Apns,
            400,
            br#"{"reason":"BadDeviceToken"}"#,
            true,
            None,
        );
        assert_eq!(truncated, ProviderOutcome::PermanentPayload);
        assert!(!invalidates_token(truncated));
        let (payload, _, _) = classify_provider_response(
            ProviderFamily::Apns,
            400,
            br#"{"reason":"PayloadTooLarge"}"#,
            false,
            None,
        );
        assert_eq!(payload, ProviderOutcome::PermanentPayload);
        let (config, _, _) = classify_provider_response(
            ProviderFamily::Apns,
            403,
            br#"{"reason":"Forbidden"}"#,
            false,
            None,
        );
        assert_eq!(config, ProviderOutcome::PermanentConfig);
        let (fcm, _, quota) = classify_provider_response(
            ProviderFamily::Fcm,
            404,
            br#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#,
            false,
            None,
        );
        assert_eq!(fcm, ProviderOutcome::InvalidToken);
        assert!(!quota);
        let (not_found, _, not_found_quota) = classify_provider_response(
            ProviderFamily::Fcm,
            404,
            br#"{"error":{"code":404,"status":"NOT_FOUND"}}"#,
            false,
            None,
        );
        assert_ne!(not_found, ProviderOutcome::InvalidToken);
        assert!(!not_found_quota);
        let (quota_status, _, quota_flag) = classify_provider_response(
            ProviderFamily::Fcm,
            429,
            br#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"QUOTA_EXCEEDED"}]}}"#,
            false,
            None,
        );
        assert_eq!(quota_status, ProviderOutcome::Transient);
        assert!(quota_flag);
        let (argument, _, _) = classify_provider_response(
            ProviderFamily::Fcm,
            400,
            br#"{"error":{"status":"INVALID_ARGUMENT"}}"#,
            false,
            None,
        );
        assert_eq!(argument, ProviderOutcome::PermanentPayload);
        let (hidden, _, _) = classify_provider_response(
            ProviderFamily::Fcm,
            400,
            br#"{"error":{"status":"UNREGISTERED"}}"#,
            true,
            None,
        );
        assert_eq!(hidden, ProviderOutcome::PermanentPayload);
        let (web, _, _) =
            classify_provider_response(ProviderFamily::WebPush, 410, b"", false, None);
        assert_eq!(web, ProviderOutcome::InvalidToken);
    }

    #[test]
    fn retries_stay_inside_the_deadline_and_permanent_payload_does_not_retry() {
        assert_eq!(retry_after_delta_seconds("10"), Some(10));
        assert_eq!(retry_after_delta_seconds("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        let step =
            next_attempt(clock(1, 1_000, 90_000), ProviderOutcome::Transient, None, false, 0);
        assert_eq!(
            step,
            AttemptStep::Wait {
                delay: std::time::Duration::from_millis(1_000),
                outcome: ProviderOutcome::Transient
            }
        );
        let quota_floor =
            next_attempt(clock(1, 1_000, 90_000), ProviderOutcome::Transient, None, true, 0);
        assert_eq!(
            quota_floor,
            AttemptStep::Wait {
                delay: super::FCM_QUOTA_MIN_DELAY,
                outcome: ProviderOutcome::Transient
            }
        );
        let jitter =
            next_attempt(clock(1, 1_000, 90_000), ProviderOutcome::Transient, None, false, 2_000);
        assert_eq!(
            jitter,
            AttemptStep::Wait {
                delay: std::time::Duration::from_millis(1_200),
                outcome: ProviderOutcome::Transient
            }
        );
        let honored =
            next_attempt(clock(1, 1_000, 90_000), ProviderOutcome::Transient, Some(10), false, 0);
        assert_eq!(
            honored,
            AttemptStep::Wait {
                delay: std::time::Duration::from_secs(10),
                outcome: ProviderOutcome::Transient
            }
        );
        let quota =
            next_attempt(clock(1, 1_000, 90_000), ProviderOutcome::Transient, Some(5), true, 0);
        assert_eq!(
            quota,
            AttemptStep::Wait {
                delay: std::time::Duration::from_secs(60),
                outcome: ProviderOutcome::Transient
            }
        );
        let missed =
            next_attempt(clock(1, 1_000, 1_010), ProviderOutcome::Transient, None, true, 0);
        assert_eq!(missed, AttemptStep::Stop(ProviderOutcome::Expired));
        let stopped =
            next_attempt(clock(3, 1_000, 90_000), ProviderOutcome::Transient, None, false, 0);
        assert_eq!(stopped, AttemptStep::Stop(ProviderOutcome::Transient));
        let permanent = next_attempt(
            clock(1, 1_000, 90_000),
            ProviderOutcome::PermanentPayload,
            Some(30),
            false,
            0,
        );
        assert_eq!(permanent, AttemptStep::Stop(ProviderOutcome::PermanentPayload));
    }
}
