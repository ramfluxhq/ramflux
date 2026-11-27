// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed refusals of the card session API. Every `card_session_*` code reaches the client
//! as `error.code` and `error.reason_code`, never as a `ValidationFailed` message token.
use crate::SdkError;
use serde_json::json;

pub(super) const EXPIRED: &str = "card_session_expired";
pub(super) const LIMIT_EXCEEDED: &str = "card_limit_exceeded";

fn message(code: &str) -> &'static str {
    match code {
        EXPIRED => "card session expired; reopen the card",
        "card_session_inactive" => "card session is not active",
        "card_session_limit" => "card session limit reached",
        "card_session_refused" => "card session request refused",
        "card_session_stale" => "card session request is stale",
        LIMIT_EXCEEDED => "card runtime limit exceeded: resident VMs",
        "card_session_busy" => "card session store is busy",
        _ => "card session error",
    }
}

/// A typed refusal for `code`.
pub(super) fn typed(code: &'static str) -> SdkError {
    SdkError::LocalBusRefused {
        code: code.to_owned(),
        message: message(code).to_owned(),
        body: Box::new(json!({"reason_code": code})),
    }
}

/// The session id was dropped by a lock, sign-out, actor stop or connection close.
pub(super) fn expired(session: u64) -> SdkError {
    SdkError::LocalBusRefused {
        code: EXPIRED.to_owned(),
        message: message(EXPIRED).to_owned(),
        body: Box::new(json!({"reason_code": EXPIRED, "session": session})),
    }
}
