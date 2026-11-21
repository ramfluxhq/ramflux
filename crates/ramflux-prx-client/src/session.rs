// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `POST /api/sessions` with a caller `session_key` (`session_key_v1`).
//!
//! The key grammar, the `console-` prefix and the owner rules are PRX's to check: the client
//! sends the key as given, so the daemon's refusal is what a caller sees.

use crate::capabilities::{Capabilities, SESSION_KEY_V1, require};
use crate::client::PrxClient;
use crate::error::{PrxError, decode_ok, protocol};
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;

/// The answer of a session create: `201` when created, `200` when this owner already holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCreated {
    /// The session id: PRX uses the caller's key as the id.
    pub session_id: String,
    pub created: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSession {
    session_id: String,
    created: bool,
}

impl PrxClient {
    /// Creates the session for `session_key`, or reads the existing one of this owner.
    /// Needs `session_key_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error (for example `field_invalid` for a bad key,
    /// `session_owner_conflict`), or a transport or contract error. A `201` with
    /// `created:false`, or a `200` with `created:true`, is a contract violation.
    pub async fn create_session(
        &self,
        caps: &Capabilities,
        session_key: &str,
    ) -> Result<SessionCreated, PrxError> {
        require(caps, SESSION_KEY_V1)?;
        let body = json!({ "session_key": session_key });
        let raw = self.transport.call(Method::POST, "/api/sessions", None, Some(&body)).await?;
        let wire: WireSession = decode_ok(&raw.body)?;
        let expected_created = match raw.status {
            201 => true,
            200 => false,
            _ => return Err(protocol("session create answered an unexpected 2xx status")),
        };
        if wire.created != expected_created {
            return Err(protocol("session create: status and created disagree"));
        }
        if wire.session_id != session_key {
            return Err(protocol("session create: session_id is not the session key"));
        }
        Ok(SessionCreated { session_id: wire.session_id, created: wire.created })
    }
}
