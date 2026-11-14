// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Correlation for one call control on one authenticated gateway stream.

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionFrame {
    frame_type: String,
    context: CallSubmitContext,
    state: CallResolutionState,
    media_allowed: bool,
    wake_resolved: bool,
}

/// Validate the closed decision carrier before a generic gateway-frame decoder consumes it.
/// # Errors
/// Rejects unknown members, absent values, non-I-JSON and malformed operation identity.
pub fn validate_call_resolution_frame(bytes: &[u8]) -> Result<(), crate::ProtocolError> {
    let value: serde_json::Value = crate::parse_i_json(bytes)?;
    if value.get("frame_type").and_then(serde_json::Value::as_str) != Some("call_resolved") {
        return Ok(());
    }
    if bytes.len() > 4096 {
        return Err(crate::ProtocolError::NotificationContract("call_resolution_size"));
    }
    let frame: DecisionFrame = crate::parse_i_json(bytes)?;
    frame.context.validate()?;
    let _ = (frame.frame_type, frame.state, frame.media_allowed, frame.wake_resolved);
    Ok(())
}

/// Capability required for correlated call submissions and decisions.
pub const CALL_RESOLUTION_CAPABILITY: &str = "gateway.call_resolution.v1";

/// A decision is useful only for this complete operation identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallSubmitContext {
    pub version: u32,
    pub call_ref: String,
    pub start_digest: String,
    pub request_id: String,
    pub envelope_id: String,
    pub session_id: String,
    pub session_generation: String,
}

impl CallSubmitContext {
    /// # Errors
    /// Refuses malformed identifiers, unsupported versions and oversized contexts.
    pub fn validate(&self) -> Result<(), crate::ProtocolError> {
        let valid_id = |s: &str| {
            !s.is_empty() && s.len() <= 512 && s.trim() == s && !s.chars().any(char::is_control)
        };
        let valid_bytes = |s: &str, n: usize| {
            s.len() == (n * 8usize).div_ceil(6)
                && crate::decode_base64url(s)
                    .is_ok_and(|b| b.len() == n && crate::encode_base64url(&b) == s)
        };
        if self.version != 1
            || !valid_bytes(&self.call_ref, 16)
            || !valid_bytes(&self.start_digest, 32)
            || !valid_bytes(&self.session_generation, 32)
            || !valid_id(&self.request_id)
            || !valid_id(&self.envelope_id)
            || !valid_id(&self.session_id)
            || crate::canonical_json_bytes(self)?.len() > 2048
        {
            return Err(crate::ProtocolError::NotificationContract("call_context"));
        }
        Ok(())
    }
}

/// Gateway call state; expiry is represented as cancelled on the public stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallResolutionState {
    Ringing,
    Answered,
    Rejected,
    Ended,
    Cancelled,
}

/// Both flags are checked against the state rather than trusted independently.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallResolution {
    pub context: CallSubmitContext,
    pub state: CallResolutionState,
    pub media_allowed: bool,
    pub wake_resolved: bool,
}

/// The complete authenticated body for a call. Optional members are explicit nulls.
#[derive(Serialize)]
pub struct CallSubmitBody<'a> {
    pub envelope: &'a crate::Envelope,
    pub call_intent: Option<&'a crate::SignedCallIntentV1>,
    pub wake_id: Option<&'a str>,
    pub call_ref: &'a str,
    pub call_terminal: Option<&'a str>,
    pub call_context: &'a CallSubmitContext,
}

impl CallResolution {
    #[must_use]
    pub const fn consistent(&self) -> bool {
        match self.state {
            CallResolutionState::Ringing => self.media_allowed && !self.wake_resolved,
            CallResolutionState::Answered => self.media_allowed && self.wake_resolved,
            CallResolutionState::Rejected
            | CallResolutionState::Ended
            | CallResolutionState::Cancelled => !self.media_allowed && self.wake_resolved,
        }
    }
}
