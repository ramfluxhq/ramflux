// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant SDK ephemeral submit codec, D1 validation, and D5 local unsupported.

use ramflux_protocol::ephemeral::{
    EphemeralDropReason, EphemeralModeError, EphemeralSubmitOutcome, EphemeralSubmitResult,
    GATEWAY_EPHEMERAL_CAPABILITY, deadline,
};
use ramflux_protocol::{Envelope, GATEWAY_SESSION_PUSH_CAPABILITY, parse_i_json};
use serde::{Deserialize, Serialize};

/// Typed result of [`send_ephemeral`]: local D1/D5 or a mapped `ephemeral_result`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EphemeralSendOutcome {
    Delivered,
    Invalid(EphemeralModeError),
    Unsupported,
    RateLimited,
    Replayed,
    Dropped(EphemeralDropReason),
}

/// Transport or codec failure after D1/D5 have already decided to send.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EphemeralSendError {
    #[error("ephemeral submit could not be encoded")]
    Encode,
    #[error("ephemeral result could not be decoded")]
    Decode,
    #[error("ephemeral transport write failed")]
    TransportWrite,
    #[error("ephemeral transport read failed")]
    TransportRead,
}

/// One-shot wire used by [`send_ephemeral`]. Implementations must not persist frames.
pub trait EphemeralWire {
    /// # Errors
    /// Returns [`EphemeralSendError::TransportWrite`] when the frame cannot be written.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), EphemeralSendError>;
    /// # Errors
    /// Returns [`EphemeralSendError::TransportRead`] when no result frame is available.
    fn recv_frame(&mut self) -> Result<Vec<u8>, EphemeralSendError>;
}

#[derive(Serialize)]
struct EphemeralSubmitFrame<'a> {
    frame_type: &'static str,
    submit: EphemeralSubmitBody<'a>,
}

#[derive(Serialize)]
struct EphemeralSubmitBody<'a> {
    envelope: &'a Envelope,
}

#[derive(Deserialize)]
struct EphemeralResultFrame {
    frame_type: String,
    envelope_id: String,
    #[serde(flatten)]
    result: EphemeralSubmitResult,
}

/// D5: both echoed capabilities are required before a frame may be written.
#[must_use]
pub fn echo_holds_ephemeral_send(capabilities: &[String]) -> bool {
    let push = GATEWAY_SESSION_PUSH_CAPABILITY;
    let ephemeral = GATEWAY_EPHEMERAL_CAPABILITY;
    capabilities.iter().any(|capability| capability == push)
        && capabilities.iter().any(|capability| capability == ephemeral)
}

/// Encodes the C→G ephemeral submit frame (`frame_type=submit`, envelope body).
///
/// # Errors
/// Returns [`EphemeralSendError::Encode`] when JSON serialisation fails.
pub fn encode_ephemeral_submit(envelope: &Envelope) -> Result<Vec<u8>, EphemeralSendError> {
    serde_json::to_vec(&EphemeralSubmitFrame {
        frame_type: "submit",
        submit: EphemeralSubmitBody { envelope },
    })
    .map_err(|_| EphemeralSendError::Encode)
}

/// Decodes a G→C `ephemeral_result` into a typed send outcome.
///
/// # Errors
/// Returns [`EphemeralSendError::Decode`] when the bytes are not a valid result frame.
pub fn decode_ephemeral_result(bytes: &[u8]) -> Result<EphemeralSendOutcome, EphemeralSendError> {
    let frame: EphemeralResultFrame =
        parse_i_json(bytes).map_err(|_| EphemeralSendError::Decode)?;
    if frame.frame_type != "ephemeral_result" || frame.envelope_id.is_empty() {
        return Err(EphemeralSendError::Decode);
    }
    Ok(map_submit_result(frame.result))
}

/// Validates D1, applies D5, writes at most one submit frame, and maps the result.
///
/// # Errors
/// Returns a transport or codec error only after D1 and D5 have accepted the send.
pub fn send_ephemeral<W: EphemeralWire>(
    envelope: &Envelope,
    echo_capabilities: &[String],
    now_ms: u64,
    wire: &mut W,
) -> Result<EphemeralSendOutcome, EphemeralSendError> {
    if let Err(error) = deadline(envelope, now_ms) {
        return Ok(EphemeralSendOutcome::Invalid(error));
    }
    if !echo_holds_ephemeral_send(echo_capabilities) {
        return Ok(EphemeralSendOutcome::Unsupported);
    }
    let frame = encode_ephemeral_submit(envelope)?;
    wire.send_frame(&frame)?;
    decode_ephemeral_result(&wire.recv_frame()?)
}

fn map_submit_result(result: EphemeralSubmitResult) -> EphemeralSendOutcome {
    match (result.outcome(), result.reason()) {
        (EphemeralSubmitOutcome::Accepted, None) => EphemeralSendOutcome::Delivered,
        (EphemeralSubmitOutcome::Dropped, Some(EphemeralDropReason::Invalid) | None)
        | (EphemeralSubmitOutcome::Accepted, Some(_)) => {
            EphemeralSendOutcome::Invalid(EphemeralModeError::InvalidDeliveryMode)
        }
        (
            EphemeralSubmitOutcome::Dropped,
            Some(EphemeralDropReason::Unsupported | EphemeralDropReason::RecipientUnsupported),
        ) => EphemeralSendOutcome::Unsupported,
        (EphemeralSubmitOutcome::Dropped, Some(EphemeralDropReason::RateLimited)) => {
            EphemeralSendOutcome::RateLimited
        }
        (EphemeralSubmitOutcome::Dropped, Some(EphemeralDropReason::Replayed)) => {
            EphemeralSendOutcome::Replayed
        }
        (EphemeralSubmitOutcome::Dropped, Some(reason)) => EphemeralSendOutcome::Dropped(reason),
    }
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod send_tests;
