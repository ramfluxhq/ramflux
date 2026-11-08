// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant SDK ephemeral submit codec, D1 validation, and D5 local unsupported.

use ramflux_protocol::ephemeral::{
    EphemeralDropReason, EphemeralModeError, EphemeralSubmitResult, GATEWAY_EPHEMERAL_CAPABILITY,
    deadline,
};
use ramflux_protocol::{Envelope, GATEWAY_SESSION_PUSH_CAPABILITY, SignedRequest, parse_i_json};

use crate::{GatewayClientFrame, GatewayServerFrame, GatewaySubmitFrame};

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
    #[error("ephemeral result envelope_id did not match the submit")]
    ResultMismatch,
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

/// D5: both echoed capabilities are required before a frame may be written.
#[must_use]
pub fn echo_holds_ephemeral_send(capabilities: &[String]) -> bool {
    let push = GATEWAY_SESSION_PUSH_CAPABILITY;
    let ephemeral = GATEWAY_EPHEMERAL_CAPABILITY;
    capabilities.iter().any(|capability| capability == push)
        && capabilities.iter().any(|capability| capability == ephemeral)
}

/// Encodes the C→G submit with the S6b P11 codec (`GatewayClientFrame::Submit`).
///
/// # Errors
/// Returns [`EphemeralSendError::Encode`] when JSON serialisation fails.
pub fn encode_ephemeral_submit(
    signed_request: &SignedRequest,
    envelope: &Envelope,
) -> Result<Vec<u8>, EphemeralSendError> {
    serde_json::to_vec(&GatewayClientFrame::Submit {
        submit: GatewaySubmitFrame {
            signed_request: signed_request.clone(),
            envelope: envelope.clone(),
        },
    })
    .map_err(|_| EphemeralSendError::Encode)
}

/// Decodes a G→C `ephemeral_result` with the P11 server codec and matches `envelope_id`.
///
/// # Errors
/// Returns [`EphemeralSendError::Decode`] when the bytes are not a result frame, or
/// [`EphemeralSendError::ResultMismatch`] when `envelope_id` differs from the submit.
pub fn decode_ephemeral_result(
    bytes: &[u8],
    envelope_id: &str,
) -> Result<EphemeralSendOutcome, EphemeralSendError> {
    match parse_i_json(bytes).map_err(|_| EphemeralSendError::Decode)? {
        GatewayServerFrame::EphemeralResult { envelope_id: result_id, result }
            if result_id == envelope_id =>
        {
            Ok(map_submit_result(result))
        }
        GatewayServerFrame::EphemeralResult { envelope_id: result_id, .. }
            if !result_id.is_empty() =>
        {
            Err(EphemeralSendError::ResultMismatch)
        }
        _ => Err(EphemeralSendError::Decode),
    }
}

/// Validates D1, applies D5, writes at most one submit frame, and maps the result.
///
/// # Errors
/// Returns a transport or codec error only after D1 and D5 have accepted the send.
pub fn send_ephemeral<W: EphemeralWire>(
    signed_request: &SignedRequest,
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
    let frame = encode_ephemeral_submit(signed_request, envelope)?;
    wire.send_frame(&frame)?;
    decode_ephemeral_result(&wire.recv_frame()?, &envelope.envelope_id)
}

fn map_submit_result(result: EphemeralSubmitResult) -> EphemeralSendOutcome {
    match result.reason() {
        None => EphemeralSendOutcome::Delivered,
        Some(EphemeralDropReason::Invalid) => {
            EphemeralSendOutcome::Invalid(EphemeralModeError::InvalidDeliveryMode)
        }
        Some(EphemeralDropReason::Unsupported | EphemeralDropReason::RecipientUnsupported) => {
            EphemeralSendOutcome::Unsupported
        }
        Some(EphemeralDropReason::RateLimited) => EphemeralSendOutcome::RateLimited,
        Some(EphemeralDropReason::Replayed) => EphemeralSendOutcome::Replayed,
        Some(reason) => EphemeralSendOutcome::Dropped(reason),
    }
}

#[cfg(test)]
#[path = "send_tests.rs"]
mod send_tests;
