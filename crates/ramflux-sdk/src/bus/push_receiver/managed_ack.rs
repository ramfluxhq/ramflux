// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Managed public ACK (`message.ack` / `rf dm ack`) refuses before engine, mark, or delete.

use crate::bus::protocol::LocalBusMessageAckRequest;
use crate::prelude::*;

/// Stable bus / [`SdkError`] code for a managed-ledger public ACK.
pub(crate) const MANAGED_ACK_CODE: &str = "receive_ledger_managed_ack";

/// Preserves the public request shape and returns a typed refusal.
/// Does not acquire an engine, send a wire ACK, mark local acknowledgement, or delete holds.
///
/// # Errors
/// Always [`SdkError::InboundRejected`] with [`MANAGED_ACK_CODE`].
pub(crate) fn managed_public_ack(request: &LocalBusMessageAckRequest) -> Result<(), SdkError> {
    let _ =
        (request.envelope_id.as_str(), request.receiver_device_id.as_str(), request.received_at);
    Err(SdkError::InboundRejected(MANAGED_ACK_CODE.to_owned()))
}
