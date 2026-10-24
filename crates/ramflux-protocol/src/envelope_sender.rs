// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender authentication excludes only the gateway's appended franking receipt fields.
use crate::{Envelope, ProtocolError};
/// Canonical sender-signed envelope bytes, retaining the root claim and all sender metadata.
/// # Errors
/// Returns canonical JSON errors.
pub fn envelope_sender_signed_bytes(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    let mut sender = envelope.clone();
    if let Some(receipt) =
        sender.ext.ext.get_mut("franking").and_then(serde_json::Value::as_object_mut)
    {
        for field in ["franking_tag", "node_id", "accepted_at"] {
            receipt.remove(field);
        }
    }
    crate::signed_bytes(&sender)
}
