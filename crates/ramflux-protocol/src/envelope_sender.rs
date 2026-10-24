// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sender authentication preserves identity claims while excluding appended public node metadata.
use crate::{Envelope, ProtocolError};
/// Canonical sender-signed envelope bytes, retaining the root claim and all sender metadata.
/// # Errors
/// Returns canonical JSON errors.
pub fn envelope_sender_signed_bytes(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    let mut sender = envelope.clone();
    // Forwarders attach existing root-signed device-set evidence. Its independent signatures
    // authenticate the same root and branch; this never removes the sender's signed root claim.
    sender.ext.ext.remove("source_device_authority");
    if let Some(receipt) =
        sender.ext.ext.get_mut("franking").and_then(serde_json::Value::as_object_mut)
    {
        for field in ["franking_tag", "node_id", "accepted_at"] {
            receipt.remove(field);
        }
    }
    crate::signed_bytes(&sender)
}
