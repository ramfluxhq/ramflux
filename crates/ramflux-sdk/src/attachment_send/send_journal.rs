// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable record of one `conversation.send` operation that carries prepared attachments.
//!
//! The record lives at `conversation-send/<operation-hash>` (the namespace retention and
//! capacity already bound). It carries the phase so a send parked off the account actor can
//! be resumed or reported after a restart. Private request content is never stored here.

use serde::{Deserialize, Serialize};

/// Where the operation stands. Transitions only move forward, except a retryable failure,
/// which leaves the record Pending in its last durable phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SendPhase {
    /// Admitted and fingerprinted; no prepare has been claimed yet.
    #[default]
    Reserved,
    /// Prepares are claimed and the roster is planned.
    Preparing,
    /// The upload worker owns the sealed ciphertext; the actor is free meanwhile.
    Uploading,
    /// Grants are being wrapped for the planned targets.
    Wrapping,
    /// The final content is frozen and delivery has started.
    Delivering,
    /// Delivered and completed; the stored result replays.
    Sent,
}

/// The durable send receipt. Completion is set only after delivery is recorded.
#[derive(Serialize, Deserialize)]
pub(crate) struct SendRecord {
    pub(crate) fingerprint: String,
    pub(crate) expires_at: i64,
    #[serde(default)]
    pub(crate) completed: bool,
    #[serde(default)]
    pub(crate) completed_at: Option<i64>,
    #[serde(default)]
    pub(crate) phase: SendPhase,
}

impl SendRecord {
    /// A newly admitted record, before any prepare is claimed.
    pub(crate) fn admitted(fingerprint: String, expires_at: i64) -> Self {
        Self {
            fingerprint,
            expires_at,
            completed: false,
            completed_at: None,
            phase: SendPhase::Reserved,
        }
    }
}

/// Actor-state key for one operation: the operation id is hashed so the key is bounded.
pub(crate) fn key(operation: &str) -> String {
    format!(
        "conversation-send/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.conversation.send.operation.v1",
            operation.as_bytes()
        )
    )
}
