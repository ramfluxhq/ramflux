// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Negotiated client frames. A frame can only be built through a validating constructor: the
//! wire enum and the field holding it are private to this module, so no other module can
//! construct, mutate or destructure one, and every frame that exists can be encoded.

// Dormant: the first caller arrives with the capable operations of later parts.
#![allow(dead_code)]

use super::IncarnationId;
use crate::gateway::GatewayResumeFrame;
use serde::Serialize;

/// Why a client frame could not be built. Each alternative has its own refusal row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientFrameError {
    InvalidIncarnation,
    ResumeLimitZero,
    FetchSeqZero,
    BatchLength,
    BatchZeroSeq,
    BatchOrder,
}

/// The wire shape, in node-core field order. Private: see the module documentation.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "frame_type", rename_all = "snake_case")]
enum Wire {
    Resume { resume: GatewayResumeFrame, incarnation_id: IncarnationId },
    FetchEntry { incarnation_id: IncarnationId, inbox_seq: u64 },
    AckBatch { incarnation_id: IncarnationId, inbox_seqs: Vec<u64> },
    Ack { incarnation_id: IncarnationId, ack: ramflux_protocol::Ack },
    Nack { incarnation_id: IncarnationId, nack: ramflux_protocol::Nack },
}

/// One negotiated client frame. The constructors are the only way to build one, so every
/// frame the gateway would refuse locally is refused before any write.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub(crate) struct CapableClientFrame {
    wire: Wire,
}

/// Largest `ack_batch` the gateway accepts.
const MAX_ACK_BATCH: usize = 64;

fn incarnation(id: &str) -> Result<IncarnationId, ClientFrameError> {
    IncarnationId::try_from(id.to_owned()).map_err(|_| ClientFrameError::InvalidIncarnation)
}

impl CapableClientFrame {
    /// # Errors
    /// Refuses a malformed incarnation or a zero `limit` (the gateway nacks `invalid_limit`).
    pub(crate) fn resume(id: &str, resume: GatewayResumeFrame) -> Result<Self, ClientFrameError> {
        let incarnation_id = incarnation(id)?;
        if resume.limit == 0 {
            return Err(ClientFrameError::ResumeLimitZero);
        }
        Ok(Self { wire: Wire::Resume { resume, incarnation_id } })
    }

    /// # Errors
    /// Refuses a malformed incarnation or `inbox_seq == 0`.
    pub(crate) fn fetch_entry(id: &str, inbox_seq: u64) -> Result<Self, ClientFrameError> {
        let incarnation_id = incarnation(id)?;
        if inbox_seq == 0 {
            return Err(ClientFrameError::FetchSeqZero);
        }
        Ok(Self { wire: Wire::FetchEntry { incarnation_id, inbox_seq } })
    }

    /// # Errors
    /// Refuses a malformed incarnation, a batch outside `1..=64`, a zero element and any
    /// element that is not strictly greater than its predecessor (the gateway predicate).
    pub(crate) fn ack_batch(id: &str, inbox_seqs: Vec<u64>) -> Result<Self, ClientFrameError> {
        let incarnation_id = incarnation(id)?;
        if inbox_seqs.is_empty() || inbox_seqs.len() > MAX_ACK_BATCH {
            return Err(ClientFrameError::BatchLength);
        }
        if inbox_seqs.contains(&0) {
            return Err(ClientFrameError::BatchZeroSeq);
        }
        if inbox_seqs.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ClientFrameError::BatchOrder);
        }
        Ok(Self { wire: Wire::AckBatch { incarnation_id, inbox_seqs } })
    }

    /// # Errors
    /// Refuses a malformed incarnation.
    pub(crate) fn ack(id: &str, ack: ramflux_protocol::Ack) -> Result<Self, ClientFrameError> {
        Ok(Self { wire: Wire::Ack { incarnation_id: incarnation(id)?, ack } })
    }

    /// # Errors
    /// Refuses a malformed incarnation.
    pub(crate) fn nack(id: &str, nack: ramflux_protocol::Nack) -> Result<Self, ClientFrameError> {
        Ok(Self { wire: Wire::Nack { incarnation_id: incarnation(id)?, nack } })
    }

    /// Encodes the frame exactly as the wire carries it.
    ///
    /// # Errors
    /// Returns the serializer error.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.wire)
    }
}
