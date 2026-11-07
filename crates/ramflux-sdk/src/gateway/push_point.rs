// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Point reads, batch ACKs and the single-ACK adapter on a negotiated session.

// Dormant: `fetch_entry` and `ack_batch` get their first callers in later parts.
#![allow(dead_code)]

use super::host_frames::{Step, Wait};
use super::session_push::{
    AckResult, CapableClientFrame, CapableServerFrame, ClientFrameError, EntryGoneReason,
    PageEntryRecord, PushNackReason, SessionMode,
};
use super::{GatewayCursor, GatewaySessionEngine};
use crate::SdkError;

/// What the gateway answered to one `fetch_entry`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PointReply {
    Entry(Box<PageEntryRecord>),
    TooLarge {
        retain_until: i64,
    },
    Gone {
        observed_issued_inbox_seq: u64,
        reason: EntryGoneReason,
    },
    /// A refusal keyed to this session's incarnation. The session stays usable.
    Refused(PushNackReason),
}

/// What the gateway answered to one `ack_batch`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BatchReply {
    Done { cursor: GatewayCursor, results: Vec<AckResult> },
    Refused(PushNackReason),
}

fn local_refusal(what: &str, why: &str) -> SdkError {
    SdkError::GatewaySessionRejected(format!("{what} refused locally: {why}"))
}

fn client_error(what: &str, error: ClientFrameError) -> SdkError {
    local_refusal(
        what,
        match error {
            ClientFrameError::InvalidIncarnation => "the incarnation is malformed",
            ClientFrameError::ResumeLimitZero => "the limit is zero",
            ClientFrameError::FetchSeqZero => "the sequence is zero",
            ClientFrameError::BatchLength => "the batch length is outside 1..=64",
            ClientFrameError::BatchZeroSeq => "a batch sequence is zero",
            ClientFrameError::BatchOrder => "the batch is not strictly ascending",
        },
    )
}

impl GatewaySessionEngine {
    fn incarnation_of(&self, what: &str) -> Result<String, SdkError> {
        match &self.mode {
            SessionMode::Push { incarnation } => Ok(incarnation.as_str().to_owned()),
            _ => Err(local_refusal(what, "the session is not negotiated")),
        }
    }

    /// Reads the one capable reply of a point, batch or single-ACK wait.
    async fn read_point_reply(
        &mut self,
        operation: &'static str,
        wait: Wait,
    ) -> Result<Result<CapableServerFrame, PushNackReason>, SdkError> {
        loop {
            match self.read_step(operation, wait).await? {
                Step::Reply(reply) => return Ok(Ok(*reply)),
                Step::Refused(reason) => return Ok(Err(reason)),
                Step::Legacy(frame) => {
                    // Events are handled by the dispatcher; a legacy reply of any kind
                    // retires the session.
                    self.dispatch_frame(&frame, None)?;
                }
                Step::SubmitAccepted(_) | Step::ResumePage(_) => {
                    return Err(
                        self.retire("unexpected capable reply while awaiting a point reply")
                    );
                }
            }
        }
    }

    fn check_incarnation(
        &mut self,
        id: &super::session_push::IncarnationId,
    ) -> Result<(), SdkError> {
        match &self.mode {
            SessionMode::Push { incarnation } if incarnation == id => Ok(()),
            _ => Err(self.retire("reply with a foreign incarnation")),
        }
    }

    /// Reads one inbox entry by sequence on a negotiated session.
    ///
    /// # Errors
    /// Refuses locally, before any write, on a session that is not negotiated or for
    /// `seq == 0`. Otherwise returns an error when the session is retired or the transport
    /// fails.
    pub(crate) async fn fetch_entry(&mut self, seq: u64) -> Result<PointReply, SdkError> {
        let id = self.incarnation_of("fetch_entry")?;
        let frame = CapableClientFrame::fetch_entry(&id, seq)
            .map_err(|error| client_error("fetch_entry", error))?;
        self.write_capable_frame(&frame).await?;
        let reply = match self.read_point_reply("fetch entry", Wait::Fetch).await? {
            Ok(reply) => reply,
            Err(reason) => return Ok(PointReply::Refused(reason)),
        };
        match reply {
            CapableServerFrame::Entry { incarnation_id, record } => {
                self.check_incarnation(&incarnation_id)?;
                if record.entry.inbox_seq != seq {
                    return Err(self.retire("entry for a different sequence"));
                }
                if record.entry.target_delivery_id != self.config.target_delivery_id {
                    return Err(self.retire("entry for a different target"));
                }
                Ok(PointReply::Entry(record))
            }
            CapableServerFrame::EntryTooLarge { incarnation_id, inbox_seq, retain_until } => {
                self.check_incarnation(&incarnation_id)?;
                if inbox_seq != seq {
                    return Err(self.retire("entry_too_large for a different sequence"));
                }
                Ok(PointReply::TooLarge { retain_until })
            }
            CapableServerFrame::EntryGone {
                incarnation_id,
                inbox_seq,
                observed_issued_inbox_seq,
                reason,
            } => {
                self.check_incarnation(&incarnation_id)?;
                if inbox_seq != seq {
                    return Err(self.retire("entry_gone for a different sequence"));
                }
                if observed_issued_inbox_seq < seq {
                    return Err(self.retire("entry_gone observed below the requested sequence"));
                }
                Ok(PointReply::Gone { observed_issued_inbox_seq, reason })
            }
            _ => Err(self.retire("unexpected capable reply while awaiting a point reply")),
        }
    }

    /// Acknowledges a batch of sequences on a negotiated session.
    ///
    /// # Errors
    /// Refuses locally, before any write, on a session that is not negotiated or for a batch
    /// outside `1..=64` ascending non-zero sequences. Otherwise returns an error when the
    /// session is retired or the transport fails.
    pub(crate) async fn ack_batch(&mut self, seqs: Vec<u64>) -> Result<BatchReply, SdkError> {
        let id = self.incarnation_of("ack_batch")?;
        let frame = CapableClientFrame::ack_batch(&id, seqs.clone())
            .map_err(|error| client_error("ack_batch", error))?;
        self.write_capable_frame(&frame).await?;
        let reply = match self.read_point_reply("ack batch", Wait::AckBatch).await? {
            Ok(reply) => reply,
            Err(reason) => return Ok(BatchReply::Refused(reason)),
        };
        let CapableServerFrame::AckBatch { incarnation_id, cursor, results } = reply else {
            return Err(self.retire("unexpected capable reply while awaiting a point reply"));
        };
        self.check_incarnation(&incarnation_id)?;
        if cursor.target_delivery_id != self.config.target_delivery_id {
            return Err(self.retire("ack_batch cursor for a different target"));
        }
        if results.len() != seqs.len()
            || results.iter().zip(&seqs).any(|(result, seq)| result.inbox_seq != *seq)
        {
            return Err(self.retire("ack_batch results do not match the requested sequences"));
        }
        Ok(BatchReply::Done { cursor, results })
    }

    /// `ack()` on a negotiated session: one capable `ack`, answered by one capable `ack`.
    pub(crate) async fn push_ack(
        &mut self,
        ack: ramflux_protocol::Ack,
    ) -> Result<GatewayCursor, SdkError> {
        let id = self.incarnation_of("ack")?;
        let frame =
            CapableClientFrame::ack(&id, ack).map_err(|error| client_error("ack", error))?;
        self.write_capable_frame(&frame).await?;
        let reply = match self.read_point_reply("ack", Wait::Ack).await? {
            Ok(reply) => reply,
            Err(reason) => {
                return Err(SdkError::GatewaySessionRejected(reason.as_str().to_owned()));
            }
        };
        let CapableServerFrame::Ack { incarnation_id, cursor } = reply else {
            return Err(self.retire("unexpected capable reply while awaiting a point reply"));
        };
        self.check_incarnation(&incarnation_id)?;
        if cursor.target_delivery_id != self.config.target_delivery_id {
            return Err(self.retire("ack cursor for a different target"));
        }
        self.config.last_seen_inbox_seq = cursor.inbox_seq;
        Ok(cursor)
    }
}
