// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incarnation-bound mesh contracts; legacy response structs stay source compatible.
use crate::{InboxCursorResponse, RouterCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum SessionPushReason {
    #[error("incarnation_mismatch")]
    IncarnationMismatch,
    #[error("invalid_seq")]
    InvalidSeq,
    #[error("invalid_limit")]
    InvalidLimit,
    #[error("cursor_ahead")]
    CursorAhead,
    #[error("payload_too_large")]
    PayloadTooLarge,
    #[error("busy")]
    Busy,
    #[error("internal_error")]
    InternalError,
}
#[derive(Debug, Serialize, thiserror::Error)]
#[error("{reason}")]
pub struct SessionPushError {
    pub reason: SessionPushReason,
    pub incarnation_id: Option<String>,
}
impl SessionPushError {
    #[must_use]
    pub fn new(reason: SessionPushReason, incarnation_id: Option<String>) -> Self {
        Self { reason, incarnation_id }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAckBatchRequest {
    pub target_delivery_id: String,
    pub incarnation_id: String,
    pub inbox_seqs: Vec<u64>,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionAckOutcome {
    Acked,
    AlreadySettled,
    NotFound,
    InvalidSeq,
    Rejected,
}
#[derive(Debug, Serialize)]
pub struct SessionAckResult {
    pub inbox_seq: u64,
    pub outcome: SessionAckOutcome,
    pub reason: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct SessionAckBatchResponse {
    pub incarnation_id: String,
    pub cursor: InboxCursorResponse,
    pub results: Vec<SessionAckResult>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedSeqsRequest {
    pub targets: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct IssuedSeq {
    pub target_delivery_id: String,
    pub incarnation_id: Option<String>,
    pub inbox_seq: u64,
}
#[derive(Debug, Serialize)]
pub struct IssuedSeqsResponse {
    pub issued: Vec<IssuedSeq>,
}
#[derive(Debug, Serialize)]
pub struct SessionPushCapabilities {
    pub capabilities: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct SessionPushSubmitResponse {
    #[serde(flatten)]
    pub delivery: crate::EnvelopeSubmitResponse,
    pub incarnation_id: Option<String>,
    pub retain_until: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct SessionPushFanoutDelivery {
    #[serde(flatten)]
    pub delivery: crate::ItestMvp10OwnDeviceFanoutDelivery,
    pub incarnation_id: Option<String>,
    pub retain_until: Option<i64>,
}
#[derive(Debug, Serialize)]
pub struct SessionPushFanoutResponse {
    pub principal_id: String,
    pub source_device_id: String,
    pub delivered: Vec<SessionPushFanoutDelivery>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionPushForwardOutcome {
    Queued,
    Overflowed,
    NoSession,
    Full,
    Unsupported,
    Expired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionPushForwardResponse {
    pub delivered: bool,
    pub outcome: Option<SessionPushForwardOutcome>,
}

#[derive(Deserialize)]
struct ForwardReplyWire {
    delivered: bool,
    #[serde(default)]
    outcome: Option<SessionPushForwardOutcome>,
}
impl<'de> Deserialize<'de> for SessionPushForwardResponse {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let wire = ForwardReplyWire::deserialize(decoder)?;
        if let Some(outcome) = wire.outcome {
            let handled = matches!(
                outcome,
                SessionPushForwardOutcome::Queued | SessionPushForwardOutcome::Overflowed
            );
            if wire.delivered != handled {
                return Err(serde::de::Error::custom("forward delivered/outcome mismatch"));
            }
        }
        Ok(Self { delivered: wire.delivered, outcome: wire.outcome })
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionPushSessionRequest {
    #[serde(flatten)]
    pub session: crate::SessionDescriptor,
    pub session_push: bool,
    #[serde(default)]
    pub ephemeral: bool,
}
#[derive(Debug, Serialize)]
pub struct SessionPushSessionResponse {
    #[serde(flatten)]
    pub session: crate::SessionDescriptor,
    pub incarnation_id: String,
}

impl RouterCore {
    /// Snapshot a published watermark without creating an inbox.
    #[must_use]
    pub fn session_push_status(&self, target: &str) -> IssuedSeq {
        let shard = self.target_shard(target);
        IssuedSeq {
            target_delivery_id: target.into(),
            incarnation_id: shard.inbox.incarnation_id(target).map(str::to_owned),
            inbox_seq: shard.inbox.settlement_boundary(target),
        }
    }
    /// Validate the expected namespace without changing read state.
    /// # Errors
    /// Returns the current incarnation on mismatch.
    pub fn check_inbox_incarnation(
        &self,
        target: &str,
        expected: &str,
    ) -> Result<(), SessionPushError> {
        let status = self.session_push_status(target);
        if expected.len() != 32
            || !expected.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || status.incarnation_id.as_deref() != Some(expected)
        {
            return Err(SessionPushError::new(
                SessionPushReason::IncarnationMismatch,
                status.incarnation_id,
            ));
        }
        Ok(())
    }
    /// Apply a validated sequence batch under the existing bounded settlement lease.
    /// # Errors
    /// Refuses invalid sequences, a stale incarnation, or unavailable storage before mutation.
    pub fn session_ack_batch(
        &self,
        store: &crate::RouterRedbStore,
        request: &SessionAckBatchRequest,
    ) -> Result<SessionAckBatchResponse, SessionPushError> {
        let target = &request.target_delivery_id;
        let failure =
            |reason| SessionPushError::new(reason, self.session_push_status(target).incarnation_id);
        if request.inbox_seqs.is_empty()
            || request.inbox_seqs.len() > 64
            || request.inbox_seqs.windows(2).any(|w| w[0] >= w[1])
            || request.inbox_seqs.contains(&0)
        {
            return Err(failure(SessionPushReason::InvalidSeq));
        }
        self.bind_publication(store).map_err(|_| failure(SessionPushReason::InternalError))?;
        let lease =
            store.acquire_acknowledgement(target).map_err(|_| failure(SessionPushReason::Busy))?;
        self.check_inbox_incarnation(target, &request.incarnation_id)?;
        let issued = self.session_push_status(target).inbox_seq;
        if request.inbox_seqs.iter().any(|s| *s > issued) {
            return Err(failure(SessionPushReason::InvalidSeq));
        }

        let acks = self.session_ack_members(target, &request.inbox_seqs);
        let settled = self.cursor_state(target).map_or(0, |c| c.settled_inbox_seq);
        let applied = self
            .apply_ack_batch_leased(store, target, &acks, &lease)
            .map_err(|_| failure(SessionPushReason::InternalError))?;
        let results = request
            .inbox_seqs
            .iter()
            .zip(applied)
            .map(|(&seq, result)| {
                let (outcome, reason) = match result {
                    Ok(_) => (
                        if seq <= settled {
                            SessionAckOutcome::AlreadySettled
                        } else {
                            SessionAckOutcome::Acked
                        },
                        None,
                    ),
                    Err(crate::NodeCoreError::EnvelopeNotFound(_)) => (
                        if seq <= settled {
                            SessionAckOutcome::AlreadySettled
                        } else {
                            SessionAckOutcome::NotFound
                        },
                        None,
                    ),
                    Err(crate::NodeCoreError::AckBackpressureRetry) => {
                        (SessionAckOutcome::Rejected, Some("ack_backpressure_retry".into()))
                    }
                    Err(_) => (SessionAckOutcome::Rejected, Some("invalid_seq".into())),
                };
                SessionAckResult { inbox_seq: seq, outcome, reason }
            })
            .collect();
        let cursor = self.cursor_state(target).unwrap_or_else(|| crate::CursorAckState {
            target_delivery_id: target.clone(),
            ..Default::default()
        });
        Ok(SessionAckBatchResponse {
            incarnation_id: request.incarnation_id.clone(),
            cursor: InboxCursorResponse::from(&cursor),
            results,
        })
    }
    fn session_ack_members(&self, target: &str, seqs: &[u64]) -> Vec<ramflux_protocol::Ack> {
        let shard = self.target_shard(target);
        seqs.iter()
            .map(|seq| {
                let row = shard.inbox.pending.get(target).and_then(|rows| rows.get(seq));
                let mut ext = ramflux_protocol::Ext::default();
                ext.ext.insert("inbox_seq".into(), serde_json::json!(seq));
                ramflux_protocol::Ack {
                    schema: "ramflux.ack.v1".into(),
                    version: 1,
                    domain: "ramflux.ack.v1".into(),
                    ext,
                    signed: ramflux_protocol::SignedFields {
                        signing_key_id: "router-session".into(),
                        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                        signature: String::new(),
                    },
                    ack_id: format!("session-ack-{seq}"),
                    envelope_id: row
                        .map_or_else(String::new, |row| row.envelope.envelope_id.clone()),
                    receiver_device_id: String::new(),
                    received_at: 0,
                    cursor_after: None,
                }
            })
            .collect()
    }
    /// Read the original acceptance deadline by its ordered sequence index.
    #[must_use]
    pub fn session_delivery_metadata(
        &self,
        target: &str,
        seq: u64,
    ) -> (Option<String>, Option<i64>) {
        let shard = self.target_shard(target);
        (
            shard.inbox.incarnation_id(target).map(str::to_owned),
            shard
                .inbox
                .pending
                .get(target)
                .and_then(|rows| rows.get(&seq))
                .map(|entry| shard.inbox.retain_until(entry)),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;

impl RouterCore {
    /// Persist a capable NACK under the same bounded namespace fence as ACK.
    /// # Errors
    /// Refuses invalid sequences or an old E before touching the live inbox.
    pub fn session_nack(
        &self,
        store: &crate::RouterRedbStore,
        request: &crate::TargetNackRequest,
        incarnation: &str,
    ) -> Result<crate::InboxCursorResponse, SessionPushError> {
        let target = &request.target_delivery_id;
        let failure =
            |reason| SessionPushError::new(reason, self.session_push_status(target).incarnation_id);
        self.bind_publication(store).map_err(|_| failure(SessionPushReason::InternalError))?;
        let lease =
            store.acquire_acknowledgement(target).map_err(|_| failure(SessionPushReason::Busy))?;
        self.check_inbox_incarnation(target, incarnation)?;
        let issued = self.session_push_status(target).inbox_seq;
        let seq = request.nack.ext.ext.get("inbox_seq").and_then(serde_json::Value::as_u64);
        if seq.is_none_or(|s| s == 0 || s > issued) {
            return Err(failure(SessionPushReason::InvalidSeq));
        }
        let cursor = self
            .apply_nack_for_target(target, &request.nack)
            .map_err(|_| failure(SessionPushReason::InvalidSeq))?;
        store
            .record_leased_nack(&cursor, lease)
            .map_err(|_| failure(SessionPushReason::InternalError))?;
        Ok(crate::InboxCursorResponse::from(&cursor))
    }
}
