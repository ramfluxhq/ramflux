// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant compatibility executor (S6b P18). No production caller reaches these
//! entry points: live receive still uses the legacy Resume/ACK path. P20/P21 wire
//! `admit_in` onto the actor W1/W2 and WA. Sequence equality alone never authorizes
//! a legacy ACK. Clock values are injected; tests never wait on the wall clock.
#![allow(dead_code)]

use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveExpectation,
    ReceiveStage, ReceiveStageResult, ReceiveTransaction, StorageError,
};

/// Authoritative compat lookup is always `Resume(after=s-1, limit=1)`.
pub(crate) const LOOKUP_LIMIT: u32 = 1;
/// Bounded intent scan per actor/network turn; an ordinary call runs between intents.
pub(crate) const TURN_INTENTS: u32 = 16;
/// Compat sweep interval in seconds.
pub(crate) const SWEEP_SECS: i64 = 5;
/// Normal compat Resume starts at 64 entries.
pub(crate) const FRAME_LIMIT_INITIAL: u32 = 64;
/// Sticky per-connection retry after a frame-size failure.
pub(crate) const FRAME_LIMIT_FALLBACK: u32 = 1;
/// Serialized JSON byte cap F (design §5).
pub(crate) const FRAME_MAX_BYTES: usize = 1_048_576;
/// Assumed maximum client lag behind router time for the conservative deadline.
pub(crate) const CLOCK_SKEW_SECS: i64 = 120;
const TTL_CAP_SECS: i64 = 604_800;
const SUSPEND: &str = "gateway/compat-suspended/";

/// Envelope identity already on the registered work copy. No extra plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentProof {
    pub envelope_id: String,
    pub payload_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckDecision {
    Authorize,
    Suspend,
    RefuseSequenceAlone,
    SettleAbsent,
    RetainBackoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FallbackDeadline {
    pub expires_at: i64,
    pub fallback_clock_unverified: bool,
    pub guaranteed_retirement: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompatSession {
    pub limit: u32,
    pub paused_reason: Option<&'static str>,
    pub reconnects: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameOutcome {
    Accept { limit: u32 },
    RetryFresh { limit: u32 },
    Pause { reason: &'static str },
}

/// One exact (T,s) lookup reply. The executor never calls normal receive or moves C.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LookupReply<'a> {
    Entry { seq: u64, envelope_id: &'a str, payload_hash: &'a str, incarnation: Option<&'a str> },
    Empty { first_seq: Option<u64> },
    FrameTooLarge { bytes: usize, entries: u32 },
    Timeout,
}

pub(crate) struct CompatExecutor<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

pub(crate) struct AdmitRequest {
    pub sequence: u64,
    pub now: i64,
}

impl CompatExecutor<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// W0 must already be open. W1 is the caller's effect; this W2 writes the compat
    /// terminal intent and keeps the registered work as the equality proof.
    #[allow(clippy::unused_self)]
    pub(crate) fn admit_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        request: &AdmitRequest,
    ) -> Result<ReceiveCoverResult, SdkError> {
        tx.require_writer()?;
        tx.require_open_input(request.sequence)?;
        let result = tx.cover_at(
            ReceiveCover {
                sequence: request.sequence,
                kind: ReceiveCoverKind::CompatTerminal,
                gaps: &[],
                retain_until: 0,
            },
            request.now,
        )?;
        before_commit_fault()?;
        Ok(result)
    }

    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        request: &AdmitRequest,
    ) -> Result<ReceiveCoverResult, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            let result = self.admit_in(tx, request);
            let failed = result.is_err();
            outcome = Some(result);
            if failed {
                return Err(StorageError::Integrity("source effect failed"));
            }
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("compat admit did not run".into())),
        }
    }
}

fn suspend_key(target: &str, incarnation: &str, sequence: u64) -> String {
    format!("{SUSPEND}{target}/{incarnation}/{sequence}")
}

fn add_ts(base: i64, delta: i64) -> Result<i64, SdkError> {
    base.checked_add(delta).ok_or_else(|| SdkError::LocalBus("compat timestamp overflow".into()))
}

/// Conservative `retain_until` when the old node omitted the router deadline (§2.3).
/// Clock lag is local receive time minus router acceptance time.
pub(crate) fn fallback_deadline(
    router_accepted_at: i64,
    envelope_ttl: i64,
    first_seen: i64,
    router_retain: Option<i64>,
) -> Result<FallbackDeadline, SdkError> {
    if let Some(expires_at) = router_retain {
        return Ok(FallbackDeadline {
            expires_at,
            fallback_clock_unverified: false,
            guaranteed_retirement: true,
        });
    }
    let ttl_cap = envelope_ttl.clamp(0, TTL_CAP_SECS);
    let router_cap = add_ts(router_accepted_at, ttl_cap)?;
    let from_seen = add_ts(add_ts(first_seen, TTL_CAP_SECS)?, CLOCK_SKEW_SECS)?;
    let expires_at = router_cap.min(from_seen);
    let lag = router_accepted_at
        .checked_sub(first_seen)
        .ok_or_else(|| SdkError::LocalBus("compat timestamp overflow".into()))?;
    let unverified = lag > CLOCK_SKEW_SECS;
    Ok(FallbackDeadline {
        expires_at,
        fallback_clock_unverified: unverified,
        guaranteed_retirement: !unverified && expires_at >= router_cap,
    })
}

pub(crate) fn start_session() -> CompatSession {
    CompatSession { limit: FRAME_LIMIT_INITIAL, paused_reason: None, reconnects: 0 }
}

/// Frame-size fallback: 64 → retire session → sticky limit 1. A single entry still
/// over F pauses with `legacy_entry_too_large` and does not reconnect. Limit-1 with
/// more than one entry is a protocol error and blocks later Accept.
pub(crate) fn on_legacy_frame(
    session: &mut CompatSession,
    bytes: usize,
    entries: u32,
    _cursor: u64,
) -> FrameOutcome {
    if let Some(reason) = session.paused_reason {
        return FrameOutcome::Pause { reason };
    }
    if session.limit == FRAME_LIMIT_FALLBACK && entries > 1 {
        session.paused_reason = Some("legacy_frame_protocol");
        return FrameOutcome::Pause { reason: "legacy_frame_protocol" };
    }
    if bytes <= FRAME_MAX_BYTES {
        return FrameOutcome::Accept { limit: session.limit };
    }
    if session.limit == FRAME_LIMIT_INITIAL {
        session.reconnects = session.reconnects.saturating_add(1);
        session.limit = FRAME_LIMIT_FALLBACK;
        return FrameOutcome::RetryFresh { limit: FRAME_LIMIT_FALLBACK };
    }
    if entries <= 1 {
        session.paused_reason = Some("legacy_entry_too_large");
        return FrameOutcome::Pause { reason: "legacy_entry_too_large" };
    }
    session.paused_reason = Some("legacy_frame_protocol");
    FrameOutcome::Pause { reason: "legacy_frame_protocol" }
}

/// Proof-gated legacy ACK. Sequence equality alone never authorizes.
pub(crate) fn authorize_legacy_ack(
    db: &AccountDb,
    target: &str,
    incarnation: &str,
    sequence: u64,
    capable_e: Option<&str>,
    lookup: &LookupReply<'_>,
) -> Result<AckDecision, SdkError> {
    if sequence_alone() {
        return Ok(AckDecision::Authorize);
    }
    let local = load_proof(db, target, incarnation, sequence)?;
    match lookup {
        LookupReply::Timeout | LookupReply::FrameTooLarge { .. } => Ok(AckDecision::RetainBackoff),
        LookupReply::Empty { first_seq } => {
            let first_after = first_seq.is_none_or(|first| first > sequence);
            if first_after && (local.is_some() || capable_e == Some(incarnation)) {
                Ok(AckDecision::SettleAbsent)
            } else if local.is_none() && capable_e.is_none() {
                suspend(db, target, incarnation, sequence)?;
                Ok(AckDecision::Suspend)
            } else {
                Ok(AckDecision::RetainBackoff)
            }
        }
        LookupReply::Entry { seq, envelope_id, payload_hash, incarnation: reply_e } => {
            if *seq != sequence {
                return Ok(AckDecision::RetainBackoff);
            }
            let e_ok =
                capable_e == Some(incarnation) || reply_e.is_some_and(|got| got == incarnation);
            match local {
                Some(proof)
                    if proof.envelope_id == *envelope_id && proof.payload_hash == *payload_hash =>
                {
                    Ok(AckDecision::Authorize)
                }
                Some(_) => Ok(AckDecision::RefuseSequenceAlone),
                None if e_ok => Ok(AckDecision::Authorize),
                None => {
                    suspend(db, target, incarnation, sequence)?;
                    Ok(AckDecision::Suspend)
                }
            }
        }
    }
}

fn load_proof(
    db: &AccountDb,
    target: &str,
    incarnation: &str,
    sequence: u64,
) -> Result<Option<ContentProof>, SdkError> {
    match db.receive_work_content_proof(target, incarnation, sequence)? {
        Some((envelope_id, payload_hash)) => Ok(Some(ContentProof { envelope_id, payload_hash })),
        None => Ok(None),
    }
}

fn suspend(db: &AccountDb, target: &str, incarnation: &str, sequence: u64) -> Result<(), SdkError> {
    db.persist_actor_state(&suspend_key(target, incarnation, sequence), &"incarnation_unverified")?;
    Ok(())
}

/// Same-E capable reconnection clears the unverified suspend marker.
pub(crate) fn resume_same_e(
    db: &AccountDb,
    target: &str,
    incarnation: &str,
    sequence: u64,
) -> Result<(), SdkError> {
    db.remove_actor_state(&suspend_key(target, incarnation, sequence))?;
    Ok(())
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("compat before-commit"));
    }
    Ok(())
}

fn sequence_alone() -> bool {
    matches!(current_fault(), Fault::SequenceAlone)
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    BeforeCommit,
    SequenceAlone,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: Fault, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|cell| cell.set(Fault::None));
        }
    }
    FAULT.with(|cell| cell.set(fault));
    let _reset = Reset;
    f()
}

#[cfg(test)]
#[path = "compat_tests.rs"]
mod compat_tests;
