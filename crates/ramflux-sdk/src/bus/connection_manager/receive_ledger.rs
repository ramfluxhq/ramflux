// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activated catch-up: real `resume_page` through `apply::apply_page`.

use super::super::{AccountWork, ConnectionHandle, ReceiveTurn};
use super::{
    ReceiveEntry, ReceiveTrigger, apply_entry, bind_retry_turns, catch_up_yields, entry_id,
    flush_acks,
};
use crate::SdkError;
use crate::bus::couriers::writer::Writer;
use crate::bus::push_receiver::apply::{self, ApplyLoss, ApplyOutcome, ApplyPage, ApplyPoint};
use crate::bus::push_receiver::apply_w1;
use crate::gateway::push_point::PointReply;
use crate::gateway::push_resume::{PageReply, ResumePage};
use ramflux_storage::{ACK_FLUSH_COUNT, StorageError};
use tokio::{sync::mpsc, time::Instant};

pub(super) struct LedgerCatchUp {
    pub active: bool,
    pub paused: bool,
    pub backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
}

pub(super) struct CatchUp<'a> {
    pub handle: &'a ConnectionHandle,
    pub work: &'a mpsc::Sender<AccountWork>,
    pub generation: u64,
    pub trigger: ReceiveTrigger,
    pub call_timeout: std::time::Duration,
    pub turn: ReceiveTurn,
    pub cursor: u64,
    pub backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
    pub retries: Vec<ReceiveEntry>,
    pub limit: usize,
}

pub(super) async fn catch_up_ledger(job: CatchUp<'_>) -> Result<LedgerCatchUp, SdkError> {
    let CatchUp {
        handle,
        work,
        generation,
        trigger,
        call_timeout,
        mut turn,
        mut cursor,
        mut backpressure,
        retries,
        limit,
    } = job;
    flush_acks(handle, work, generation, trigger == ReceiveTrigger::Connected, call_timeout)
        .await?;
    let mut retries: std::collections::BTreeMap<_, _> =
        retries.into_iter().map(|prepared| (entry_id(&prepared.entry), prepared)).collect();
    sync_reorder_cursor(handle, turn.cursor)?;
    let mut active = false;
    let mut paused = false;
    let mut pages = 0_u32;
    let mut applied = 0_usize;
    let writer = Writer::new(work.clone(), generation);
    loop {
        let page = resume_one(handle, cursor, limit, call_timeout).await?;
        pages = pages.saturating_add(1);
        if catch_up_yields(pages) {
            handle.note_catch_up_yield();
            tokio::task::yield_now().await;
            handle.note_catch_up_yield_resumed();
            pages = 0;
        }
        let more = page.more;
        let (next_active, next_paused, next_bp, next_applied) = drive_page(
            handle,
            work,
            &writer,
            &mut turn,
            generation,
            &page,
            &mut retries,
            call_timeout,
            backpressure,
            applied,
        )
        .await?;
        active |= next_active;
        paused |= next_paused;
        backpressure = next_bp;
        applied = next_applied;
        if paused || !more {
            break;
        }
        cursor = turn.cursor;
    }
    if !paused {
        let (next_active, next_bp) = apply_leftover(
            handle,
            work,
            &writer,
            &mut turn,
            generation,
            retries,
            call_timeout,
            backpressure,
            applied,
        )
        .await?;
        active |= next_active;
        backpressure = next_bp;
    }
    // Resync/Connected drain a remainder smaller than ACK_FLUSH_COUNT (16).
    // A Tick pass that applied work also flushes the remainder so a short inbox
    // does not wait on the 1s age rule (courier ACK hold, first-page catch-up).
    flush_acks(handle, work, generation, trigger != ReceiveTrigger::Tick || active, call_timeout)
        .await?;
    Ok(LedgerCatchUp { active, paused, backpressure })
}

#[allow(clippy::too_many_arguments, reason = "page drive shares the live handles")]
async fn drive_page(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    writer: &Writer,
    turn: &mut ReceiveTurn,
    generation: u64,
    page: &ResumePage,
    retries: &mut std::collections::BTreeMap<(String, u64, String), ReceiveEntry>,
    call_timeout: std::time::Duration,
    mut backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
    mut applied: usize,
) -> Result<(bool, bool, Box<crate::bus::contact_backpressure::Backpressure>, usize), SdkError> {
    let mut active = false;
    let mut paused = false;
    let records = page.entries.clone();
    loop {
        let outcome = apply_resume(writer, turn, generation, page).await?;
        match step_outcome(outcome, page, turn)? {
            Step::Covered => {
                mark_reorder_covered(handle, turn.cursor)?;
                break;
            }
            Step::Paused => {
                paused = true;
                break;
            }
            Step::NeedStage { sequence, cursor: next } => {
                turn.cursor = next;
                let (accepted, next_bp) = stage_page_entry(
                    handle,
                    work,
                    writer,
                    turn,
                    generation,
                    &records,
                    sequence,
                    retries,
                    call_timeout,
                    backpressure,
                )
                .await?;
                active |= accepted;
                backpressure = next_bp;
                applied = applied.saturating_add(1);
                if applied.is_multiple_of(ACK_FLUSH_COUNT) {
                    flush_acks(handle, work, generation, false, call_timeout).await?;
                }
            }
            Step::NeedPoint { seq, cursor: next } => {
                turn.cursor = next;
                let (next_paused, next_bp) = fetch_apply_point(
                    handle,
                    work,
                    writer,
                    turn,
                    generation,
                    seq,
                    call_timeout,
                    backpressure,
                )
                .await?;
                backpressure = next_bp;
                paused |= next_paused;
                if paused {
                    break;
                }
            }
        }
    }
    Ok((active, paused, backpressure, applied))
}

#[allow(clippy::too_many_arguments, reason = "catch-up leftover shares the live handles")]
async fn apply_leftover(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    writer: &Writer,
    turn: &mut ReceiveTurn,
    generation: u64,
    retries: std::collections::BTreeMap<(String, u64, String), ReceiveEntry>,
    call_timeout: std::time::Duration,
    mut backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
    mut applied: usize,
) -> Result<(bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let mut leftover: Vec<_> = retries.into_values().collect();
    leftover.sort_by_key(|entry| entry.entry.inbox_seq);
    bind_retry_turns(&mut leftover, Some(turn));
    let mut active = false;
    for mut entry in leftover {
        entry.turn = Some(turn.clone());
        let (accepted, next) =
            apply_entry(handle, work, generation, entry, call_timeout, backpressure).await?;
        active |= accepted;
        backpressure = next;
        applied = applied.saturating_add(1);
        if applied.is_multiple_of(ACK_FLUSH_COUNT) {
            flush_acks(handle, work, generation, false, call_timeout).await?;
        }
        turn.cursor = refresh_turn_cursor(writer, &turn.target).await?;
    }
    Ok((active, backpressure))
}

#[allow(clippy::too_many_arguments, reason = "NeedStage apply shares the live handles")]
async fn stage_page_entry(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    writer: &Writer,
    turn: &mut ReceiveTurn,
    generation: u64,
    records: &[crate::gateway::session_push::PageEntryRecord],
    sequence: u64,
    retries: &mut std::collections::BTreeMap<(String, u64, String), ReceiveEntry>,
    call_timeout: std::time::Duration,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<(bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let Some(record) = records.iter().find(|row| row.entry.inbox_seq == sequence) else {
        require_disk_stage(writer, turn, generation, sequence).await?;
        sync_reorder_cursor(handle, turn.cursor)?;
        return Ok((false, backpressure));
    };
    let retry_key =
        retries.remove(&entry_id(&record.entry)).and_then(|prepared| prepared.retry_key);
    let (accepted, next) = apply_entry(
        handle,
        work,
        generation,
        ReceiveEntry {
            entry: record.entry.clone(),
            retry_key,
            replay: false,
            turn: Some(turn.clone()),
        },
        call_timeout,
        backpressure,
    )
    .await?;
    turn.cursor = refresh_turn_cursor(writer, &turn.target).await?;
    sync_reorder_cursor(handle, turn.cursor)?;
    Ok((accepted, next))
}

/// Resume pages can omit a body the gateway has retired. Durable W0 is then the source of truth.
async fn require_disk_stage(
    writer: &Writer,
    turn: &ReceiveTurn,
    generation: u64,
    sequence: u64,
) -> Result<(), SdkError> {
    let turn = turn.clone();
    writer
        .apply(move |account| {
            let recovered =
                crate::bus::sync_driver::source::w0::SourceW0::from_actor(&turn, generation)
                    .recover_from_disk(account.client.account_db()?)?;
            if recovered.iter().any(|input| input.sequence == sequence) {
                Ok(())
            } else {
                Err(SdkError::InboundRejected("receive page need-stage missing entry".into()))
            }
        })
        .await
}

fn sync_reorder_cursor(handle: &ConnectionHandle, cursor: u64) -> Result<(), SdkError> {
    handle
        .reorder()
        .advance_cursor(handle.receive_now_ms(), cursor)
        .map_err(|error| SdkError::InboundRejected(error.to_string()))
}

fn mark_reorder_covered(handle: &ConnectionHandle, cursor: u64) -> Result<(), SdkError> {
    handle
        .reorder()
        .covered(handle.receive_now_ms(), cursor)
        .map_err(|error| SdkError::InboundRejected(error.to_string()))
}

enum Step {
    Covered,
    Paused,
    NeedStage { sequence: u64, cursor: u64 },
    NeedPoint { seq: u64, cursor: u64 },
}

fn step_outcome(
    outcome: ApplyOutcome,
    page: &ResumePage,
    turn: &mut ReceiveTurn,
) -> Result<Step, SdkError> {
    match outcome {
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
            apply_w1::map_page_outcome(outcome, page_high_seq(page))?;
            turn.cursor = cursor;
            Ok(Step::Covered)
        }
        ApplyOutcome::Paused { cursor } => {
            turn.cursor = cursor;
            Ok(Step::Paused)
        }
        ApplyOutcome::NeedStage { sequence, cursor } => Ok(Step::NeedStage { sequence, cursor }),
        ApplyOutcome::NeedFetch { after } => {
            Ok(Step::NeedPoint { seq: after.saturating_add(1), cursor: after })
        }
        ApplyOutcome::NeedPoint { seq, cursor } => Ok(Step::NeedPoint { seq, cursor }),
    }
}

fn page_high_seq(page: &ResumePage) -> u64 {
    page.entries.iter().map(|row| row.entry.inbox_seq).max().unwrap_or(page.covered_through_seq)
}

async fn resume_one(
    handle: &ConnectionHandle,
    after: u64,
    limit: usize,
    call_timeout: std::time::Duration,
) -> Result<ResumePage, SdkError> {
    if handle.session_is_push() {
        return resume_push(handle, after, limit, call_timeout).await;
    }
    resume_legacy(handle, after, limit, call_timeout).await
}

async fn resume_push(
    handle: &ConnectionHandle,
    after: u64,
    limit: usize,
    call_timeout: std::time::Duration,
) -> Result<ResumePage, SdkError> {
    match handle
        .call(
            move |engine| Box::pin(engine.resume_page(after, limit)),
            Instant::now() + call_timeout,
        )
        .await?
    {
        PageReply::Page(page) => Ok(*page),
        PageReply::Refused(reason) => Err(SdkError::GatewaySessionRejected(format!(
            "resume_page refused: {}",
            reason.as_str()
        ))),
    }
}

async fn resume_legacy(
    handle: &ConnectionHandle,
    after: u64,
    limit: usize,
    call_timeout: std::time::Duration,
) -> Result<ResumePage, SdkError> {
    use crate::bus::push_receiver::compat::{FRAME_MAX_BYTES, FrameOutcome, on_legacy_frame};
    let mut session = handle.compat_session();
    let want = usize::try_from(session.limit).unwrap_or(limit).min(limit);
    let entries = handle
        .call(
            move |engine| Box::pin(engine.resume_after(after, want)),
            Instant::now() + call_timeout,
        )
        .await?;
    let bytes =
        serde_json::to_vec(&entries).map_or(FRAME_MAX_BYTES.saturating_add(1), |body| body.len());
    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    match on_legacy_frame(&mut session, bytes, count, after) {
        FrameOutcome::Accept { .. } => {
            handle.set_compat_session(session);
            Ok(legacy_page(handle, after, want, entries))
        }
        FrameOutcome::RetryFresh { limit: sticky } => {
            handle.set_compat_session(session);
            let sticky_usize = usize::try_from(sticky).unwrap_or(1);
            let retry = handle
                .call(
                    move |engine| Box::pin(engine.resume_after(after, sticky_usize)),
                    Instant::now() + call_timeout,
                )
                .await?;
            let retry_bytes = serde_json::to_vec(&retry)
                .map_or(FRAME_MAX_BYTES.saturating_add(1), |body| body.len());
            let retry_count = u32::try_from(retry.len()).unwrap_or(u32::MAX);
            let mut sticky_session = handle.compat_session();
            match on_legacy_frame(&mut sticky_session, retry_bytes, retry_count, after) {
                FrameOutcome::Accept { .. } => {
                    handle.set_compat_session(sticky_session);
                    Ok(legacy_page(handle, after, sticky_usize, retry))
                }
                FrameOutcome::Pause { reason } => {
                    handle.set_compat_session(sticky_session);
                    Err(SdkError::GatewaySessionRejected(reason.into()))
                }
                FrameOutcome::RetryFresh { .. } => {
                    handle.set_compat_session(sticky_session);
                    Err(SdkError::GatewaySessionRejected("legacy_frame_protocol".into()))
                }
            }
        }
        FrameOutcome::Pause { reason } => {
            handle.set_compat_session(session);
            Err(SdkError::GatewaySessionRejected(reason.into()))
        }
    }
}

fn legacy_page(
    handle: &ConnectionHandle,
    after: u64,
    limit: usize,
    entries: Vec<crate::GatewayInboxEntry>,
) -> ResumePage {
    use crate::bus::push_receiver::compat::fallback_deadline;
    use crate::gateway::session_push::PageEntryRecord;
    use crate::time::now_unix_timestamp;
    let high = entries.iter().map(|entry| entry.inbox_seq).max().unwrap_or(after);
    let more = !entries.is_empty() && entries.len() == limit;
    let covered = high;
    let issued = if more { covered.saturating_add(1) } else { covered };
    let first_seen = now_unix_timestamp();
    ResumePage {
        after_inbox_seq: after,
        covered_through_seq: covered,
        issued_inbox_seq: issued,
        settled_through_seq: covered,
        entries: entries
            .into_iter()
            .map(|entry| {
                let ttl = i64::from(entry.envelope.ttl);
                let deadline = fallback_deadline(entry.envelope.created_at, ttl, first_seen, None)
                    .unwrap_or(crate::bus::push_receiver::compat::FallbackDeadline {
                        expires_at: 0,
                        fallback_clock_unverified: true,
                        guaranteed_retirement: false,
                    });
                handle.note_fallback_clock(deadline.fallback_clock_unverified);
                PageEntryRecord { retain_until: deadline.expires_at, entry }
            })
            .collect(),
        known_losses: Vec::new(),
        oversize_next: None,
        more,
    }
}

async fn apply_resume(
    writer: &Writer,
    turn: &ReceiveTurn,
    generation: u64,
    page: &ResumePage,
) -> Result<ApplyOutcome, SdkError> {
    let target = turn.target.clone();
    let incarnation = turn.incarnation.clone();
    let after = page.after_inbox_seq;
    let covered = page.covered_through_seq;
    let issued = page.issued_inbox_seq;
    let settled = page.settled_through_seq;
    let more = page.more;
    let oversize_next = page.oversize_next;
    let seqs: Vec<u64> = page.entries.iter().map(|row| row.entry.inbox_seq).collect();
    let losses: Vec<(u64, u64, &'static str)> = page
        .known_losses
        .iter()
        .map(|loss| (loss.from_seq, loss.to_seq, loss.reason.as_str()))
        .collect();
    let expected_generation = turn.generation;
    let erasure = turn.erasure_generation;
    let cursor = turn.cursor;
    writer
        .apply(move |account| {
            let db = account.client.account_db()?;
            let expected = ramflux_storage::ReceiveExpectation {
                target: &target,
                incarnation: &incarnation,
                cursor,
                generation: expected_generation,
                erasure_generation: erasure,
            };
            let owned: Vec<ApplyLoss<'_>> = losses
                .iter()
                .map(|(from_seq, to_seq, reason)| ApplyLoss {
                    from_seq: *from_seq,
                    to_seq: *to_seq,
                    reason,
                })
                .collect();
            match apply::apply_page(
                db,
                expected,
                generation,
                ApplyPage {
                    target: &target,
                    incarnation: &incarnation,
                    after,
                    covered,
                    issued,
                    settled,
                    entries: &seqs,
                    known_losses: &owned,
                    oversize_next,
                    more,
                },
            ) {
                Ok(outcome) => Ok(outcome),
                Err(apply::ApplyError::Protocol(text)) => {
                    Err(SdkError::InboundRejected(text.into()))
                }
                Err(apply::ApplyError::Storage(error)) => Err(error.into()),
            }
        })
        .await
}

#[allow(clippy::too_many_arguments, reason = "point fetch shares the catch-up handles")]
async fn fetch_apply_point(
    handle: &ConnectionHandle,
    work: &mpsc::Sender<AccountWork>,
    writer: &Writer,
    turn: &mut ReceiveTurn,
    generation: u64,
    seq: u64,
    call_timeout: std::time::Duration,
    backpressure: Box<crate::bus::contact_backpressure::Backpressure>,
) -> Result<(bool, Box<crate::bus::contact_backpressure::Backpressure>), SdkError> {
    let reply = handle
        .call(move |engine| Box::pin(engine.fetch_entry(seq)), Instant::now() + call_timeout)
        .await?;
    match reply {
        PointReply::Entry(record) => {
            let outcome =
                apply_point_on(writer, turn, generation, seq, point_entry(turn, seq)).await?;
            match entry_point_step(turn, seq, outcome)? {
                EntryPoint::Stage => {
                    let (accepted, next) = apply_entry(
                        handle,
                        work,
                        generation,
                        ReceiveEntry {
                            entry: record.entry,
                            retry_key: None,
                            replay: false,
                            turn: Some(turn.clone()),
                        },
                        call_timeout,
                        backpressure,
                    )
                    .await?;
                    let _ = accepted;
                    turn.cursor = refresh_turn_cursor(writer, &turn.target).await?;
                    Ok((false, next))
                }
                EntryPoint::Paused => Ok((true, backpressure)),
                EntryPoint::Covered => Ok((false, backpressure)),
            }
        }
        PointReply::TooLarge { retain_until } => {
            let outcome = apply_point_on(
                writer,
                turn,
                generation,
                seq,
                point_too_large(turn, seq, retain_until),
            )
            .await?;
            let paused = matches!(outcome, ApplyOutcome::Paused { .. });
            finish_point(turn, seq, outcome)?;
            Ok((paused, backpressure))
        }
        PointReply::Gone { observed_issued_inbox_seq, reason } => {
            let outcome = apply_point_on(
                writer,
                turn,
                generation,
                seq,
                point_gone(turn, seq, observed_issued_inbox_seq, reason.as_str()),
            )
            .await?;
            let paused = matches!(outcome, ApplyOutcome::Paused { .. });
            finish_point(turn, seq, outcome)?;
            Ok((paused, backpressure))
        }
        PointReply::Refused(reason) => Err(SdkError::GatewaySessionRejected(format!(
            "fetch_entry refused: {}",
            reason.as_str()
        ))),
    }
}

fn point_entry(turn: &ReceiveTurn, seq: u64) -> ApplyPoint<'_> {
    ApplyPoint::Entry { seq, target: &turn.target, incarnation: &turn.incarnation }
}

fn point_too_large(turn: &ReceiveTurn, seq: u64, retain_until: i64) -> ApplyPoint<'_> {
    ApplyPoint::TooLarge { seq, retain_until, incarnation: &turn.incarnation }
}

fn point_gone<'a>(
    turn: &'a ReceiveTurn,
    seq: u64,
    observed: u64,
    reason: &'a str,
) -> ApplyPoint<'a> {
    ApplyPoint::Gone { seq, observed_issued: observed, reason, incarnation: &turn.incarnation }
}

async fn apply_point_on(
    writer: &Writer,
    turn: &ReceiveTurn,
    generation: u64,
    seq: u64,
    point: ApplyPoint<'_>,
) -> Result<ApplyOutcome, SdkError> {
    let target = turn.target.clone();
    let incarnation = turn.incarnation.clone();
    let expected_generation = turn.generation;
    let erasure = turn.erasure_generation;
    let cursor = turn.cursor;
    let owned = OwnedPoint::from(point);
    writer
        .apply(move |account| {
            let db = account.client.account_db()?;
            let expected = ramflux_storage::ReceiveExpectation {
                target: &target,
                incarnation: &incarnation,
                cursor,
                generation: expected_generation,
                erasure_generation: erasure,
            };
            let point = owned.borrow(&target, &incarnation);
            match apply::apply_point(db, expected, generation, seq, point) {
                Ok(outcome) => Ok(outcome),
                Err(apply::ApplyError::Protocol(text)) => {
                    Err(SdkError::InboundRejected(text.into()))
                }
                Err(apply::ApplyError::Storage(error)) => Err(error.into()),
            }
        })
        .await
}

enum OwnedPoint {
    Entry { seq: u64 },
    TooLarge { seq: u64, retain_until: i64 },
    Gone { seq: u64, observed_issued: u64, reason: String },
}

impl OwnedPoint {
    fn from(point: ApplyPoint<'_>) -> Self {
        match point {
            ApplyPoint::Entry { seq, .. } => Self::Entry { seq },
            ApplyPoint::TooLarge { seq, retain_until, .. } => Self::TooLarge { seq, retain_until },
            ApplyPoint::Gone { seq, observed_issued, reason, .. } => {
                Self::Gone { seq, observed_issued, reason: reason.to_owned() }
            }
        }
    }

    fn borrow<'a>(&'a self, target: &'a str, incarnation: &'a str) -> ApplyPoint<'a> {
        match self {
            Self::Entry { seq } => ApplyPoint::Entry { seq: *seq, target, incarnation },
            Self::TooLarge { seq, retain_until } => {
                ApplyPoint::TooLarge { seq: *seq, retain_until: *retain_until, incarnation }
            }
            Self::Gone { seq, observed_issued, reason } => ApplyPoint::Gone {
                seq: *seq,
                observed_issued: *observed_issued,
                reason,
                incarnation,
            },
        }
    }
}

const ENTRY_POINT_REFETCH: &str = "receive entry point cannot re-fetch";

#[derive(Debug)]
enum EntryPoint {
    Stage,
    Paused,
    Covered,
}

fn entry_point_step(
    turn: &mut ReceiveTurn,
    seq: u64,
    outcome: ApplyOutcome,
) -> Result<EntryPoint, SdkError> {
    match outcome {
        ApplyOutcome::NeedStage { sequence, cursor } if sequence == seq => {
            turn.cursor = cursor;
            Ok(EntryPoint::Stage)
        }
        ApplyOutcome::Paused { cursor } => {
            turn.cursor = cursor;
            Ok(EntryPoint::Paused)
        }
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
            apply_w1::map_page_outcome(outcome, seq)?;
            turn.cursor = cursor;
            Ok(EntryPoint::Covered)
        }
        ApplyOutcome::NeedStage { .. }
        | ApplyOutcome::NeedPoint { .. }
        | ApplyOutcome::NeedFetch { .. } => {
            Err(SdkError::Storage(StorageError::Integrity(ENTRY_POINT_REFETCH)))
        }
    }
}

fn finish_point(turn: &mut ReceiveTurn, seq: u64, outcome: ApplyOutcome) -> Result<(), SdkError> {
    match outcome {
        ApplyOutcome::Covered { cursor } | ApplyOutcome::AlreadyCovered { cursor } => {
            apply_w1::map_page_outcome(outcome, seq)?;
            turn.cursor = cursor;
            Ok(())
        }
        ApplyOutcome::Paused { cursor }
        | ApplyOutcome::NeedStage { cursor, .. }
        | ApplyOutcome::NeedPoint { cursor, .. }
        | ApplyOutcome::NeedFetch { after: cursor } => {
            turn.cursor = cursor;
            Ok(())
        }
    }
}

async fn refresh_turn_cursor(writer: &Writer, target: &str) -> Result<u64, SdkError> {
    let target = target.to_owned();
    writer.apply(move |account| apply_w1::read_cursor(account.client.account_db()?, &target)).await
}

#[cfg(test)]
mod entry_point_tests {
    use super::*;

    fn turn() -> ReceiveTurn {
        ReceiveTurn {
            target: "t".into(),
            incarnation: "e".into(),
            cursor: 3,
            generation: 1,
            erasure_generation: 0,
            compat: false,
        }
    }

    fn assert_refetch(result: &Result<EntryPoint, SdkError>, turn: &ReceiveTurn) {
        assert!(
            matches!(result, Err(SdkError::Storage(StorageError::Integrity(ENTRY_POINT_REFETCH)))),
            "unexpected Entry must be Integrity: {result:?}"
        );
        assert_eq!(turn.cursor, 3, "unexpected Entry must not move C");
    }

    #[test]
    fn need_stage_mismatch_is_integrity() {
        let mut turn = turn();
        assert_refetch(
            &entry_point_step(&mut turn, 4, ApplyOutcome::NeedStage { sequence: 5, cursor: 9 }),
            &turn,
        );
    }

    #[test]
    fn need_point_is_integrity() {
        let mut turn = turn();
        assert_refetch(
            &entry_point_step(&mut turn, 4, ApplyOutcome::NeedPoint { seq: 4, cursor: 9 }),
            &turn,
        );
    }

    #[test]
    fn need_fetch_is_integrity() {
        let mut turn = turn();
        assert_refetch(
            &entry_point_step(&mut turn, 4, ApplyOutcome::NeedFetch { after: 9 }),
            &turn,
        );
    }
}
