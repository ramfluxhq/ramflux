// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Validate `resume_page` / `FetchEntry` and apply the useful suffix into W2.
use ramflux_storage::{
    AccountDb, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveExpectation,
    ReceiveKnownLoss, ReceivePageView, ReceiveReconcileResult, ReceiveTransaction, StorageError,
};

/// Protocol or storage failure while applying a page or point outcome.
#[derive(Debug)]
pub(crate) enum ApplyError {
    Protocol(&'static str),
    Storage(StorageError),
}

impl From<StorageError> for ApplyError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Known-loss interval after wire decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApplyLoss<'a> {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: &'a str,
}

/// Validated `resume_page` fields the actor will later map from the wire.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ApplyPage<'a> {
    pub target: &'a str,
    pub incarnation: &'a str,
    pub after: u64,
    pub covered: u64,
    pub issued: u64,
    pub settled: u64,
    pub entries: &'a [u64],
    pub known_losses: &'a [ApplyLoss<'a>],
    pub oversize_next: Option<u64>,
    pub more: bool,
}

/// Exact `FetchEntry` outcome. Reason strings are the wire `snake_case` codes.
/// Every variant carries the reply's incarnation E, checked against the transaction's E.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyPoint<'a> {
    Entry { seq: u64, target: &'a str, incarnation: &'a str },
    TooLarge { seq: u64, retain_until: i64, incarnation: &'a str },
    Gone { seq: u64, observed_issued: u64, reason: &'a str, incarnation: &'a str },
}

/// Known-loss reasons a page may carry; the same allow-list W2 cover enforces.
const PAGE_LOSS_REASONS: &[&str] =
    &["expired", "ack_window_overflow", "nacked", "aborted", "oversize", "unknown"];

/// Durable result of one ApplyPage/ApplyPoint call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyOutcome {
    Covered { cursor: u64 },
    AlreadyCovered { cursor: u64 },
    NeedFetch { after: u64 },
    NeedStage { sequence: u64, cursor: u64 },
    NeedPoint { seq: u64, cursor: u64 },
    Paused { cursor: u64 },
}

/// Validates §5.1 page invariants. An invalid page leaves C unchanged.
pub(crate) fn validate_page(page: &ApplyPage<'_>) -> Result<(), ApplyError> {
    if page.after > page.covered {
        return Err(ApplyError::Protocol("receive page after exceeds covered"));
    }
    if page.covered > page.issued {
        return Err(ApplyError::Protocol("receive page covered exceeds issued"));
    }
    if page.settled > page.issued {
        return Err(ApplyError::Protocol("receive page settled exceeds issued"));
    }
    let mut previous = None;
    for &seq in page.entries {
        if seq == 0 || seq <= page.after || seq > page.covered {
            return Err(ApplyError::Protocol("receive page entry outside coverage"));
        }
        if previous.is_some_and(|seen| seq <= seen) {
            return Err(ApplyError::Protocol("receive page entry not sorted unique"));
        }
        previous = Some(seq);
    }
    let mut last_to = page.after;
    for loss in page.known_losses {
        if loss.from_seq == 0 || loss.from_seq <= page.after || loss.to_seq > page.covered {
            return Err(ApplyError::Protocol("receive page loss outside coverage"));
        }
        if loss.to_seq < loss.from_seq {
            return Err(ApplyError::Protocol("receive page loss inverted"));
        }
        if !PAGE_LOSS_REASONS.contains(&loss.reason) {
            return Err(ApplyError::Protocol("receive page loss reason invalid"));
        }
        if loss.from_seq <= last_to {
            return Err(ApplyError::Protocol("receive page loss overlap"));
        }
        if page.entries.iter().any(|&seq| seq >= loss.from_seq && seq <= loss.to_seq) {
            return Err(ApplyError::Protocol("receive page entry overlaps loss"));
        }
        last_to = loss.to_seq;
    }
    if let Some(marker) = page.oversize_next {
        let expected = page
            .covered
            .checked_add(1)
            .ok_or(ApplyError::Protocol("receive page marker invalid"))?;
        if marker != expected || marker > page.issued || marker == 0 {
            return Err(ApplyError::Protocol("receive page marker invalid"));
        }
    }
    if page.more != (page.covered < page.issued) {
        return Err(ApplyError::Protocol("receive page more mismatch"));
    }
    let progressed = page.covered > page.after || page.oversize_next == page.after.checked_add(1);
    if page.after < page.issued && !progressed {
        return Err(ApplyError::Protocol("receive page does not progress"));
    }
    if page.after == page.issued && (page.more || page.covered != page.issued) {
        return Err(ApplyError::Protocol("receive page does not progress"));
    }
    Ok(())
}

/// Validates exact Entry / `EntryTooLarge` / `EntryGone` coupling to the requested sequence.
pub(crate) fn validate_point(
    requested: u64,
    target: &str,
    incarnation: &str,
    point: &ApplyPoint<'_>,
) -> Result<(), ApplyError> {
    let (seq, got_e) = match *point {
        ApplyPoint::Entry { seq, incarnation, .. }
        | ApplyPoint::TooLarge { seq, incarnation, .. }
        | ApplyPoint::Gone { seq, incarnation, .. } => (seq, incarnation),
    };
    if seq != requested {
        return Err(ApplyError::Protocol("receive point sequence mismatch"));
    }
    if got_e != incarnation {
        return Err(ApplyError::Protocol("receive point incarnation mismatch"));
    }
    match *point {
        ApplyPoint::Entry { target: got, .. } => {
            if got != target {
                return Err(ApplyError::Protocol("receive point target mismatch"));
            }
        }
        ApplyPoint::TooLarge { .. } => {}
        ApplyPoint::Gone { observed_issued, reason, .. } => {
            if observed_issued < seq {
                return Err(ApplyError::Protocol("receive point gone observed below sequence"));
            }
            if !matches!(
                reason,
                "expired" | "ack_window_overflow" | "nacked" | "aborted" | "unknown"
            ) {
                return Err(ApplyError::Protocol("receive point gone reason invalid"));
            }
        }
    }
    Ok(())
}

/// Applies a same-E page: trim after<=C<covered to the useful suffix, subtract receipts, feed W2.
pub(crate) fn apply_page(
    db: &AccountDb,
    expected: ReceiveExpectation<'_>,
    generation: u64,
    page: ApplyPage<'_>,
) -> Result<ApplyOutcome, ApplyError> {
    validate_page(&page)?;
    if page.target != expected.target {
        return Err(ApplyError::Protocol("receive page target mismatch"));
    }
    if page.incarnation != expected.incarnation {
        return Err(ApplyError::Protocol("receive page incarnation mismatch"));
    }
    let cursor = expected.cursor;
    if reject_stale() && page.after < cursor && cursor < page.covered {
        return Err(ApplyError::Protocol("receive page cursor stale"));
    }
    if cursor < page.after {
        return Ok(ApplyOutcome::NeedFetch { after: cursor });
    }
    if cursor >= page.covered {
        if let Some(seq) = page.oversize_next
            && Some(seq) == cursor.checked_add(1)
        {
            return Ok(ApplyOutcome::NeedPoint { seq, cursor });
        }
        return Ok(ApplyOutcome::AlreadyCovered { cursor });
    }
    let trimmed = trim(&page, cursor);
    let losses: Vec<ReceiveKnownLoss<'_>> = trimmed
        .known_losses
        .iter()
        .map(|loss| ReceiveKnownLoss {
            from_seq: loss.from_seq,
            to_seq: loss.to_seq,
            reason: loss.reason,
        })
        .collect();
    let view = ReceivePageView {
        after: cursor,
        covered: page.covered,
        entries: trimmed.entries,
        known_losses: &losses,
    };
    let plan = db.receive_transaction(expected, generation, |tx| tx.reconcile(view))?;
    let (steps, need_stage) = match &plan {
        ReceiveReconcileResult::Plan(steps) => (steps.as_slice(), None),
        ReceiveReconcileResult::NeedStage { sequence, prefix } => {
            (prefix.as_slice(), Some(*sequence))
        }
    };
    let result = db.apply_receive_plan(expected, generation, steps)?;
    let cursor = read_cursor(db, expected.target)?;
    if result == ReceiveCoverResult::Paused {
        return Ok(ApplyOutcome::Paused { cursor });
    }
    if let Some(sequence) = need_stage {
        return Ok(ApplyOutcome::NeedStage { sequence, cursor });
    }
    if let Some(seq) = page.oversize_next
        && Some(seq) == cursor.checked_add(1)
    {
        return Ok(ApplyOutcome::NeedPoint { seq, cursor });
    }
    Ok(ApplyOutcome::Covered { cursor })
}

/// Recovers a local receipt first; otherwise accounts TooLarge/Gone as W2.
pub(crate) fn apply_point(
    db: &AccountDb,
    expected: ReceiveExpectation<'_>,
    generation: u64,
    requested: u64,
    point: ApplyPoint<'_>,
) -> Result<ApplyOutcome, ApplyError> {
    validate_point(requested, expected.target, expected.incarnation, &point)?;
    if expected.cursor.checked_add(1) != Some(requested) {
        return Err(ApplyError::Protocol("receive point sequence mismatch"));
    }
    let entry = [requested];
    let mut loss = ReceiveKnownLoss { from_seq: requested, to_seq: requested, reason: "oversize" };
    let (entries, losses): (&[u64], &[ReceiveKnownLoss<'_>]) = match point {
        ApplyPoint::Entry { .. } => (&entry, &[]),
        ApplyPoint::TooLarge { .. } => {
            loss.reason = "oversize";
            (&[], std::slice::from_ref(&loss))
        }
        ApplyPoint::Gone { reason, .. } => {
            loss.reason = reason;
            (&[], std::slice::from_ref(&loss))
        }
    };
    let view = ReceivePageView {
        after: expected.cursor,
        covered: requested,
        entries,
        known_losses: losses,
    };
    let plan = db.receive_transaction(expected, generation, |tx| tx.reconcile(view))?;
    let mut steps = match plan {
        ReceiveReconcileResult::Plan(steps) => steps,
        ReceiveReconcileResult::NeedStage { sequence, prefix } => {
            db.apply_receive_plan(expected, generation, &prefix)?;
            let cursor = read_cursor(db, expected.target)?;
            return Ok(ApplyOutcome::NeedStage { sequence, cursor });
        }
    };
    if let ApplyPoint::TooLarge { retain_until, .. } = point
        && let Some(step) = steps.iter_mut().find(|step| {
            step.kind == ramflux_storage::ReceiveCoverKind::GapOnly && step.sequence == requested
        })
    {
        step.kind = ramflux_storage::ReceiveCoverKind::Oversize;
        step.retain_until = retain_until;
    }
    let result = db.apply_receive_plan(expected, generation, &steps)?;
    let cursor = read_cursor(db, expected.target)?;
    if result == ReceiveCoverResult::Paused {
        return Ok(ApplyOutcome::Paused { cursor });
    }
    Ok(ApplyOutcome::Covered { cursor })
}

/// After NeedStage→held W1, the actor advances C over the held sequence (I4, §2.3 step 3).
pub(crate) fn cover_held(
    db: &AccountDb,
    expected: ReceiveExpectation<'_>,
    generation: u64,
    sequence: u64,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expected, generation, |tx| cover_held_in(tx, sequence, &[]))
}

/// Same held W2 as [`cover_held`], joining an already-open receive transaction.
/// `gaps` are the page's reconciled intervals in `(C, sequence]`; empty only when
/// `sequence == C + 1`.
pub(crate) fn cover_held_in(
    tx: &ReceiveTransaction<'_>,
    sequence: u64,
    gaps: &[ramflux_storage::ReceiveGap<'_>],
) -> Result<ReceiveCoverResult, StorageError> {
    tx.cover(ReceiveCover { sequence, kind: ReceiveCoverKind::Held, gaps, retain_until: 0 })
}

struct Trimmed<'a> {
    entries: &'a [u64],
    known_losses: Vec<ApplyLoss<'a>>,
}

fn trim<'a>(page: &ApplyPage<'a>, cursor: u64) -> Trimmed<'a> {
    let start = page.entries.partition_point(|&seq| seq <= cursor);
    let mut known_losses = Vec::new();
    for loss in page.known_losses {
        if loss.to_seq <= cursor {
            continue;
        }
        let from_seq = loss.from_seq.max(cursor.saturating_add(1));
        if from_seq <= loss.to_seq {
            known_losses.push(ApplyLoss { from_seq, to_seq: loss.to_seq, reason: loss.reason });
        }
    }
    Trimmed { entries: &page.entries[start..], known_losses }
}

fn read_cursor(db: &AccountDb, target: &str) -> Result<u64, ApplyError> {
    use ramflux_storage::ProjectionStore;
    db.projection_checkpoint(&format!("gateway_receive_cursor:{target}"))?
        .map_or(Ok(0), |s| s.parse::<u64>().map_err(|_| StorageError::AuthorizationRejected))
        .map_err(ApplyError::from)
}

fn reject_stale() -> bool {
    #[cfg(test)]
    {
        REJECT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static REJECT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: ApplyFault, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REJECT.with(|slot| slot.set(false));
        }
    }
    REJECT.with(|slot| slot.set(true));
    let _reset = Reset;
    let _ = fault;
    write()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyFault {
    RejectStale,
}
