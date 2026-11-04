// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conservation and restart tests at the B commit / A settlement boundary.
use super::super::drain::DrainFailPoint;
use super::*;
fn setup() -> TestResult<(Scenario, crate::ForwardedEnvelopeRequest, MigrationDrainEntry)> {
    setup_count(1)
}
fn setup_count(
    count: u64,
) -> TestResult<(Scenario, crate::ForwardedEnvelopeRequest, MigrationDrainEntry)> {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let mut request = super::forwarded::sender(&s.target)?;
    let entry = crate::InboxEntry {
        inbox_seq: 7,
        target_delivery_id: s.target.clone(),
        envelope: request.envelope.clone(),
    };
    for offset in 0..count {
        let mut entry = entry.clone();
        entry.inbox_seq += offset;
        if offset == 0 {
            s.a.store()?.record_submission_increment(
                "drain-cutover",
                i64::MAX / 2,
                Some(&entry),
            )?;
            request.envelope = entry.envelope.clone();
        } else {
            s.a.store()?.record_inbox_entry(&entry)?;
        }
    }
    let committed = s.commit(&op)?;
    let HomeRecord::Committed { commit_proof, .. } = committed.record else {
        return Err("proof".into());
    };
    let row = s.a.store()?.migration_drain_page(&s.target, 0)?.pop().ok_or("row")?;
    request.migration_evidence = Some(crate::ForwardedMigrationEvidence {
        commit_proof: Some(*commit_proof),
        retain_until: row.retain_until,
        floors: vec![],
    });
    Ok((s, request, row))
}
fn progress(s: &Scenario) -> TestResult<BacklogProgress> {
    Ok(s.a.store()?.migration_backlog_progress(
        &s.anchor,
        &s.authorization.body.migration_id,
        MigrationRole::Source,
    )?)
}
fn finish(s: &Scenario, now: u64) -> TestResult {
    s.a.store()?.finish_home_migration_backlog(
        &s.anchor,
        &s.authorization.body.migration_id,
        now,
    )?;
    assert!(
        !s.a.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Source
            )?
            .ok_or("operation")?
            .live_budget
    );
    Ok(())
}
fn cursor(s: &Scenario) -> TestResult<MigrationBacklogCursor> {
    let tx = s.a.store()?.migration_db().begin_write()?;
    Ok(read(
        &tx,
        BACKLOG,
        &serde_json::to_string(&(&s.anchor, &s.authorization.body.migration_id, &s.target))?,
    )?
    .ok_or("cursor")?)
}
fn accept(
    s: &Scenario,
    request: crate::ForwardedEnvelopeRequest,
) -> TestResult<crate::RouterSubmitOutcome> {
    Ok(s.b.core.submit_forwarded_envelope(
        s.b.store()?,
        Some(&s.b.node),
        request,
        crate::now_unix_seconds(),
    )?)
}
#[test]
fn drain_releases_entry_only_after_b_commit_or_duplicate_ack() -> TestResult {
    let (s, request, row) = setup()?;
    s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::Held, NOW + 3)?;
    assert!(finish(&s, NOW + 3).is_err());
    assert_eq!(progress(&s)?.remaining, 1);
    assert!(matches!(accept(&s, request.clone())?, crate::RouterSubmitOutcome::OfflineQueued(_)));
    assert!(matches!(
        accept(&s, request)?,
        crate::RouterSubmitOutcome::DuplicateFederatedForward { .. }
    ));
    s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::BAck, NOW + 4)?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, []);
    assert_eq!(progress(&s)?.forwarded, 1);
    finish(&s, NOW + 4)
}
#[test]
fn drain_crash_after_b_commit_before_a_ack_replays_same_entry_and_b_keeps_one_copy() -> TestResult {
    let (mut s, request, row) = setup()?;
    let before = cursor(&s)?;
    assert!(matches!(accept(&s, request.clone())?, crate::RouterSubmitOutcome::OfflineQueued(_)));
    assert!(
        s.a.store()?.fail_drain(&row, DrainFailPoint::AfterBAckBeforeACommit, NOW + 3).is_err()
    );
    s.a.restart()?;
    s.b.restart()?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, vec![row.clone()]);
    assert_eq!(cursor(&s)?, before);
    assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    assert_eq!(s.b.core.resume(&s.target, 0, 10).len(), 1);
    assert!(matches!(
        accept(&s, request)?,
        crate::RouterSubmitOutcome::DuplicateFederatedForward { .. }
    ));
    assert_eq!(s.b.core.resume(&s.target, 0, 10).len(), 1);
    s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::BAck, NOW + 4)?;
    s.a.restart()?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, []);
    assert_eq!(s.a.core.resume(&s.target, 0, 10), []);
    assert_eq!(progress(&s)?.forwarded, 1);
    finish(&s, NOW + 4)
}
#[test]
fn signed_rejection_retains_entry_and_budget_until_original_expiry() -> TestResult {
    let (mut s, _, row) = setup()?;
    for _ in 0..2 {
        s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::Rejected, NOW + 3)?;
        s.a.restart()?;
        let p = progress(&s)?;
        assert_eq!((p.remaining, p.rejected, p.forwarded), (1, 1, 0));
        assert_eq!(s.a.core.resume(&s.target, 0, 10).len(), 1);
        assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?.len(), 1);
        assert!(finish(&s, NOW + 3).is_err());
    }
    assert!(
        s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::Expired, NOW + 4).is_err()
    );
    s.a.store()?.settle_migration_drain(
        &row,
        MigrationDrainOutcome::Expired,
        u64::try_from(row.retain_until)?,
    )?;
    let p = progress(&s)?;
    assert_eq!((p.remaining, p.rejected, p.expired), (0, 0, 1));
    finish(&s, u64::try_from(row.retain_until)?)
}
#[test]
fn entry_past_inbox_retain_until_is_counted_expired_never_forwarded() -> TestResult {
    let (mut s, _, row) = setup()?;
    s.a.store()?.settle_migration_drain(
        &row,
        MigrationDrainOutcome::Expired,
        u64::try_from(row.retain_until)?,
    )?;
    s.a.restart()?;
    assert_eq!((progress(&s)?.expired, progress(&s)?.forwarded), (1, 0));
    assert_eq!(s.b.core.resume(&s.target, 0, 10), []);
    assert_eq!(s.a.core.resume(&s.target, 0, 10), []);
    finish(&s, u64::try_from(row.retain_until)?)
}
#[test]
fn window_close_keeps_held_backlog_until_retain_until_then_releases_budget() -> TestResult {
    let (s, _, row) = setup()?;
    s.a.store()?.settle_migration_drain(&row, MigrationDrainOutcome::Held, NOW + 3)?;
    let close = NOW + 2 + FORWARD_SECONDS;
    assert!(s.a.store()?.migration_forward_window(&s.target, close)?.is_none());
    assert!(finish(&s, close).is_err());
    assert_eq!((progress(&s)?.remaining, progress(&s)?.evidence_required), (1, 1));
    s.a.store()?.settle_migration_drain(
        &row,
        MigrationDrainOutcome::Expired,
        u64::try_from(row.retain_until)?,
    )?;
    finish(&s, u64::try_from(row.retain_until)?)
}
#[test]
fn receiver_ack_at_a_after_commit_counts_receiver_acked_and_releases() -> TestResult {
    let (mut s, _, row) = setup()?;
    let ack = crate::CursorAckState {
        target_delivery_id: s.target.clone(),
        last_acknowledged_inbox_seq: Some(row.entry.inbox_seq),
        acked_inbox_seqs: [row.entry.inbox_seq].into(),
        ..Default::default()
    };
    s.a.store()?.record_ack_increment(&ack, &row.entry.envelope.envelope_id)?;
    s.a.restart()?;
    let p = progress(&s)?;
    assert_eq!((p.remaining, p.receiver_acked, p.forwarded), (0, 1, 0));
    finish(&s, NOW + 3)?;
    // NACK retirement/dead-letter and cumulative settled ranges use the same writer.
    for nack_path in [false, true] {
        let (mut s, _, _) = setup_count(3)?;
        let rows = s.a.store()?.migration_drain_page(&s.target, 0)?;
        let cursor = crate::CursorAckState {
            target_delivery_id: s.target.clone(),
            last_acknowledged_inbox_seq: (!nack_path).then_some(rows[2].entry.inbox_seq),
            retired_inbox_seqs: vec![rows[1].entry.inbox_seq],
            settled_inbox_seq: rows[0].entry.inbox_seq,
            acked_inbox_seqs: [rows[2].entry.inbox_seq].into(),
            ..Default::default()
        };
        if nack_path {
            s.a.store()?.record_nack_increment(&cursor)?;
        } else {
            s.a.store()?.record_ack_increment(&cursor, &rows[2].entry.envelope.envelope_id)?;
        }
        s.a.restart()?;
        assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, []);
        let p = progress(&s)?;
        assert_eq!((p.scheduled, p.receiver_acked, p.remaining, p.forwarded), (3, 3, 0, 0));
        finish(&s, NOW + 3)?;
    }
    let (mut s, _, row) = setup()?;
    s.a.restart()?;
    let nack = ramflux_protocol::Nack {
        schema: "ramflux.nack.v1".into(),
        version: 1,
        domain: "ramflux.nack.v1".into(),
        ext: ramflux_protocol::Ext::default(),
        signed: row.entry.envelope.signed.clone(),
        nack_id: "receiver-dead-letter".into(),
        envelope_id: row.entry.envelope.envelope_id.clone(),
        receiver_device_id: s.target.clone(),
        reason: ramflux_protocol::NackReason::EpochRollback,
        received_at: i64::try_from(NOW + 3)?,
        retry_after: None,
        proof_hash: None,
        new_home_node_hint: None,
    };
    for _ in 0..crate::inbox::ROUTER_NACK_RETRY_LIMIT {
        let cursor = s.a.core.apply_nack_for_target(&s.target, &nack)?;
        s.a.store()?.record_nack_increment(&cursor)?;
    }
    assert_eq!(s.a.core.cursor_state(&s.target).ok_or("cursor")?.dead_letters.len(), 1);
    s.a.restart()?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, []);
    assert_eq!(progress(&s)?.receiver_acked, 1);
    finish(&s, NOW + 3)?;
    Ok(())
}
#[test]
fn backlog_counters_conserve_across_retries_and_transitions() -> TestResult {
    let (s, _, row) = setup()?;
    for outcome in [
        MigrationDrainOutcome::Held,
        MigrationDrainOutcome::Held,
        MigrationDrainOutcome::Rejected,
        MigrationDrainOutcome::Held,
        MigrationDrainOutcome::Rejected,
        MigrationDrainOutcome::BAck,
        MigrationDrainOutcome::BAck,
    ] {
        s.a.store()?.settle_migration_drain(&row, outcome, NOW + 3)?;
        let p = progress(&s)?;
        assert_eq!(p.scheduled, p.remaining + p.forwarded + p.receiver_acked + p.expired);
        assert!(p.evidence_required + p.rejected <= p.remaining);
        assert_eq!(p.scheduled, 1);
    }
    assert_eq!(progress(&s)?.forwarded, 1);
    finish(&s, NOW + 3)
}

#[test]
fn later_settlement_does_not_skip_an_earlier_held_entry() -> TestResult {
    let (mut s, _, _) = setup_count(2)?;
    let rows = s.a.store()?.migration_drain_page(&s.target, 0)?;
    assert_eq!(rows.len(), 2);
    s.a.store()?.settle_migration_drain(&rows[0], MigrationDrainOutcome::Held, NOW + 3)?;
    s.a.store()?.settle_migration_drain(&rows[1], MigrationDrainOutcome::BAck, NOW + 3)?;
    s.a.restart()?;
    let c = cursor(&s)?;
    assert_eq!(c.next_seq, rows[0].entry.inbox_seq);
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, c.next_seq)?.len(), 1);
    let p = progress(&s)?;
    assert_eq!((p.scheduled, p.remaining, p.evidence_required, p.forwarded), (2, 1, 1, 1));
    s.a.store()?.settle_migration_drain(&rows[0], MigrationDrainOutcome::BAck, NOW + 4)?;
    assert_eq!(cursor(&s)?.next_seq, c.high_water + 1);
    finish(&s, NOW + 4)
}

#[test]
fn overlapping_capture_cannot_replace_an_outstanding_migration_obligation() -> TestResult {
    let (s, _, row) = setup()?;
    let store = s.a.store()?;
    let cursor = cursor(&s)?;
    let tx = store.migration_db().begin_write()?;
    assert!(super::super::drain::capture(store, &tx, &[cursor], NOW + 2).is_err());
    drop(tx);
    assert_eq!(store.migration_drain_page(&s.target, 0)?, vec![row]);
    Ok(())
}
