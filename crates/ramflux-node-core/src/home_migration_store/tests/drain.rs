// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conservation and restart tests at the B commit / A settlement boundary.
use super::super::drain::DrainFailPoint;
use super::*;
use crate::{CursorAckState, ROUTER_CURSOR_STATE_TABLE};
fn setup() -> TestResult<(Scenario, crate::ForwardedEnvelopeRequest, MigrationDrainEntry)> {
    setup_count(1)
}
fn setup_count(
    count: u64,
) -> TestResult<(Scenario, crate::ForwardedEnvelopeRequest, MigrationDrainEntry)> {
    setup_count_mode(count, false, false)
}
fn setup_count_mode(
    count: u64,
    direct: bool,
    redb_only: bool,
) -> TestResult<(Scenario, crate::ForwardedEnvelopeRequest, MigrationDrainEntry)> {
    let mut s = Scenario::prepared()?;
    if redb_only {
        drop(s.a.store.take());
        s.a.store = Some(RouterRedbStore::open_without_wal(&s.a.path)?);
    }
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
            if direct {
                s.a.store()?.record_inbox_entry(&entry)?;
            } else {
                s.a.store()?.record_submission_increment(
                    "drain-cutover",
                    i64::MAX / 2,
                    Some(&entry),
                )?;
            }
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
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::Held, NOW + 3)?;
    assert!(finish(&s, NOW + 3).is_err());
    assert_eq!(progress(&s)?.remaining, 1);
    let crate::RouterSubmitOutcome::OfflineQueued(original) = accept(&s, request.clone())? else {
        return Err("original acceptance".into());
    };
    let crate::RouterSubmitOutcome::OfflineQueued(retry) = accept(&s, request)? else {
        return Err("retry acceptance".into());
    };
    assert_eq!(retry.entry.inbox_seq, original.entry.inbox_seq);
    assert_eq!(s.b.core.resume(&s.target, 0, 10), vec![original.entry]);
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::BAck, NOW + 4)?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, []);
    assert_eq!(progress(&s)?.forwarded, 1);
    finish(&s, NOW + 4)
}
#[test]
fn drain_crash_after_b_commit_before_a_ack_replays_same_entry_and_b_keeps_one_copy() -> TestResult {
    let (mut s, request, row) = setup()?;
    let before = cursor(&s)?;
    let crate::RouterSubmitOutcome::OfflineQueued(original) = accept(&s, request.clone())? else {
        return Err("original acceptance".into());
    };
    assert!(
        s.a.store()?
            .fail_drain(&s.a.core, &row, DrainFailPoint::AfterBAckBeforeACommit, NOW + 3)
            .is_err()
    );
    s.a.restart()?;
    s.b.restart()?;
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, vec![row.clone()]);
    assert_eq!(cursor(&s)?, before);
    assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    assert_eq!(s.b.core.resume(&s.target, 0, 10).len(), 1);
    let crate::RouterSubmitOutcome::OfflineQueued(retry) = accept(&s, request)? else {
        return Err("retry acceptance".into());
    };
    assert_eq!(retry.entry.inbox_seq, original.entry.inbox_seq);
    assert_eq!(s.b.core.resume(&s.target, 0, 10), vec![original.entry]);
    assert_eq!(s.b.core.resume(&s.target, 0, 10).len(), 1);
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::BAck, NOW + 4)?;
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
        s.a.store()?.settle_migration_drain(
            &s.a.core,
            &row,
            MigrationDrainOutcome::Rejected,
            NOW + 3,
        )?;
        s.a.restart()?;
        let p = progress(&s)?;
        assert_eq!((p.remaining, p.rejected, p.forwarded), (1, 1, 0));
        assert_eq!(s.a.core.resume(&s.target, 0, 10).len(), 1);
        assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?.len(), 1);
        assert!(finish(&s, NOW + 3).is_err());
    }
    assert!(
        s.a.store()?
            .settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::Expired, NOW + 4)
            .is_err()
    );
    s.a.store()?.settle_migration_drain(
        &s.a.core,
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
        &s.a.core,
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
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::Held, NOW + 3)?;
    let close = NOW + 2 + FORWARD_SECONDS;
    assert!(s.a.store()?.migration_forward_window(&s.target, close)?.is_none());
    assert!(finish(&s, close).is_err());
    assert_eq!((progress(&s)?.remaining, progress(&s)?.evidence_required), (1, 1));
    s.a.store()?.settle_migration_drain(
        &s.a.core,
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
            retired_inbox_seqs: vec![rows[0].entry.inbox_seq, rows[1].entry.inbox_seq],
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
        s.a.store()?.settle_migration_drain(&s.a.core, &row, outcome, NOW + 3)?;
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
    s.a.store()?.settle_migration_drain(
        &s.a.core,
        &rows[0],
        MigrationDrainOutcome::Held,
        NOW + 3,
    )?;
    s.a.store()?.settle_migration_drain(
        &s.a.core,
        &rows[1],
        MigrationDrainOutcome::BAck,
        NOW + 3,
    )?;
    s.a.restart()?;
    let c = cursor(&s)?;
    assert_eq!(c.next_seq, rows[0].entry.inbox_seq);
    assert_eq!(s.a.store()?.migration_drain_page(&s.target, c.next_seq)?.len(), 1);
    let p = progress(&s)?;
    assert_eq!((p.scheduled, p.remaining, p.evidence_required, p.forwarded), (2, 1, 1, 1));
    s.a.store()?.settle_migration_drain(
        &s.a.core,
        &rows[0],
        MigrationDrainOutcome::BAck,
        NOW + 4,
    )?;
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

#[test]
fn back_settlement_updates_live_inbox_projection() -> TestResult {
    let (mut s, request, row) = setup()?;
    s.a.restart()?;
    assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    for outcome in [MigrationDrainOutcome::Held, MigrationDrainOutcome::Rejected] {
        s.a.store()?.settle_migration_drain(&s.a.core, &row, outcome, NOW + 3)?;
        assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    }
    assert!(matches!(accept(&s, request)?, crate::RouterSubmitOutcome::OfflineQueued(_)));
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::BAck, NOW + 4)?;
    assert_eq!(s.a.core.resume(&s.target, 0, 10), []);
    assert_eq!(progress(&s)?.forwarded, 1);
    Ok(())
}

#[test]
fn expired_settlement_updates_live_inbox_projection() -> TestResult {
    let (mut s, _, row) = setup()?;
    s.a.restart()?;
    assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    let until = u64::try_from(row.retain_until)?;
    assert!(
        s.a.store()?
            .settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::Expired, until - 1,)
            .is_err()
    );
    assert_eq!(s.a.core.resume(&s.target, 0, 10), vec![row.entry.clone()]);
    s.a.store()?.settle_migration_drain(&s.a.core, &row, MigrationDrainOutcome::Expired, until)?;
    assert_eq!(s.a.core.resume(&s.target, 0, 10), []);
    assert_eq!(progress(&s)?.expired, 1);
    Ok(())
}

#[test]
fn failed_drain_commit_leaves_live_inbox_projection_unchanged() -> TestResult {
    for outcome in [MigrationDrainOutcome::BAck, MigrationDrainOutcome::Expired] {
        let (mut s, _, row) = setup()?;
        s.a.restart()?;
        let entries = s.a.core.resume(&s.target, 0, 10);
        let cursor = s.a.core.cursor_state(&s.target);
        let before = progress(&s)?;
        assert_eq!(entries, vec![row.entry.clone()]);
        s.a.fail_commit()?;
        let now = if outcome == MigrationDrainOutcome::Expired {
            u64::try_from(row.retain_until)?
        } else {
            NOW + 4
        };
        let error =
            s.a.store()?
                .settle_migration_drain(&s.a.core, &row, outcome, now)
                .err()
                .ok_or("injected commit must fail")?;
        assert!(error.to_string().contains("injected migration commit failure"));
        assert_eq!(s.a.core.resume(&s.target, 0, 10), entries);
        assert_eq!(s.a.core.cursor_state(&s.target), cursor);
        assert_eq!(s.a.store()?.migration_drain_page(&s.target, 0)?, vec![row]);
        assert_eq!(progress(&s)?, before);
        s.a.restart()?;
        assert_eq!(s.a.core.resume(&s.target, 0, 10), entries);
    }
    Ok(())
}

#[test]
fn settled_live_inbox_projection_matches_restart() -> TestResult {
    for outcome in [MigrationDrainOutcome::BAck, MigrationDrainOutcome::Expired] {
        let (mut s, _, _) = setup_count(3)?;
        s.a.restart()?;
        let rows = s.a.store()?.migration_drain_page(&s.target, 0)?;
        assert_eq!(s.a.core.resume(&s.target, 0, 10).len(), 3);
        let now = if outcome == MigrationDrainOutcome::Expired {
            u64::try_from(rows[1].retain_until)?
        } else {
            NOW + 4
        };
        s.a.store()?.settle_migration_drain(&s.a.core, &rows[1], outcome, now)?;
        // Idempotent replies must leave both neighboring entries intact.
        s.a.store()?.settle_migration_drain(&s.a.core, &rows[1], outcome, now)?;
        let live = s.a.core.resume(&s.target, 0, 10);
        assert_eq!(live, vec![rows[0].entry.clone(), rows[2].entry.clone()]);
        let cursor = s.a.core.cursor_state(&s.target);
        s.a.restart()?;
        assert_eq!(s.a.core.resume(&s.target, 0, 10), live);
        assert_eq!(s.a.core.cursor_state(&s.target), cursor);
    }
    Ok(())
}

#[test]
fn concurrent_ack_during_settlement_preserves_live_cursor_and_restart_state() -> TestResult {
    for outcome in [MigrationDrainOutcome::BAck, MigrationDrainOutcome::Expired] {
        let (mut s, _, _) = setup_count(3)?;
        s.a.restart()?;
        let rows = s.a.store()?.migration_drain_page(&s.target, 0)?;
        let ack_entry = &rows[2].entry;
        let ack = ramflux_protocol::Ack {
            schema: "ramflux.ack.v1".into(),
            version: 1,
            domain: "ramflux.ack.v1".into(),
            ext: ramflux_protocol::Ext {
                ext: [("inbox_seq".into(), json!(ack_entry.inbox_seq))].into(),
            },
            signed: ack_entry.envelope.signed.clone(),
            ack_id: "concurrent-receiver-ack".into(),
            envelope_id: ack_entry.envelope.envelope_id.clone(),
            receiver_device_id: s.target.clone(),
            received_at: i64::try_from(NOW + 3)?,
            cursor_after: None,
        };
        let store = s.a.store()?;
        let mut lease = Some(store.acquire_acknowledgement(&s.target)?);
        // Park the real ACK path after its memory update, before the durable write.
        let ack_cursor = s.a.core.apply_ack_for_target(&s.target, &ack)?;
        let now = if outcome == MigrationDrainOutcome::Expired {
            u64::try_from(rows[1].retain_until)?
        } else {
            NOW + 4
        };
        // Settlement cannot overtake this ACK. A bounded attempt reports busy;
        // retry only after the ACK's durable write releases its settlement ticket.
        let core = &s.a.core;
        let settlement_row = &rows[1];
        std::thread::scope(|scope| -> TestResult {
            let (tx, rx) = std::sync::mpsc::channel();
            scope.spawn(move || {
                let result = store.settle_migration_drain(core, settlement_row, outcome, now);
                let _ = tx.send(result);
            });
            let blocked = match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(result) => result,
                Err(error) => {
                    // Even a broken unbounded wait must unblock before scoped join.
                    drop(lease.take());
                    return Err(error.into());
                }
            };
            assert!(matches!(
                blocked,
                Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
            ));
            Ok(())
        })?;
        store.record_leased_ack(&ack_cursor, &ack.envelope_id, lease.take().ok_or("ACK lease")?)?;
        store.settle_migration_drain(&s.a.core, &rows[1], outcome, now)?;
        let live_cursor = s.a.core.cursor_state(&s.target).ok_or("live cursor")?;
        assert!(live_cursor.acked_inbox_seqs.contains(&ack_entry.inbox_seq));
        assert!(live_cursor.acked_inbox_seqs.contains(&rows[1].entry.inbox_seq));
        assert_eq!(live_cursor.last_acknowledged_inbox_seq, ack_cursor.last_acknowledged_inbox_seq);
        assert_eq!(live_cursor.acked_envelope_ids, ack_cursor.acked_envelope_ids);
        assert!(live_cursor.issued_inbox_seq >= ack_cursor.issued_inbox_seq);
        assert!(live_cursor.settled_inbox_seq >= ack_cursor.settled_inbox_seq);
        // A duplicate must still be recognized in memory before restart.
        s.a.core.apply_ack_for_target(&s.target, &ack)?;
        let live = s.a.core.resume(&s.target, 0, 10);
        let cursor = s.a.core.cursor_state(&s.target);
        assert_eq!(live, vec![rows[0].entry.clone()]);
        s.a.restart()?;
        assert_eq!(s.a.core.resume(&s.target, 0, 10), live);
        assert_eq!(s.a.core.cursor_state(&s.target), cursor);
    }
    Ok(())
}

#[test]
fn settlement_preserves_memory_only_issued_and_settled_marks() -> TestResult {
    for outcome in [MigrationDrainOutcome::BAck, MigrationDrainOutcome::Expired] {
        let (mut s, _, _) = setup_count(3)?;
        s.a.restart()?;
        let rows = s.a.store()?.migration_drain_page(&s.target, 0)?;
        {
            let mut shard = s.a.core.target_shard(&s.target);
            shard.inbox.observe_issued_seq(&s.target, 50);
            let mut cursor = shard.inbox.cursor_state(&s.target).cloned().ok_or("cursor")?;
            cursor.settled_inbox_seq = rows[0].entry.inbox_seq - 1;
            cursor.acked_inbox_seqs.insert(49);
            shard.inbox.restore_cursor_state(cursor);
        }
        let before = s.a.core.cursor_state(&s.target).ok_or("cursor")?;
        let now = if outcome == MigrationDrainOutcome::Expired {
            u64::try_from(rows[1].retain_until)?
        } else {
            NOW + 4
        };
        s.a.store()?.settle_migration_drain(&s.a.core, &rows[1], outcome, now)?;
        let after = s.a.core.cursor_state(&s.target).ok_or("cursor")?;
        let mut expected = before;
        expected.acked_inbox_seqs.insert(rows[1].entry.inbox_seq);
        assert_eq!(after, expected);
        assert_eq!(
            s.a.core.resume(&s.target, 0, 10),
            vec![rows[0].entry.clone(), rows[2].entry.clone()]
        );
    }
    Ok(())
}

#[test]
pub(crate) fn drain_then_ack_restart_preserves_incarnation_and_ack() -> TestResult {
    for mode in 0..3 {
        let redb_only = mode == 0;
        let (mut s, _, row) = setup_count_mode(2, mode != 2, redb_only)?;
        let id = s.a.store()?.inbox_status(&s.target)?.0.ok_or("E")?;
        s.a.store()?.settle_migration_drain(
            &s.a.core,
            &row,
            MigrationDrainOutcome::BAck,
            NOW + 4,
        )?;
        assert_eq!(s.a.store()?.inbox_status(&s.target)?.0, Some(id.clone()));
        let ack_seq = if row.entry.inbox_seq == 7 { 8 } else { 7 };
        let cursor = CursorAckState {
            target_delivery_id: s.target.clone(),
            issued_inbox_seq: 8,
            acked_inbox_seqs: [ack_seq].into(),
            last_acknowledged_inbox_seq: Some(ack_seq),
            ..CursorAckState::default()
        };
        s.a.store()?.record_ack_increment(&cursor, &row.entry.envelope.envelope_id)?;
        drop(s.a.store.take());
        let store = if redb_only {
            RouterRedbStore::open_without_wal(&s.a.path)?
        } else {
            RouterRedbStore::open_with_wal(&s.a.path, s.a.path.with_extension("wal"))?
        };
        s.a.core = store.load_router()?.ok_or("restarted router")?;
        s.a.store = Some(store);
        assert_eq!(s.a.store()?.inbox_status(&s.target)?, (Some(id.clone()), 8));
        assert_eq!(s.a.core.resume(&s.target, 0, 10), []);
        let tx = s.a.store()?.migration_db().begin_write()?;
        let saved: CursorAckState =
            read(&tx, ROUTER_CURSOR_STATE_TABLE, &s.target)?.ok_or("ACK cursor")?;
        assert!(saved.acked_inbox_seqs.contains(&ack_seq) || saved.settled_inbox_seq >= ack_seq);
        assert_eq!(crate::router_store::incarnation::read_id(&tx, &s.target)?, Some(id));
    }
    Ok(())
}
