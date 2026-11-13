// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Publication merges a retention sweep that completed while the ACK commit waited.
#![allow(clippy::expect_used, reason = "regression assertions")]
use super::{tests::ack, *};
use crate::router_store::{
    incarnation::test_store,
    publication::tests::{entry, fixture},
};
use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn run(mode: u8, expired_dead_letter: bool) -> Result {
    let root = fixture(&format!("ack-retention-merge-{mode}-{expired_dead_letter}"));
    let store = Arc::new(test_store(&root, mode, 1 << 20)?);
    let router = Arc::new(RouterCore::new());
    let now = i64::try_from(crate::now_unix_seconds())?;
    let first = if expired_dead_letter { 2 } else { 1 };
    let last = first + 1;
    for seq in first..=last {
        let deadline = if seq == first { now - 1 } else { now + 3600 };
        let mut row = entry(seq);
        if seq == first {
            row.envelope.created_at = now - 7200;
        }
        router.target_shard("target").inbox.restore_pending_entry_until(row, deadline);
    }
    if expired_dead_letter {
        router.target_shard("target").inbox.restore_cursor_state(CursorAckState {
            target_delivery_id: "target".into(),
            settled_inbox_seq: 1,
            issued_inbox_seq: last,
            dead_letters: [crate::DeadLetterRecord {
                inbox_seq: 1,
                envelope_id: "old-dead".into(),
                reason: crate::DeadLetterReason::AckWindowOverflow,
                retain_until: now - 1,
            }]
            .into(),
            ..Default::default()
        });
    }
    store.bootstrap_router(&router)?;
    if mode != 0 {
        let snapshot = router.inbox_snapshot();
        for (row, deadline) in snapshot.pending_entries_with_deadline() {
            store.record_submission_increment(
                &crate::tests::request_replay_fixture(&format!("ack-retention-{}", row.inbox_seq)),
                deadline,
                Some(row),
            )?;
        }
    }
    router.prepare_publication_target(&store, "target")?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let observer = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == "direct_commit" && !done {
                entered_tx.send(()).map_err(std::io::Error::other)?;
                release_rx
                    .lock()
                    .map_err(|_| std::io::Error::other("release mutex"))?
                    .recv_timeout(Duration::from_secs(30))
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        }),
    );
    let r = router.clone();
    let s = store.clone();
    let worker = std::thread::spawn(move || r.apply_ack_batch(&s, "target", &[ack(last)]));
    entered_rx.recv_timeout(Duration::from_secs(5))?;
    let removed = router.sweep_delivery_retention(now);
    let during = router.cursor_state("target").ok_or("during cursor")?;
    release_tx.send(())?;
    let result = worker.join().map_err(|_| "ACK thread")??;
    drop(observer);
    assert_eq!(removed, 1);
    assert_eq!(during.settled_inbox_seq, first, "sweep advanced the live prefix during commit");
    assert_eq!(during.dead_letters.len(), 0);
    assert!(result.iter().all(std::result::Result::is_ok));
    let after = router.cursor_state("target").ok_or("after cursor")?;
    assert_eq!(
        after.settled_inbox_seq, last,
        "publication must advance after the last pending row retires"
    );
    assert_eq!(after.dead_letters.len(), 0, "expired baseline dead letters must not return");
    assert_eq!(router.resume("target", 0, 10), Vec::<crate::InboxEntry>::new());
    let due = router.take_retention_checkpoints();
    assert!(due.iter().any(|cursor| cursor.settled_inbox_seq == last));
    // The ordinary durable sweep/flush observes the merged cursor before restart.
    store.sweep_delivery_retention(now, false)?;
    store.retain_cursor_checkpoints(&due)?;
    drop(router);
    drop(store);
    let store = test_store(&root, mode, 1 << 20)?;
    let reopened = store.load_router()?.ok_or("restart")?;
    assert_eq!(
        reopened.cursor_state("target").ok_or("restart cursor")?.settled_inbox_seq,
        last,
        "mode={mode}, old_dead_letter={expired_dead_letter}"
    );
    assert_eq!(reopened.cursor_state("target").ok_or("restart cursor")?.dead_letters.len(), 0);
    Ok(())
}
#[test]
fn ack_publication_preserves_concurrent_retention() -> Result {
    for mode in 0..=2 {
        run(mode, false)?;
        run(mode, true)?;
    }
    Ok(())
}
