// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! R2 expiry boundaries and publication installation interleavings.
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::tests::{entry, fixture},
};
use redb::ReadableDatabase;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn stored(
    store: &RouterRedbStore,
) -> std::result::Result<CursorAckState, Box<dyn std::error::Error>> {
    let tx = store.db.begin_read()?;
    let table = tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?;
    Ok(incarnation::decode_cursor(table.get("target")?.ok_or("cursor")?.value())?)
}

#[test]
fn checkpoints_publish_to_core_installed_after_capture() -> Result {
    for mode in 0..=2 {
        for operation in 0..5 {
            let root = fixture(&format!("late-core-{mode}-{operation}"));
            let store = Arc::new(test_store(&root, mode, 1 << 20)?);
            let mut row = entry(1);
            if operation == 4 {
                row.envelope.created_at -= 7200;
            }
            store.record_inbox_entry(&row)?;
            let id = store.inbox_status("target")?.0.ok_or("E")?;
            let fired = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&fired);
            let weak = Arc::downgrade(&store);
            let registration = crate::durability_test_hooks::observe(
                root.clone(),
                Arc::new(move |_, op, done| {
                    if op == "direct_begin" && !done && !observed.swap(true, Ordering::SeqCst) {
                        // The outer writer captured None and has not acquired redb.
                        // Install the core with its previous R, then let it commit.
                        let store = weak.upgrade().ok_or_else(|| std::io::Error::other("store"))?;
                        let core = store.publication_core().map_err(std::io::Error::other)?;
                        assert_eq!(
                            core.settled_view(
                                "target",
                                &store
                                    .inbox_status("target")
                                    .map_err(std::io::Error::other)?
                                    .0
                                    .ok_or_else(|| std::io::Error::other("E"))?
                            )
                            .1,
                            0
                        );
                    }
                    Ok(())
                }),
            );
            let cursor = CursorAckState {
                target_delivery_id: "target".into(),
                issued_inbox_seq: 1,
                last_acknowledged_inbox_seq: Some(1),
                acked_inbox_seqs: [1].into(),
                retired_inbox_seqs: vec![1],
                ..Default::default()
            };
            match operation {
                0 => store.record_ack_increment(&cursor, &row.envelope.envelope_id)?,
                1 => store.record_nack_increment(&cursor)?,
                2 => store.retain_cursor_checkpoint(&cursor)?,
                3 => store.retain_cursor_checkpoints(&[cursor])?,
                _ => {
                    store.sweep_delivery_retention(
                        i64::try_from(crate::now_unix_seconds())?,
                        false,
                    )?;
                }
            }
            assert!(fired.load(Ordering::SeqCst), "forced installation before writer");
            assert_eq!(stored(&store)?.settled_inbox_seq, 1);
            assert_eq!(
                store.publication_core()?.settled_view("target", &id),
                (1, 1),
                "late core observes committed R, operation {operation}"
            );
            drop(registration);
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

#[test]
fn receiver_keeps_unswept_expired_wal_head() -> Result {
    for mode in 1..=2 {
        for nack in [false, true] {
            let root = fixture(&format!("unswept-wal-{mode}-{nack}"));
            let store = test_store(&root, mode, 1 << 20)?;
            let mut first = entry(1);
            first.envelope.created_at -= 7200;
            store.record_submission_increment(
                "expired-head",
                first.envelope.created_at + 3600,
                Some(&first),
            )?;
            let later = entry(2);
            store.record_submission_increment(
                "live-tail",
                later.envelope.created_at + 3600,
                Some(&later),
            )?;
            let (inbox, _) = store.load_delivery_state(0)?;
            assert_eq!(
                inbox.pull_after("target", 0, 1),
                vec![first.clone()],
                "unswept inbox still serves expired row"
            );
            let id = store.inbox_status("target")?.0.ok_or("E")?;
            let core = store.publication_core()?;
            let cursor = CursorAckState {
                target_delivery_id: "target".into(),
                issued_inbox_seq: 2,
                last_acknowledged_inbox_seq: (!nack).then_some(2),
                acked_inbox_seqs: if nack {
                    std::collections::BTreeSet::default()
                } else {
                    [2].into()
                },
                retired_inbox_seqs: if nack { vec![2] } else { Vec::new() },
                ..Default::default()
            };
            if nack {
                store.record_nack_increment(&cursor)?;
            } else {
                store.record_ack_increment(&cursor, &later.envelope.envelope_id)?;
            }
            assert_eq!(
                stored(&store)?.settled_inbox_seq,
                0,
                "receiver cannot settle unswept WAL head"
            );
            assert_eq!(core.settled_view("target", &id), (2, 0));
            assert_eq!(inbox.pull_after("target", 0, 1), vec![first]);
            store.sweep_delivery_retention(i64::try_from(crate::now_unix_seconds())?, false)?;
            assert_eq!(
                stored(&store)?.settled_inbox_seq,
                2,
                "explicit sweep now settles expired head"
            );
            assert_eq!(core.settled_view("target", &id), (2, 2));
            drop(core);
            drop(store);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}
