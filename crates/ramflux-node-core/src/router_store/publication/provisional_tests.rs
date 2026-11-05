// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First E belongs to the first accepted/aborted disposition, never preparation.
#![allow(clippy::expect_used, reason = "regression fixture assertions")]
use super::*;
use crate::{RouterCore, RouterRedbStore};
use redb::{ReadableDatabase, ReadableTable};
use std::sync::atomic::AtomicUsize;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn absent(store: &RouterRedbStore, target: &str) -> Result {
    let tx = store.db.begin_read()?;
    assert!(tx.open_table(crate::router_store::incarnation_state::TABLE)?.get(target)?.is_none());
    assert!(tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?.get(target)?.is_none());
    assert_eq!(store.inbox_status(target)?, (None, 0));
    Ok(())
}

#[test]
fn provisional_inbox_identity_is_atomic() -> Result {
    for mode in 0..=2 {
        for aborted in [false, true] {
            let root = super::tests::fixture(&format!("provisional-{mode}-{aborted}"));
            let store = crate::router_store::incarnation::test_store(&root, mode, 1024 * 1024)?;
            let router = RouterCore::new();
            router.bind_publication(&store)?;
            let writes = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&writes);
            let observer = crate::durability_test_hooks::observe(
                root.clone(),
                Arc::new(move |_, op, done| {
                    if matches!(op, "begin_write" | "direct_begin") && !done {
                        counted.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(())
                }),
            );
            router.prepare_publication_target(&store, "target")?;
            assert_eq!(
                writes.load(Ordering::Relaxed),
                0,
                "preparation must not commit E/counter=0"
            );
            absent(&store, "target")?;
            assert!(router.inbox_snapshot().incarnation_id("target").is_none());
            let core = store.publication_core()?;
            let id = core.current_incarnation("target").expect("provisional identity");
            // Repeated preparation must preserve this E.
            router.prepare_publication_target(&store, "target")?;
            assert_eq!(core.current_incarnation("target"), Some(id.clone()));
            let operation = capture(|| {
                let entry = super::view_tests::submit(&router, &store, 1, false);
                absent(&store, "target").expect("no first assignment on disk before hand-off");
                assert!(router.inbox_snapshot().incarnation_id("target").is_none());
                if !aborted {
                    store
                        .record_submission_increment(
                            &crate::envelope_replay_tuple_key(
                                &super::view_tests::source(),
                                &entry.envelope,
                            ),
                            entry.envelope.created_at + 3600,
                            Some(&entry),
                        )
                        .expect("first acceptance");
                }
            })?;
            operation.published_blocking()?;
            if mode == 0 || aborted {
                assert_eq!(
                    writes.load(Ordering::Relaxed),
                    1,
                    "first disposition owns exactly one redb transaction"
                );
            }
            assert_eq!(store.inbox_status("target")?, (Some(id.clone()), 1));
            assert_eq!(router.inbox_snapshot().incarnation_id("target"), Some(id.as_str()));
            assert_eq!(router.resume("target", 0, 10).len(), usize::from(!aborted));
            drop(observer);
            drop(router);
            drop(core);
            drop(store);
            let reopened = crate::router_store::incarnation::test_store(&root, mode, 1024 * 1024)?;
            assert_eq!(reopened.inbox_status("target")?, (Some(id), 1));
            let restored = reopened.load_router()?.expect("recovered first disposition");
            assert_eq!(restored.resume("target", 0, 10).len(), usize::from(!aborted));
            drop(restored);
            drop(reopened);
            std::fs::remove_dir_all(root)?;
        }
        fanout_refusal(mode)?;
    }
    Ok(())
}

fn fanout_refusal(mode: u8) -> Result {
    let root = super::tests::fixture(&format!("provisional-refusal-{mode}"));
    let store = crate::router_store::incarnation::test_store(&root, mode, 1024 * 1024)?;
    let router = RouterCore::new();
    router.bind_publication(&store)?;
    let full_id = store.initialize_inbox("full")?;
    let core = store.publication_core()?;
    let guards = (0..ABORTED_RANGE_CAPACITY)
        .map(|_| core.reserve("full", &full_id, &[]))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let operation = capture(|| {
        router.prepare_publication_target(&store, "unrelated")?;
        let id = core.current_incarnation("unrelated").expect("provisional fanout E");
        super::operation::reserve_targets(
            &core,
            &[("unrelated".into(), id), ("full".into(), full_id.clone())],
        )
    })?;
    assert!(operation.published_blocking()?.is_err());
    absent(&store, "unrelated")?;
    assert!(router.inbox_snapshot().incarnation_id("unrelated").is_none());
    assert_eq!(core.metrics().in_flight_count, ABORTED_RANGE_CAPACITY);
    for guard in &guards {
        guard.definite_non_write();
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(30),
            core.wait_published(guards.last().expect("last assignment")),
        )
        .await
    })?;
    drop(guards);
    drop(router);
    drop(core);
    drop(store);
    let reopened = crate::router_store::incarnation::test_store(&root, mode, 1024 * 1024)?;
    absent(&reopened, "unrelated")?;
    drop(reopened);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
