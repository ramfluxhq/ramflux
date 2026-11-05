// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P9 retention, startup and two-restart durable prefix oracles.
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::{
        capture,
        tests::{entry, fixture},
        view_tests::submit,
    },
};
use redb::ReadableTable;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn stored(
    store: &crate::RouterRedbStore,
) -> std::result::Result<CursorAckState, Box<dyn std::error::Error>> {
    let tx = store.migration_db().begin_read()?;
    let table = tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?;
    Ok(crate::router_store::incarnation::decode_cursor(
        table.get("target")?.ok_or("cursor")?.value(),
    )?)
}

pub(super) fn sweep_and_checkpoint() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("retention-checkpoint-{mode}"));
        let store = test_store(&root, mode, 1 << 20)?;
        let id = store.initialize_inbox("target")?;
        let router = crate::RouterCore::new();
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        let held = core.reserve("target", &id, &[])?;
        let later = capture(|| submit(&router, &store, 2, true))?;
        let now = i64::try_from(crate::now_unix_seconds())? + 7200;
        assert_eq!(router.sweep_delivery_retention(now), 1);
        let cursors = router.take_retention_checkpoints();
        assert_eq!(cursors.len(), 1);
        assert_eq!(cursors[0].settled_inbox_seq, 0, "missing guard pins memory sweep");
        let mut forged = cursors[0].clone();
        forged.settled_inbox_seq = 2;
        store.retain_cursor_checkpoint(&forged)?;
        assert_eq!(stored(&store)?.settled_inbox_seq, 0, "single writer validates P");
        store.retain_cursor_checkpoints(&[forged])?;
        assert_eq!(stored(&store)?.settled_inbox_seq, 0, "batch writer validates P");
        store.sweep_delivery_retention(now, false)?;
        assert_eq!(stored(&store)?.settled_inbox_seq, 0, "durable sweep validates P");
        held.definite_non_write();
        later.published_blocking()?;
        store.retain_cursor_checkpoint(&CursorAckState {
            target_delivery_id: "target".into(),
            ..Default::default()
        })?;
        assert_eq!(stored(&store)?.settled_inbox_seq, 2);
        assert_eq!(core.settled_view("target", &id), (2, 2));
        assert!(core.view("target", &id).1.is_empty(), "checkpoint releases reasons");
        drop(held);
        drop(core);
        drop(router);
        drop(store);
        for _ in 0..2 {
            let store = test_store(&root, mode, 1 << 20)?;
            let router = store.load_router()?.ok_or("router")?;
            assert_eq!(router.resume("target", 0, 10), Vec::<crate::InboxEntry>::new());
            assert_eq!(stored(&store)?.settled_inbox_seq, 2);
            assert_eq!(store.publication_core()?.view("target", &id).1, Vec::<(u64, u64)>::new());
            drop(router);
            drop(store);
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

pub(super) fn startup_after_wal_merge() -> Result {
    for mode in 1..=2 {
        let root = fixture(&format!("startup-prefix-{mode}"));
        let store = test_store(&root, mode, 1 << 20)?;
        let id = store.initialize_inbox("target")?;
        // The accepted row exists only in WAL; the redb counter is higher.
        let accepted = entry(2);
        store.record_submission_increment(
            "startup-accepted",
            accepted.envelope.created_at + 3600,
            Some(&accepted),
        )?;
        let tx = store.migration_db().begin_write()?;
        crate::router_store::incarnation::set_cursor(&tx, "target", 9, &id, false)?;
        tx.commit()?;
        drop(store);
        for _ in 0..2 {
            let store = test_store(&root, mode, 1 << 20)?;
            let router = store.load_router()?.ok_or("router")?;
            assert_eq!(
                router.resume("target", 0, 10),
                vec![accepted.clone()],
                "startup must retain WAL-only row"
            );
            assert_eq!(
                stored(&store)?.settled_inbox_seq,
                1,
                "startup R stops below accepted2, not redb issued9"
            );
            assert_eq!(stored(&store)?.issued_inbox_seq, 9);
            drop(router);
            drop(store);
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn retention_mode_oracles() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("retention-mode-{mode}"));
        let store = test_store(&root, mode, 1 << 20)?;
        store.initialize_inbox("target")?;
        let mut expired = entry(4);
        expired.envelope.created_at -= 7200;
        store.record_submission_increment(
            "expired-mode",
            expired.envelope.created_at + 3600,
            Some(&expired),
        )?;
        drop(store);
        let store = test_store(&root, mode, 1 << 20)?;
        let router = store.load_router()?.ok_or("router")?;
        let rows = router.resume("target", 0, 10);
        assert_eq!(
            rows.len(),
            usize::from(mode == 0),
            "expired redb rows restored until sweep; WAL rows omitted"
        );
        assert_eq!(
            router.inbox_snapshot().cursor_state("target").ok_or("cursor")?.issued_inbox_seq,
            4,
            "expired WAL still restores issued floor"
        );
        let now = i64::try_from(crate::now_unix_seconds())?;
        store.sweep_delivery_retention(now, false)?;
        assert_eq!(stored(&store)?.settled_inbox_seq, 4);
        drop(router);
        drop(store);
        for _ in 0..2 {
            let store = test_store(&root, mode, 1 << 20)?;
            let router = store.load_router()?.ok_or("router")?;
            assert_eq!(router.resume("target", 0, 10), Vec::<crate::InboxEntry>::new());
            assert_eq!(store.inbox_status("target")?.1, 4);
            drop(router);
            drop(store);
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn startup_checkpoint_after_wal_merge() -> Result {
    startup_after_wal_merge()
}
