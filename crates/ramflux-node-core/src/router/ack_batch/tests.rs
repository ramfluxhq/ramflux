// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T5/T6/T19: durable equivalence, failure atomicity and guard-bound ACK capacity.
#![allow(clippy::expect_used, clippy::panic, reason = "regression assertions")]
use super::*;
use crate::router_store::{
    incarnation::test_store,
    publication::{
        capture,
        tests::{entry, fixture},
        view_tests::submit,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

pub(super) fn ack(seq: u64) -> ramflux_protocol::Ack {
    let mut ext = ramflux_protocol::Ext::default();
    ext.ext.insert("inbox_seq".into(), serde_json::json!(seq));
    ramflux_protocol::Ack {
        schema: "ramflux.ack.v1".into(),
        version: 1,
        domain: "ramflux.ack.v1".into(),
        ext,
        signed: entry(seq).envelope.signed,
        ack_id: format!("ack-{seq}"),
        envelope_id: format!("entry-{seq}"),
        receiver_device_id: "receiver".into(),
        received_at: 1_760_000_010,
        cursor_after: None,
    }
}
fn seed(
    store: &crate::RouterRedbStore,
    count: u64,
    mode: u8,
    full_window: bool,
) -> std::result::Result<RouterCore, NodeCoreError> {
    let router = RouterCore::new();
    for seq in 1..=count {
        static CREATED: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
        let mut row = entry(seq);
        row.envelope.created_at = *CREATED.get_or_init(|| row.envelope.created_at);
        router.target_shard("target").inbox.restore_pending_entry_until(row, i64::MAX);
    }
    // Build the common precondition offline, then persist it atomically. The
    // measured ACK batch and the sequential comparison below use real writers.
    if full_window {
        for seq in 2..=1025 {
            router.apply_ack_for_target("target", &ack(seq))?;
        }
    }
    store.bootstrap_router(&router)?;
    if mode != 0 {
        let inbox = router.inbox_snapshot();
        for row in inbox.pending_entries() {
            store.record_submission_increment(
                &crate::tests::request_replay_fixture(&format!("seed-{}", row.inbox_seq)),
                row.envelope.created_at + 3600,
                Some(row),
            )?;
        }
    }
    router.prepare_publication_target(store, "target")?;
    Ok(router)
}
fn one(
    router: &RouterCore,
    store: &crate::RouterRedbStore,
    seq: u64,
) -> std::result::Result<CursorAckState, NodeCoreError> {
    let lease = store.acquire_acknowledgement("target")?;
    let cursor = router.apply_ack_for_target("target", &ack(seq))?;
    store.record_leased_ack(&cursor, "", lease)?;
    Ok(cursor)
}
fn pending(router: &RouterCore) -> Vec<u64> {
    router.target_shard("target").inbox.pending_entries().map(|e| e.inbox_seq).collect()
}

#[test]
fn ack_batch_reopen_equivalence() -> Result {
    for mode in 0..=2 {
        let left = fixture(&format!("ack-sequential-{mode}"));
        let right = fixture(&format!("ack-batch-{mode}"));
        let sequential_store = test_store(&left, mode, 1 << 20)?;
        let batch_store = test_store(&right, mode, 1 << 20)?;
        let sequential = seed(&sequential_store, 1089, mode, true)?;
        let batch = seed(&batch_store, 1089, mode, true)?;
        // First member overflows the window and retires head1. Later members clear
        // their own transient retirement lists; the batch writer must retain head1.
        let starts = Arc::new(AtomicUsize::new(0));
        let commits = Arc::new(AtomicUsize::new(0));
        let a = Arc::clone(&starts);
        let b = Arc::clone(&commits);
        let observer = crate::durability_test_hooks::observe(
            right.to_path_buf(),
            Arc::new(move |_, op, done| {
                if done && op == "direct_begin" {
                    a.fetch_add(1, Ordering::Relaxed);
                }
                if done && op == "direct_commit" {
                    b.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            }),
        );
        let acks = (1026..=1089).map(ack).collect::<Vec<_>>();
        let results = batch.apply_ack_batch(&batch_store, "target", &acks)?;
        assert!(results.iter().all(std::result::Result::is_ok));
        assert_eq!(starts.load(Ordering::Relaxed), 1);
        assert_eq!(commits.load(Ordering::Relaxed), 1);
        drop(observer);
        for seq in 1026..=1089 {
            one(&sequential, &sequential_store, seq)?;
        }
        assert_eq!(pending(&batch), Vec::<u64>::new());
        drop(batch);
        drop(sequential);
        drop(batch_store);
        drop(sequential_store);
        let batch_store = test_store(&right, mode, 1 << 20)?;
        let sequential_store = test_store(&left, mode, 1 << 20)?;
        let batch = batch_store.load_router()?.ok_or("batch")?;
        let sequential = sequential_store.load_router()?.ok_or("sequential")?;
        assert_eq!(pending(&batch), pending(&sequential));
        assert!(pending(&batch).is_empty(), "no ACKed or retired row resurrects");
        let a = batch.inbox_snapshot();
        let b = sequential.inbox_snapshot();
        assert_eq!(a.cursor_state("target"), b.cursor_state("target"));
        for store in [&batch_store, &sequential_store] {
            use redb::{ReadableDatabase, ReadableTable};
            let tx = store.migration_db().begin_read()?;
            assert_eq!(tx.open_table(crate::ROUTER_INBOX_ENTRY_TABLE)?.iter()?.count(), 0);
            let expiry: redb::TableDefinition<&str, &[u8]> =
                redb::TableDefinition::new("router_inbox_expiry_v1");
            assert_eq!(tx.open_table(expiry)?.iter()?.count(), 0, "no stale expiry index");
        }
        // Sequence selectors must still resolve idempotent ACKs after reopen.
        for seq in 1..=1089 {
            assert!(batch.apply_ack_for_target("target", &ack(seq)).is_ok());
        }
    }
    Ok(())
}

#[test]
fn guard_blocked_ack_window() -> Result {
    for mode in 0..=2 {
        let root = fixture(&format!("ack-guard-{mode}"));
        let store = test_store(&root, mode, 1 << 20)?;
        let router = RouterCore::new();
        let id = store.initialize_inbox("target")?;
        router.prepare_publication_target(&store, "target")?;
        let core = store.publication_core()?;
        let held = core.reserve("target", &id, &[])?;
        assert_eq!(held.sequence(), 1);
        // Use production allocation and persistence; no waiting on publication at1.
        for seq in 2..=1027 {
            let _ = capture(|| submit(&router, &store, seq, true))?;
        }
        let sequences = (2..=1027).filter(|seq| *seq != 501).collect::<Vec<_>>();
        for chunk in sequences[..1024].chunks(64) {
            let results = router.apply_ack_batch(
                &store,
                "target",
                &chunk.iter().copied().map(ack).collect::<Vec<_>>(),
            )?;
            assert!(results.iter().all(std::result::Result::is_ok));
        }
        let before = router.target_shard("target").inbox.cursor_state("target").cloned();
        let rows = pending(&router);
        let result = router.apply_ack_batch(&store, "target", &[ack(1027)])?;
        assert_eq!(pending(&router), rows, "refused ACK must preserve the skipped live row");
        assert!(matches!(&result[0], Err(NodeCoreError::AckBackpressureRetry)));
        assert!(
            rows.contains(&501) && rows.contains(&1027),
            "both skipped and rejected rows remain live"
        );
        assert_eq!(router.target_shard("target").inbox.cursor_state("target"), before.as_ref());
        assert!(before.as_ref().ok_or("cursor")?.dead_letters.is_empty());
        drop(held);
        // Wait on the resolver's predicate, not a timer that could complete the guard.
        let deadline = Instant::now() + Duration::from_secs(30);
        while core.view("target", &id).0 < 1027 {
            assert!(Instant::now() < deadline, "resolver hang guard");
            std::thread::yield_now();
        }
        let results = router.apply_ack_batch(&store, "target", &[ack(501), ack(1027)])?;
        assert!(results.iter().all(std::result::Result::is_ok));
        assert_eq!(pending(&router), Vec::<u64>::new());
        drop(router);
        drop(core);
        drop(store);
        let store = test_store(&root, mode, 1 << 20)?;
        assert_eq!(pending(&store.load_router()?.ok_or("reopen")?), Vec::<u64>::new());
    }
    Ok(())
}

#[test]
fn ack_batch_atomic_failure() -> Result {
    const CHILD: &str = "RAMFLUX_ACK_BATCH_CHILD";
    if let Some(root) = std::env::var_os(CHILD) {
        return atomic_child(root);
    }
    for mode in 0..=2 {
        // A caller-owned, uncommitted transaction can be discarded without fencing.
        let root = fixture(&format!("ack-precommit-{mode}"));
        let store = test_store(&root, mode, 1 << 20)?;
        let router = seed(&store, 3, mode, false)?;
        let before = pending(&router);
        let cursor_before = router.target_shard("target").inbox.cursor_state("target").cloned();
        let observer = crate::durability_test_hooks::observe(
            root.to_path_buf(),
            Arc::new(|_, op, _| {
                if op == "ack_candidate" {
                    Err(std::io::Error::other("discard candidate"))
                } else {
                    Ok(())
                }
            }),
        );
        assert!(router.apply_ack_batch(&store, "target", &[ack(1), ack(2), ack(3)]).is_err());
        assert_eq!(pending(&router), before, "failed candidate must never replace live inbox");
        assert_eq!(
            router.target_shard("target").inbox.cursor_state("target"),
            cursor_before.as_ref()
        );
        drop(observer);
        drop(router);
        drop(store);
        let store = test_store(&root, mode, 1 << 20)?;
        assert_eq!(pending(&store.load_router()?.ok_or("reopen")?), before);
        for cut in ["failed", "committed"] {
            let root = fixture(&format!("ack-cut-{mode}-{cut}"));
            let mut child = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "router::ack_batch::tests::ack_batch_atomic_failure",
                    "--nocapture",
                ])
                .env(CHILD, &root)
                .env("RAMFLUX_ACK_BATCH_MODE", mode.to_string())
                .env("RAMFLUX_ACK_BATCH_CUT", cut)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    panic!("ACK failure child hang guard");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if cut == "committed" {
                assert_eq!(status.code(), Some(73));
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    assert_eq!(status.signal(), Some(6));
                }
                assert!(!status.success());
            }
            assert!(!root.join("forbidden-success").exists());
            let store = test_store(&root, mode, 1 << 20)?;
            let router = store.load_router()?.ok_or("child reopen")?;
            assert_eq!(pending(&router).len(), if cut == "committed" { 0 } else { 3 });
            if cut == "committed" {
                assert_eq!(
                    router
                        .target_shard("target")
                        .inbox
                        .cursor_state("target")
                        .ok_or("cursor")?
                        .settled_inbox_seq,
                    3
                );
            }
        }
    }
    Ok(())
}

fn atomic_child(root: std::ffi::OsString) -> Result {
    let root = PathBuf::from(root);
    let mode = std::env::var("RAMFLUX_ACK_BATCH_MODE")?.parse::<u8>()?;
    let cut = std::env::var("RAMFLUX_ACK_BATCH_CUT")?;
    let store = test_store(&root, mode, 1 << 20)?;
    let router = seed(&store, 3, mode, false)?;
    let _observer = crate::durability_test_hooks::observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == "direct_commit" {
                if cut == "failed" && !done {
                    return Err(std::io::Error::other("injected ACK commit failure"));
                }
                if cut == "committed" && done {
                    std::process::exit(73);
                }
            }
            Ok(())
        }),
    );
    let result = router.apply_ack_batch(&store, "target", &[ack(1), ack(2), ack(3)]);
    if result.is_ok() {
        std::fs::write(root.join("forbidden-success"), b"success")?;
    }
    std::thread::park();
    Err("child remained serving".into())
}
