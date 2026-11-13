// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P2 real-store lifecycle, recovery loss, upgrade and head ordering fixtures.
#![allow(clippy::expect_used, clippy::panic, reason = "crash and ordering test assertions")]
use super::*;
use crate::{
    RouterRedbStore, durability_test_hooks::observe, router_store::incarnation::test_store,
};
use redb::ReadableDatabase;
use std::sync::atomic::{AtomicBool, Ordering};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn fixture(name: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "p2-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}
fn entry(seq: u64) -> InboxEntry {
    let mut row = super::tests::router_wal_inbox_entry("p2-row", "p2-target");
    row.inbox_seq = seq;
    row.envelope.created_at = 1_800_000_000;
    row
}
fn row(store: &RouterRedbStore, seq: u64) -> std::result::Result<(), NodeCoreError> {
    store.record_submission_increment(
        &crate::tests::request_replay_fixture(&format!("row-{seq}")),
        i64::MAX,
        Some(&entry(seq)),
    )?;
    Ok(())
}
pub(crate) fn lifecycle() -> Result {
    for mode in 0..3 {
        let root = fixture("lifecycle");
        let store = test_store(&root, mode, u64::MAX)?;
        assert_eq!(store.inbox_status("unknown")?, (None, 0));
        let unknown = crate::CursorAckState {
            target_delivery_id: "unknown".into(),
            last_acknowledged_inbox_seq: Some(1),
            ..crate::CursorAckState::default()
        };
        store.record_ack_increment(&unknown, "absent")?;
        store.record_nack_increment(&unknown)?;
        assert_eq!(store.inbox_status("unknown")?, (None, 0));
        assert!(store.load_delivery_state(0)?.0.cursor_state("unknown").is_none());
        let empty = store.initialize_inbox("empty")?;
        assert_eq!(store.inbox_status("empty")?, (Some(empty.clone()), 0));
        row(&store, 7)?;
        let (id, issued) = store.inbox_status("p2-target")?;
        let id = id.expect("durable E");
        assert_eq!(issued, 7);
        assert_ne!(id, empty);
        let router = store.load_router()?.expect("router");
        assert_eq!(router.inbox_snapshot().incarnation_id("p2-target"), Some(id.as_str()));
        let cursor = router.inbox_snapshot().cursor_state("p2-target").expect("cursor").clone();
        store.retain_cursor_checkpoint(&cursor)?;
        store.record_nack_increment(&cursor)?;
        drop(store);
        for _ in 0..2 {
            let store = test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            assert_eq!(store.inbox_status("p2-target")?, (Some(id.clone()), 7));
            assert_eq!(store.inbox_status("empty")?, (Some(empty.clone()), 0));
            assert_eq!(store.inbox_status("unknown")?, (None, 0));
            assert_eq!(
                store.load_delivery_state(0)?.0.pull_after("p2-target", 0, 10),
                vec![entry(7)]
            );
        }
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
pub(crate) fn upgrade() -> Result {
    for mode in [1, 2] {
        for legacy_root in [false, true] {
            let root = fixture("upgrade");
            fs::create_dir_all(&root)?;
            // Exact legacy WAL encoder and bare header; no association or incarnation metadata.
            let store = test_store(&root, 0, u64::MAX)?;
            let mut inbox = crate::OpaqueDeviceInbox::new();
            inbox.observe_issued_seq("p2-target", 70);
            let mut cursor = inbox.cursor_state("p2-target").expect("cursor").clone();
            cursor.settled_inbox_seq = 30;
            store.retain_cursor_checkpoint(&cursor)?;
            drop(store);
            let wal = root.join("wal");
            let directory = if legacy_root { wal.clone() } else { router_wal_shard_root(&wal, 0) };
            fs::create_dir_all(&directory)?;
            write_current_router_wal_segment(&directory, "legacy-row", i64::MAX, &entry(50))?;
            let rotated = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&rotated);
            let guard = observe(
                root.clone(),
                Arc::new(move |_, op, _| {
                    if op == "rotation_pending" {
                        observed.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                }),
            );
            let store = test_store(&root, mode, u64::MAX)?;
            let router = store.load_router()?.expect("upgraded router");
            assert!(!rotated.load(Ordering::SeqCst), "pre-S6 upgrade must not rotate");
            drop(guard);
            assert!(
                fs::read(router_wal_segment_path(&directory, 0))?.starts_with(ROUTER_WAL_MAGIC)
            );
            let tx = store.migration_db().begin_read()?;
            let snapshots = tx.open_table(crate::ROUTER_SNAPSHOT_TABLE)?;
            let metadata: serde_json::Value = serde_json::from_slice(
                snapshots.get("session_push_wal_v1")?.expect("association").value(),
            )?;
            let key = if legacy_root { "" } else { "router-wal-shard-0000" };
            assert_eq!(metadata["chains"][key]["legacy"], serde_json::json!([0]));
            assert_eq!(metadata["chains"][key]["anchor"], 0);
            assert_eq!(metadata["chains"][key]["head"], 0);
            assert_eq!(
                metadata["directory_id"].as_str(),
                Some(fs::read_to_string(wal.join("identity"))?.as_str())
            );
            drop(snapshots);
            drop(tx);
            let id = store.inbox_status("p2-target")?.0.expect("upgraded E");
            assert_eq!(store.inbox_status("p2-target")?.1, 70);
            assert_eq!(
                router
                    .inbox_snapshot()
                    .cursor_state("p2-target")
                    .expect("cursor")
                    .settled_inbox_seq,
                49,
                "finalized legacy WAL merge stops the sparse prefix below live row50"
            );
            assert_eq!(router.inbox_snapshot().pull_after("p2-target", 30, 10), vec![entry(50)]);
            row(&store, 71)?; // Existing legacy tail, no roll.
            drop(store);
            let store = test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            assert_eq!(store.inbox_status("p2-target")?, (Some(id.clone()), 71));
            assert_eq!(
                store.load_delivery_state(0)?.0.pull_after("p2-target", 50, 10),
                vec![entry(71)]
            );
            drop(store);
            // The now-recorded legacy root tail is required even when it has no successor.
            fs::remove_file(router_wal_segment_path(&directory, 0))?;
            let store = test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            assert_ne!(store.inbox_status("p2-target")?.0, Some(id));
            drop(store);
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}
pub(super) fn head_matrix() -> Result {
    retired_anchor()?;
    for mode in [1, 2] {
        for roll in [false, true] {
            let root = fixture("head");
            let segment = router_wal_segment_path(
                &router_wal_shard_root(&root.join("wal"), 0),
                u64::from(roll),
            );
            let store = if roll {
                let store = test_store(&root, mode, 1)?;
                row(&store, 1)?;
                Some(store)
            } else {
                None
            };
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release = Mutex::new(release_rx);
            let appended = Arc::new(AtomicBool::new(false));
            let hook_appended = Arc::clone(&appended);
            let armed = Arc::new(AtomicBool::new(true));
            let hook_segment = segment.clone();
            let _guard = observe(
                root.clone(),
                Arc::new(move |path, op, done| {
                    if path == hook_segment
                        && op == "head_commit"
                        && !done
                        && armed.swap(false, Ordering::SeqCst)
                    {
                        entered_tx.send(()).map_err(io::Error::other)?;
                        release
                            .lock()
                            .expect("release")
                            .recv_timeout(Duration::from_secs(10))
                            .map_err(io::Error::other)?;
                    }
                    if path == hook_segment && op == "record_write" {
                        hook_appended.store(true, Ordering::SeqCst);
                    }
                    Ok(())
                }),
            );
            let worker_root = root.clone();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = thread::spawn(move || -> std::result::Result<(), NodeCoreError> {
                let store = match store {
                    Some(store) => store,
                    None => test_store(&worker_root, mode, 1)?,
                };
                row(&store, if roll { 2 } else { 1 })?;
                done_tx.send(()).map_err(identity::error)?;
                Ok(())
            });
            entered_rx.recv_timeout(Duration::from_secs(10))?;
            assert!(!appended.load(Ordering::SeqCst), "append escaped held real head commit");
            assert!(done_rx.try_recv().is_err());
            release_tx.send(())?;
            done_rx.recv_timeout(Duration::from_secs(10))?;
            worker.join().expect("writer")?;
            assert!(appended.load(Ordering::SeqCst));
            let store = test_store(&root, mode, u64::MAX)?;
            let id = store.inbox_status("p2-target")?.0.expect("E");
            store.load_router()?;
            drop(store);
            let store = test_store(&root, mode, u64::MAX)?;
            assert_eq!(store.inbox_status("p2-target")?.0, Some(id));
            drop(store);
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}
pub(super) fn loss_matrix() -> Result {
    if let Some(root) = std::env::var_os("RAMFLUX_P2_ROTATION_CHILD") {
        return rotation_child(Path::new(&root));
    }
    for mode in [1, 2] {
        for loss in ["head", "gap", "identity", "directory", "equality", "metadata"] {
            let root = fixture("loss");
            let store = test_store(&root, mode, 1)?;
            row(&store, 1)?;
            row(&store, 2)?;
            row(&store, 3)?;
            let old = store.inbox_status("p2-target")?.0.expect("E");
            store.load_router()?;
            drop(store);
            let wal = root.join("wal");
            let shard = router_wal_shard_root(&wal, 0);
            match loss {
                "head" => fs::remove_file(router_wal_segment_path(&shard, 2))?,
                "gap" => fs::remove_file(router_wal_segment_path(&shard, 1))?,
                "identity" => fs::write(wal.join("identity"), "00000000000000000000000000000000")?,
                "directory" => fs::remove_dir_all(&wal)?,
                "equality" => {
                    let raw = test_store(&root, 0, u64::MAX)?;
                    let txn = raw.migration_db().begin_write()?;
                    crate::router_store::incarnation::set_cursor(
                        &txn,
                        "p2-target",
                        3,
                        &crate::router_store::incarnation::new_id()?,
                        true,
                    )?;
                    txn.commit()?;
                }
                _ => {
                    let raw = test_store(&root, 0, u64::MAX)?;
                    let txn = raw.migration_db().begin_write()?;
                    {
                        txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)?
                            .remove("session_push_wal_v1")?;
                    }
                    txn.commit()?;
                }
            }
            let store = test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            let new = store.inbox_status("p2-target")?.0.expect("rotated E");
            assert_ne!(new, old, "required recorded segment loss must rotate E");
            crate::session_push::tests::reject_stale(&store, "p2-target", &old)?;
            drop(store);
            let store = test_store(&root, mode, u64::MAX)?;
            assert_eq!(
                store.inbox_status("p2-target")?.0,
                Some(new),
                "second restart mode={mode} loss={loss}"
            );
            drop(store);
            fs::remove_dir_all(root)?;
        }
        crash_rotations(mode)?;
        for residue in [Vec::new(), b"ramflux".to_vec(), vec![0; identity::HEADER_LEN]] {
            let root = fixture("empty-recorded");
            let store = test_store(&root, mode, u64::MAX)?;
            let old = store.initialize_inbox("p2-target")?;
            drop(store);
            let path = router_wal_segment_path(&router_wal_shard_root(&root.join("wal"), 0), 0);
            fs::write(&path, residue)?;
            for _ in 0..2 {
                let store = test_store(&root, mode, u64::MAX)?;
                assert_eq!(store.inbox_status("p2-target")?.0, Some(old.clone()));
                drop(store);
            }
            fs::remove_file(&path)?;
            let store = test_store(&root, mode, u64::MAX)?;
            assert_ne!(store.inbox_status("p2-target")?.0, Some(old));
            drop(store);
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}
fn rotation_child(root: &Path) -> Result {
    let mode = std::env::var("RAMFLUX_P2_MODE")?.parse()?;
    let operation = std::env::var("RAMFLUX_P2_CUT")?;
    let _guard = observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == operation && done {
                std::process::abort();
            }
            Ok(())
        }),
    );
    let _store = test_store(root, mode, u64::MAX)?;
    panic!("rotation crash cut not reached");
}
fn wait_abort(mut child: std::process::Child) -> Result {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(!status.success());
            return Ok(());
        }
        if Instant::now() > deadline {
            child.kill()?;
            panic!("child watchdog");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn restart_crashes() -> Result {
    if let Some(root) = std::env::var_os("RAMFLUX_P2_RESTART_CHILD") {
        let root = PathBuf::from(root);
        let mode = std::env::var("RAMFLUX_P2_MODE")?.parse()?;
        let store = test_store(&root, mode, u64::MAX)?;
        row(&store, 7)?;
        fs::write(root.join("original-E"), store.inbox_status("p2-target")?.0.expect("E"))?;
        std::process::abort();
    }
    for mode in 0..3 {
        let root = fixture("restart");
        fs::create_dir_all(&root)?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "router_wal::durability_tests::recovery_sync_before_ready"])
            .env("RAMFLUX_P2_RESTART_CHILD", &root)
            .env("RAMFLUX_P2_MODE", mode.to_string())
            .spawn()?;
        wait_abort(child)?;
        let original = fs::read_to_string(root.join("original-E"))?;
        let store = test_store(&root, mode, u64::MAX)?;
        let router = store.load_router()?.expect("router");
        assert_eq!(store.inbox_status("p2-target")?, (Some(original.clone()), 7));
        assert_eq!(router.inbox_snapshot().incarnation_id("p2-target"), Some(original.as_str()));
        assert_eq!(router.inbox_snapshot().pull_after("p2-target", 0, 10), vec![entry(7)]);
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
pub(crate) fn empty_head_crash() -> Result {
    for mode in [1, 2] {
        let root = fixture("empty-head-crash");
        let store = test_store(&root, mode, u64::MAX)?;
        row(&store, 1)?;
        store.load_router()?;
        let old = store.inbox_status("p2-target")?.0.expect("E");
        let wal = store.submission_wal.as_ref().expect("WAL");
        let association = wal.association.as_ref().expect("association");
        let directory = router_wal_shard_root(&root.join("wal"), 0);
        let path = router_wal_segment_path(&directory, 1);
        let header = identity::header(Some(association), &directory, 1)?;
        fs::write(&path, &header)?;
        File::open(&path)?.sync_all()?;
        durability_io::sync_dir(&directory)?;
        association.record_head(&directory, 1)?;
        drop(store);
        fs::write(&path, &header[..30])?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "router_wal::durability_tests::interrupted_roll_empty_header"])
            .env("RAMFLUX_P2_ROTATION_CHILD", &root)
            .env("RAMFLUX_P2_MODE", mode.to_string())
            .env("RAMFLUX_P2_CUT", "empty_head_repair")
            .spawn()?;
        wait_abort(child)?;
        let store = test_store(&root, mode, u64::MAX)?;
        store.load_router()?;
        assert_eq!(store.inbox_status("p2-target")?.0, Some(old.clone()));
        row(&store, 2)?;
        let rows = store.submission_wal.as_ref().expect("WAL").submissions(0);
        assert_eq!(
            rows.iter()
                .find(|row| row.entry.as_ref().is_some_and(|entry| entry.inbox_seq == 2))
                .expect("new row")
                .location
                .segment_id,
            1
        );
        drop(store);
        let store = test_store(&root, mode, u64::MAX)?;
        assert_eq!(store.inbox_status("p2-target")?, (Some(old), 2));
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn crash_rotations(mode: u8) -> Result {
    for operation in ["rotation_pending", "rotation_segment", "association_commit"] {
        let root = fixture("crash-rotation");
        let store = test_store(&root, mode, 1)?;
        row(&store, 1)?;
        row(&store, 2)?;
        let old = store.inbox_status("p2-target")?.0.expect("E");
        store.load_router()?;
        drop(store);
        fs::remove_file(router_wal_segment_path(&router_wal_shard_root(&root.join("wal"), 0), 1))?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "router_wal::durability_tests::interrupted_roll_empty_header",
                "--nocapture",
            ])
            .env("RAMFLUX_P2_ROTATION_CHILD", &root)
            .env("RAMFLUX_P2_MODE", mode.to_string())
            .env("RAMFLUX_P2_CUT", operation)
            .spawn()?;
        wait_abort(child)?;
        let store = test_store(&root, mode, u64::MAX)?;
        store.load_router()?;
        let new = store.inbox_status("p2-target")?.0.expect("E");
        assert_ne!(old, new);
        drop(store);
        let store = test_store(&root, mode, u64::MAX)?;
        assert_eq!(store.inbox_status("p2-target")?.0, Some(new));
        drop(store);
        fs::remove_dir_all(root)?;
    }

    Ok(())
}

fn retired_anchor() -> Result {
    use redb::ReadableDatabase;
    for mode in [1, 2] {
        let root = fixture("anchor");
        let store = test_store(&root, mode, 1)?;
        let mut expired = entry(1);
        expired.envelope.created_at = 0;
        store.record_submission_increment(
            &crate::tests::request_replay_fixture("expired"),
            i64::MAX,
            Some(&expired),
        )?;
        row(&store, 2)?;
        row(&store, 3)?;
        store.load_router()?;
        let id = store.inbox_status("p2-target")?.0.expect("E");
        let directory = router_wal_shard_root(&root.join("wal"), 0);
        let wal = store.submission_wal.as_ref().expect("WAL");
        let association = wal.association.as_ref().expect("association");
        assert!(association.retire(&directory, 0)?);
        assert!(router_wal_segment_path(&directory, 0).exists(), "anchor commit precedes unlink");
        {
            let txn = store.migration_db().begin_read()?;
            let table = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)?;
            let metadata: serde_json::Value = serde_json::from_slice(
                table.get("session_push_wal_v1")?.expect("association").value(),
            )?;
            assert_eq!(metadata["chains"]["router-wal-shard-0000"]["anchor"], 1);
        }
        drop(store);
        fs::write(router_wal_segment_path(&directory, 0), b"obsolete bytes are ignored")?;
        let store = test_store(&root, mode, u64::MAX)?;
        let router = store.load_router()?.expect("router");
        assert_eq!(store.inbox_status("p2-target")?, (Some(id), 3));
        assert_eq!(
            router
                .inbox_snapshot()
                .pull_after("p2-target", 0, 10)
                .iter()
                .map(|entry| entry.inbox_seq)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
