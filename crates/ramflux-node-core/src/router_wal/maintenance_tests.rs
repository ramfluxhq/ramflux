// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operator recovery at real marker, rename and transaction crash cuts.
#![allow(clippy::expect_used, clippy::panic, reason = "crash fixture assertions")]
use super::*;
use crate::{
    RouterRedbStore, durability_test_hooks::observe, router_store::incarnation::test_store,
};
use redb::{ReadableDatabase, ReadableTable};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const MARKER: &str = "session_push_rotation_pending_v1";
const T20: &str = "router_wal::durability_tests::interrupted_roll_empty_header";
fn fixture() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fs::canonicalize(std::env::temp_dir()).expect("temporary root").join(format!(
        "p3-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}
fn entry(seq: u64) -> InboxEntry {
    let mut entry = super::tests::router_wal_inbox_entry("restore-row", "restore-target");
    entry.inbox_seq = seq;
    entry.envelope.created_at = 1_800_000_000;
    entry
}
fn seed(root: &Path, mode: u8) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    let store = test_store(root, mode, 1)?;
    store.record_submission_increment("row-1", i64::MAX, Some(&entry(1)))?;
    store.record_submission_increment("row-2", i64::MAX, Some(&entry(2)))?;
    let ids =
        vec![store.inbox_status("restore-target")?.0.expect("E"), store.initialize_inbox("empty")?];
    store.load_router()?;
    Ok(ids)
}
fn segment(root: &Path) -> PathBuf {
    router_wal_segment_path(&router_wal_shard_root(&root.join("wal"), 0), 1)
}
fn torn(root: &Path, chained: bool) -> io::Result<()> {
    let mut bytes = fs::read(segment(root))?;
    if chained {
        bytes[identity::HEADER_LEN - 48] = b'!';
    } else {
        bytes = vec![b'x'; identity::HEADER_LEN + 80];
    }
    fs::write(segment(root), bytes)
}
fn rotate(root: &Path, mode: u8, quarantine: bool) -> std::result::Result<usize, NodeCoreError> {
    RouterRedbStore::rotate_inbox_incarnations_at(
        &root.join("db"),
        (mode != 0).then(|| root.join("wal")).as_deref(),
        quarantine.then(|| segment(root)).as_deref(),
    )
}
fn raw(root: &Path) -> std::result::Result<(Vec<String>, bool), Box<dyn std::error::Error>> {
    let db = redb::Database::open(root.join("db"))?;
    let txn = db.begin_read()?;
    let table = txn.open_table(crate::router_store::incarnation_state::TABLE)?;
    let mut ids = Vec::new();
    for target in ["restore-target", "empty"] {
        let bytes = table.get(target)?.expect("canonical inbox identity");
        ids.push(crate::router_store::incarnation_state::decode(bytes.value())?.0);
    }
    let pending = txn.open_table(crate::ROUTER_SNAPSHOT_TABLE)?.get(MARKER)?.is_some();
    Ok((ids, pending))
}
#[test]
fn wal_identity_and_restore_rotation() -> Result {
    damaged_associations()?;
    for mode in 0..3 {
        let root = fixture();
        let old = seed(&root, mode)?;
        prior_cursor_field_store(&root, mode, &old)?;
        assert_eq!(rotate(&root, mode, false)?, 2);
        let (new, pending) = raw(&root)?;
        assert!(!pending);
        assert!(new.iter().zip(&old).all(|(a, b)| a != b));
        for _ in 0..2 {
            let store = test_store(&root, mode, 1)?;
            let router = store.load_router()?.expect("router");
            assert_eq!(store.inbox_status("restore-target")?, (Some(new[0].clone()), 2));
            assert_eq!(
                router.inbox_snapshot().incarnation_id("restore-target"),
                Some(new[0].as_str())
            );
            assert_eq!(
                router.inbox_snapshot().pull_after("restore-target", 0, 10),
                vec![entry(1), entry(2)]
            );
            let cursor = crate::CursorAckState {
                target_delivery_id: "restore-target".into(),
                last_acknowledged_inbox_seq: Some(1),
                acked_inbox_seqs: BTreeSet::from([1]),
                ..crate::CursorAckState::default()
            };
            // The same sequence is still pending under the new E: an old intent cannot ACK it.
            let error = store
                .record_ack_for_incarnation(&cursor, "restore-row", &old[0])
                .expect_err("stale ACK");
            assert!(error.to_string().contains("incarnation_mismatch"));
            assert_eq!(
                store.load_delivery_state(0)?.0.pull_after("restore-target", 0, 10).len(),
                2
            );
            assert_eq!(store.inbox_status("unknown")?, (None, 0));
        }
        let store = test_store(&root, mode, 1)?;
        let mut replacement = entry(1);
        replacement.envelope.encrypted_payload = "new-incarnation-content".into();
        store.record_inbox_entry(&replacement)?;
        let cursor = crate::CursorAckState {
            target_delivery_id: "restore-target".into(),
            last_acknowledged_inbox_seq: Some(1),
            acked_inbox_seqs: BTreeSet::from([1]),
            ..crate::CursorAckState::default()
        };
        assert!(
            store
                .record_ack_for_incarnation(&cursor, "restore-row", &old[0])
                .expect_err("old intent on reused sequence")
                .to_string()
                .contains("incarnation_mismatch")
        );
        assert_eq!(
            store.load_delivery_state(0)?.0.pull_after("restore-target", 0, 1),
            vec![replacement]
        );
        store.record_ack_for_incarnation(&cursor, "restore-row", &new[0])?;
        assert_eq!(
            store.load_delivery_state(0)?.0.pull_after("restore-target", 0, 10),
            vec![entry(2)]
        );
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

pub(super) fn quarantine_matrix() -> Result {
    if let Some(root) = std::env::var_os("RAMFLUX_P3_QUARANTINE_CHILD") {
        let root = PathBuf::from(root);
        let operation = std::env::var("RAMFLUX_P3_CUT")?;
        let mode = std::env::var("RAMFLUX_P3_MODE")?.parse()?;
        let _guard = observe(
            root.clone(),
            Arc::new(move |_, op, done| {
                if op == operation && done {
                    std::process::abort();
                }
                Ok(())
            }),
        );
        rotate(&root, mode, true)?;
        panic!("cut not reached");
    }
    for mode in [1, 2] {
        for cut in [
            "none",
            "operator_rotation_pending",
            "quarantine_rename",
            "rotation_pending",
            "rotation_segment",
            "association_commit",
        ] {
            let root = fixture();
            let old = seed(&root, mode)?;
            torn(&root, mode == 2)?;
            let error = match test_store(&root, mode, 1) {
                Ok(_) => panic!("torn+data accepted"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(&segment(&root).display().to_string()));
            assert!(error.contains("--quarantine-wal-segment"));
            if cut == "none" {
                successful_quarantine(&root, mode, &old)?;
            } else {
                let mut child = std::process::Command::new(std::env::current_exe()?)
                    .args(["--exact", T20])
                    .env("RAMFLUX_P3_QUARANTINE_CHILD", &root)
                    .env("RAMFLUX_P3_MODE", mode.to_string())
                    .env("RAMFLUX_P3_CUT", cut)
                    .stdout(std::process::Stdio::null())
                    .spawn()?;
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    if let Some(status) = child.try_wait()? {
                        assert!(!status.success());
                        break;
                    }
                    if Instant::now() >= deadline {
                        child.kill()?;
                        child.wait()?;
                        panic!("quarantine child watchdog");
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                let (after, pending) = raw(&root)?;
                if cut != "association_commit" {
                    assert!(pending, "marker survives {cut}");
                }
                if ["operator_rotation_pending", "quarantine_rename"].contains(&cut) {
                    assert_eq!(after, old);
                } else {
                    assert!(after.iter().zip(&old).all(|(a, b)| a != b), "never mixed E");
                }
            }
            let store = test_store(&root, mode, 1)?;
            store.load_router()?;
            let new = store.inbox_status("restore-target")?.0.expect("new E");
            assert_ne!(new, old[0]);
            assert_eq!(store.inbox_status("restore-target")?.1, 2);
            // A valid extra segment inside quarantine is never replayed either.
            let ignored = root.join("wal/quarantine");
            super::write_legacy_router_wal_segment(&ignored, "ignored", i64::MAX, &entry(99))?;
            drop(store);
            let store = test_store(&root, mode, 1)?;
            store.load_router()?;
            assert_eq!(store.inbox_status("restore-target")?, (Some(new), 2));
            drop(store);
            assert!(!raw(&root)?.1);
            assert!(
                !segment(&root).exists()
                    || fs::read(segment(&root))?.starts_with(b"ramflux-router-wal-v2\n")
            );
            assert!(fs::read_dir(ignored)?.any(|file| {
                file.is_ok_and(|file| file.file_name().to_string_lossy().contains(".wal"))
            }));
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

fn successful_quarantine(root: &Path, mode: u8, old: &[String]) -> Result {
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let _guard = observe(
        root.to_path_buf(),
        Arc::new(move |path, op, done| {
            if done {
                captured.lock().expect("events").push((path.to_path_buf(), op.to_owned()));
            }
            Ok(())
        }),
    );
    let original = fs::read(segment(root))?;
    assert_eq!(rotate(root, mode, true)?, 2);
    // Read redb before any ordinary open: M43 cannot be hidden by gap detection.
    let (new, pending) = raw(root)?;
    assert!(!pending);
    let files =
        fs::read_dir(root.join("wal/quarantine"))?.collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 1, "quarantined segment retained before ordinary startup");
    assert_eq!(fs::read(files[0].path())?, original);
    assert!(new.iter().zip(old).all(|(a, b)| a != b), "command must rotate before ordinary start");
    let e = events.lock().expect("events");
    let pos = |path: &Path, operation: &str| {
        e.iter().position(|(p, op)| p == path && op == operation).expect(operation)
    };
    let mkdir = pos(&root.join("wal/quarantine"), "mkdir");
    let rename = pos(&segment(root), "quarantine_rename");
    assert!(mkdir < rename);
    assert!(
        e[mkdir + 1..rename].iter().any(|(p, op)| p == &root.join("wal") && op == "directory_sync"),
        "quarantine parent fsync must precede rename"
    );
    assert!(pos(&root.join("db"), "operator_rotation_pending") < mkdir);
    for directory in [root.join("wal/quarantine"), router_wal_shard_root(&root.join("wal"), 0)] {
        assert!(e[rename + 1..].iter().any(|(p, op)| p == &directory && op == "directory_sync"));
    }
    Ok(())
}

fn damaged_associations() -> Result {
    for mode in [1, 2] {
        for loss in ["identity", "directory", "anchor", "chain"] {
            let root = fixture();
            let old = seed(&root, mode)?;
            let wal = root.join("wal");
            match loss {
                "identity" => fs::write(wal.join("identity"), "00000000000000000000000000000000")?,
                "directory" => fs::remove_dir_all(&wal)?,
                "anchor" => {
                    fs::remove_file(router_wal_segment_path(&router_wal_shard_root(&wal, 0), 0))?;
                }
                _ => {
                    let path = segment(&root);
                    let mut bytes = fs::read(&path)?;
                    bytes[identity::HEADER_LEN - 8..identity::HEADER_LEN]
                        .copy_from_slice(&99_u64.to_le_bytes());
                    fs::write(path, bytes)?;
                }
            }
            assert_eq!(rotate(&root, mode, false)?, 2);
            let (new, pending) = raw(&root)?;
            assert!(!pending);
            assert!(new.iter().zip(&old).all(|(a, b)| a != b), "loss={loss}");
            for _ in 0..2 {
                let store = test_store(&root, mode, 1)?;
                store.load_router()?;
                assert_eq!(store.inbox_status("restore-target")?, (Some(new[0].clone()), 2));
            }
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

/// The operator entrypoint must work without an ordinary open to migrate the schema.
fn prior_cursor_field_store(root: &Path, mode: u8, ids: &[String]) -> Result {
    let store = test_store(root, mode, 1)?;
    let router = store.load_router()?.expect("router");
    store.save_router(&router)?;
    drop(store);
    let db = redb::Database::open(root.join("db"))?;
    let tx = db.begin_write()?;
    {
        let cursors = tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?;
        for (target, id) in ["restore-target", "empty"].iter().zip(ids) {
            let bytes = cursors.get(*target)?.expect("prior cursor field");
            let stored: crate::router_store::incarnation::StoredCursor =
                serde_json::from_slice(bytes.value())?;
            assert_eq!(stored.inbox_incarnation_id.as_deref(), Some(id.as_str()));
        }
    }
    assert!(tx.delete_table(crate::router_store::incarnation_state::TABLE)?);
    tx.commit()?;
    Ok(())
}
