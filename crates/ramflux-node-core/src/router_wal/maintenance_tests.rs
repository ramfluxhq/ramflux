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
    store.bootstrap_router(&router)?;
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

#[test]
fn review_probe_rotate_then_quarantine() -> Result {
    for mode in [1, 2] {
        let root = fixture();
        let old = seed(&root, mode)?;
        torn(&root, false)?;
        let failure = rotate(&root, mode, false).expect_err("plain rotation requires quarantine");
        assert!(failure.to_string().contains(&segment(&root).display().to_string()));
        assert!(
            failure.to_string().contains("--rotate-inbox-incarnations --quarantine-wal-segment")
        );
        assert!(!operator_marker_exists(&root)?, "plain rotation must not poison the marker");
        rotate(&root, mode, true)?;
        assert!(!operator_marker_exists(&root)?);
        let store = test_store(&root, mode, 1)?;
        store.load_router()?;
        assert_ne!(store.inbox_status("restore-target")?.0.as_ref(), Some(&old[0]));
        drop(store);
        // The inverse order also completes without ignoring a prior request.
        rotate(&root, mode, false)?;
        let store = test_store(&root, mode, 1)?;
        store.load_router()?;
        drop(store);
        assert!(!operator_marker_exists(&root)?);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn operator_marker_exists(root: &Path) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    let db = redb::Database::open(root.join("db"))?;
    let tx = db.begin_read()?;
    Ok(tx.open_table(crate::ROUTER_SNAPSHOT_TABLE)?.get(MARKER)?.is_some())
}

#[test]
fn rotation_preflight_refuses_other_damage() -> Result {
    for mode in [1, 2] {
        let root = fixture();
        let old = seed(&root, mode)?;
        torn(&root, false)?;
        let other = other_segment(&root)?;
        let healthy = fs::read(&other)?;
        let damaged = fs::read(segment(&root))?;
        let failure = RouterRedbStore::rotate_inbox_incarnations_at(
            &root.join("db"),
            Some(&root.join("wal")),
            Some(&other),
        )
        .expect_err("wrong segment must not hide actual damage");
        assert!(matches!(failure, NodeCoreError::WalSegmentRequiresQuarantine { path, .. }
            if path == segment(&root)));
        assert!(!operator_marker_exists(&root)?);
        assert_eq!(fs::read(&other)?, healthy);
        assert_eq!(fs::read(segment(&root))?, damaged);
        fs::write(&other, vec![b'x'; identity::HEADER_LEN + 80])?;
        let failure = rotate(&root, mode, true).expect_err("two damaged segments refuse up front");
        assert!(matches!(failure, NodeCoreError::WalSegmentRequiresQuarantine { path, .. }
            if path == other));
        assert_eq!(raw(&root)?, (old, false));
        assert!(segment(&root).exists() && other.exists());
        assert!(!root.join("wal/quarantine").exists());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn other_segment(root: &Path) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let shard = router_wal_shard_root(&root.join("wal"), 0);
    router_wal_segment_ids(&shard)?
        .into_iter()
        .map(|id| router_wal_segment_path(&shard, id))
        .find(|path| *path != segment(root))
        .ok_or_else(|| "missing second segment".into())
}

const REPAIR: &str = "router_wal::maintenance_tests::pending_rotation_quarantine_repair";
#[test]
fn pending_rotation_quarantine_repair() -> Result {
    if let Ok(root) = std::env::var("RAMFLUX_P3_REPAIR_CHILD") {
        let mode: u8 = std::env::var("RAMFLUX_P3_MODE")?.parse()?;
        let cut = std::env::var("RAMFLUX_P3_CUT")?;
        let _observer = observe(
            PathBuf::from(&root),
            Arc::new(move |_, operation, done| {
                if done && operation == cut {
                    std::process::abort();
                }
                Ok(())
            }),
        );
        rotate(Path::new(&root), mode, std::env::var("RAMFLUX_P3_REPAIR_QUARANTINE").is_ok())?;
        panic!("repair crash cut not reached");
    }
    for mode in [1, 2] {
        for cut in ["none", "operator_quarantine_amend", "quarantine_rename", "association_commit"]
        {
            let root = fixture();
            let old = seed(&root, mode)?;
            crash_repair_command(&root, mode, "operator_rotation_pending", false)?;
            assert_eq!(raw(&root)?, (old.clone(), true));
            // A preflight-complete plain marker models an older interrupted pass.
            // The later damaged segment must be incorporated, never ignored.
            torn(&root, false)?;
            if cut == "none" {
                rotate(&root, mode, true)?;
            } else {
                crash_repair_command(&root, mode, cut, true)?;
            }
            if cut == "operator_quarantine_amend" {
                let conflict = RouterRedbStore::rotate_inbox_incarnations_at(
                    &root.join("db"),
                    Some(&root.join("wal")),
                    Some(&other_segment(&root)?),
                )
                .expect_err("unfinished move must not be replaced");
                assert!(conflict.to_string().contains("unfinished pending move"));
                assert!(operator_marker_exists(&root)? && segment(&root).exists());
            }
            if cut == "quarantine_rename" {
                // Retry the exact argument after its source was already moved.
                rotate(&root, mode, true)?;
            } else {
                // Plain rotation must honour the pending quarantine on resume.
                rotate(&root, mode, false)?;
            }
            assert_repair_complete(&root, mode, &old)?;
            fs::remove_dir_all(root)?;
        }
        completed_move_can_amend(&fixture(), mode)?;
    }
    Ok(())
}

fn crash_repair_command(root: &Path, mode: u8, cut: &str, quarantine: bool) -> Result {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["--exact", REPAIR])
        .env("RAMFLUX_P3_REPAIR_CHILD", root)
        .env("RAMFLUX_P3_MODE", mode.to_string())
        .env("RAMFLUX_P3_CUT", cut)
        .stdout(std::process::Stdio::null());
    if quarantine {
        command.env("RAMFLUX_P3_REPAIR_QUARANTINE", "1");
    } else {
        command.env_remove("RAMFLUX_P3_REPAIR_QUARANTINE");
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(6), "real crash at {cut}");
            }
            assert!(!status.success());
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("repair crash watchdog at {cut}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_repair_complete(root: &Path, mode: u8, old: &[String]) -> Result {
    let (new, pending) = raw(root)?;
    assert!(!pending);
    assert!(new.iter().zip(old).all(|(a, b)| a != b));
    for _ in 0..2 {
        let store = test_store(root, mode, 1)?;
        store.load_router()?;
        assert_eq!(store.inbox_status("restore-target")?, (Some(new[0].clone()), 2));
    }
    Ok(())
}

fn completed_move_can_amend(root: &Path, mode: u8) -> Result {
    let old = seed(root, mode)?;
    torn(root, false)?;
    let other = other_segment(root)?;
    crash_repair_command(root, mode, "quarantine_rename", true)?;
    assert!(operator_marker_exists(root)?);
    assert!(!segment(root).exists());
    fs::write(&other, vec![b'x'; identity::HEADER_LEN + 80])?;
    RouterRedbStore::rotate_inbox_incarnations_at(
        &root.join("db"),
        Some(&root.join("wal")),
        Some(&other),
    )?;
    assert_repair_complete(root, mode, &old)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn review_low_l1_refuses_healthy_and_anchor_quarantine() -> Result {
    for mode in [1, 2] {
        let root = fixture();
        let old = seed(&root, mode)?;
        let shard = router_wal_shard_root(&root.join("wal"), 0);
        let paths: Vec<_> = router_wal_segment_ids(&shard)?
            .into_iter()
            .map(|id| router_wal_segment_path(&shard, id))
            .collect();
        assert!(paths.len() >= 2, "anchor and another healthy segment");
        let originals: Vec<_> = paths.iter().map(fs::read).collect::<io::Result<_>>()?;
        for path in &paths {
            let store = test_store(&root, mode, 1)?;
            store.load_router()?;
            drop(store);
            RouterRedbStore::rotate_inbox_incarnations_at(
                &root.join("db"),
                Some(&root.join("wal")),
                Some(path),
            )
            .expect_err("ordinary open accepts this healthy segment, including the anchor");
            assert_eq!(raw(&root)?, (old.clone(), false));
            for (path, bytes) in paths.iter().zip(&originals) {
                assert_eq!(&fs::read(path)?, bytes);
            }
            assert!(!root.join("wal/quarantine").exists());
        }
        // A plain pending marker cannot bypass quarantine admission either.
        crash_repair_command(&root, mode, "operator_rotation_pending", false)?;
        RouterRedbStore::rotate_inbox_incarnations_at(
            &root.join("db"),
            Some(&root.join("wal")),
            Some(&paths[0]),
        )
        .expect_err("pending rotation must also refuse a healthy quarantine source");
        assert!(operator_marker_exists(&root)?);
        for (path, bytes) in paths.iter().zip(&originals) {
            assert_eq!(&fs::read(path)?, bytes);
        }
        rotate(&root, mode, false)?;
        assert!(!operator_marker_exists(&root)?);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

const LEGACY_E: &str = "0123456789abcdef0123456789abcdef";
fn legacy_maintenance_image(root: &Path, corrupt_tuple: bool) -> Result {
    fs::create_dir_all(root)?;
    let db = redb::Database::create(root.join("db"))?;
    let tx = db.begin_write()?;
    let cursor = crate::router_store::incarnation::StoredCursor {
        cursor: crate::CursorAckState {
            target_delivery_id: "restore-target".into(),
            issued_inbox_seq: 7,
            ..crate::CursorAckState::default()
        },
        inbox_incarnation_id: Some(LEGACY_E.into()),
    };
    tx.open_table(crate::ROUTER_CURSOR_STATE_TABLE)?
        .insert("restore-target", serde_json::to_vec(&cursor)?.as_slice())?;
    if corrupt_tuple {
        // This older image already has expiry indexes. Isolate failure in the
        // tuple upgrade, after schema initialization and incarnation import.
        let format: redb::TableDefinition<&str, u8> =
            redb::TableDefinition::new("router_expiry_index_format_v1");
        tx.open_table(format)?.insert("version", 3)?;
    }
    let payload = if corrupt_tuple {
        b"broken".to_vec()
    } else {
        serde_json::to_vec(
            &serde_json::json!({"target_delivery_id":"restore-target","expires_at":1_900_000_000}),
        )?
    };
    tx.open_table(crate::ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?
        .insert("s:4:rootid", payload.as_slice())?;
    let source = ramflux_protocol::qualified_device_id("root", "device")?;
    let replay = format!("envelope/v2/{source}/{}", ramflux_protocol::encode_base64url("id"));
    tx.open_table(crate::ROUTER_REPLAY_TUPLE_TABLE)?
        .insert(replay.as_str(), b"1900000000".as_slice())?;
    tx.commit()?;
    Ok(())
}

#[test]
fn review_low_l2_maintenance_runs_ordinary_open_prelude() -> Result {
    for mode in 0..=2 {
        for corrupt in [false, true] {
            let root = fixture();
            legacy_maintenance_image(&root, corrupt)?;
            let result = rotate(&root, mode, false);
            if corrupt {
                assert!(result.is_err(), "tuple upgrade must fail before reading pending/marking");
            } else {
                assert_eq!(result?, 1, "maintenance must initialize a legacy schema itself");
            }
            assert_maintenance_upgrades(&root, corrupt)?;
            if !corrupt {
                let store = test_store(&root, mode, 1)?;
                assert_eq!(store.inbox_status("restore-target")?.1, 7);
                store.load_router()?;
                drop(store);
            }
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

fn assert_maintenance_upgrades(root: &Path, corrupt: bool) -> Result {
    let db = redb::Database::open(root.join("db"))?;
    let tx = db.begin_read()?;
    // These tables were absent, proving schema initialization ran before pending.
    tx.open_table(crate::ROUTER_SESSION_ENTRY_TABLE)?;
    let snapshots = tx.open_table(crate::ROUTER_SNAPSHOT_TABLE)?;
    assert!(snapshots.get(MARKER)?.is_none());
    let row = tx
        .open_table(crate::router_store::incarnation_state::TABLE)?
        .get("restore-target")?
        .expect("cursor-field incarnation imported before tuple upgrade");
    let (id, issued) = crate::router_store::incarnation_state::decode(row.value())?;
    assert_eq!(issued, 7);
    if corrupt {
        assert_eq!(id, LEGACY_E, "import precedes failed tuple upgrade without rotating");
        assert!(snapshots.get("router_envelope_tuple_v3")?.is_none());
        assert!(!root.join("wal").exists());
    } else {
        assert_ne!(id, LEGACY_E);
        assert!(snapshots.get("router_envelope_tuple_v3")?.is_some());
        let deliveries = tx.open_table(crate::ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?;
        assert!(deliveries.get("s:4:rootid")?.is_none());
        let target = ramflux_protocol::encode_base64url("restore-target");
        let key = format!(
            "v3/{}/{}/{target}",
            ramflux_protocol::encode_base64url("root"),
            ramflux_protocol::encode_base64url("id")
        );
        assert!(deliveries.get(key.as_str())?.is_some());
        let source = ramflux_protocol::qualified_device_id("root", "device")?;
        let old = format!("envelope/v2/{source}/{}", ramflux_protocol::encode_base64url("id"));
        let new =
            format!("envelope/v3/{source}/{}/{target}", ramflux_protocol::encode_base64url("id"));
        let replay = tx.open_table(crate::ROUTER_REPLAY_TUPLE_TABLE)?;
        assert!(replay.get(old.as_str())?.is_none());
        assert!(replay.get(new.as_str())?.is_some());
    }
    Ok(())
}
