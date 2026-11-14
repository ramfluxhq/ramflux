// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture assertions and watchdog failures"
)]

use super::*;
use crate::durability_test_hooks::observe;
use std::sync::atomic::{AtomicBool, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Events = Arc<Mutex<Vec<(PathBuf, String)>>>;

fn fixture(name: &str) -> ramflux_test_support::TestPath {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ramflux_test_support::TestPath::new().expect("test: allocate fixture directory").child(format!(
        "wal-durability-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn capture(root: &Path) -> (crate::durability_test_hooks::Registration, Events) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&events);
    let guard = observe(
        root.to_path_buf(),
        Arc::new(move |path, operation, completed| {
            if completed {
                output.lock().expect("events").push((path.to_path_buf(), operation.to_owned()));
            }
            Ok(())
        }),
    );
    (guard, events)
}

#[test]
fn recovery_sync_before_ready() -> TestResult {
    if std::env::var_os("RAMFLUX_P2_RESTART_CHILD").is_some() {
        return super::identity_tests::restart_crashes();
    }
    if std::env::var_os("RAMFLUX_STARTUP_MATRIX_CHILD").is_some() {
        return super::startup_tests::child();
    }
    if let Some(root) = std::env::var_os("RAMFLUX_RECORD_K_CHILD") {
        return record_k_child(PathBuf::from(root));
    }
    super::identity_tests::restart_crashes()?;
    for pipeline in [false, true] {
        let root = fixture("recovery");
        let wal_root = root.join("wal");
        let shard = router_wal_shard_root(&wal_root, 0);
        fs::create_dir_all(&shard)?;
        // Include legacy root-level segments, multiple shard segments and a repaired tail.
        let paths = [
            router_wal_segment_path(&wal_root, 0),
            router_wal_segment_path(&shard, 0),
            router_wal_segment_path(&shard, 1),
        ];
        for path in &paths {
            fs::write(path, [ROUTER_WAL_MAGIC, &[1, 2, 3]].concat())?;
        }
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "router_wal::durability_tests::recovery_sync_before_ready",
                "--nocapture",
            ])
            .env("RAMFLUX_RECORD_K_CHILD", &shard)
            .env("RAMFLUX_RECORD_K_PIPELINE", if pipeline { "1" } else { "0" })
            .spawn()?;
        wait_for_abort(child)?;
        let (_guard, events) = capture(&root);
        let wal = RouterWalStore::open_with_shards_config(&wal_root, 1, pipeline)?;
        assert_eq!(wal.submissions(0).len(), 2);
        let events = events.lock().expect("events");
        for path in paths.into_iter().chain([router_wal_segment_path(&shard, 2)]) {
            let truncate = events
                .iter()
                .position(|e| e == &(path.clone(), "set_len".into()))
                .expect("tail repair");
            let sync = events
                .iter()
                .position(|e| e == &(path.clone(), "sync_all".into()))
                .expect("recovered file sync");
            assert!(truncate < sync);
        }
        assert!(events.contains(&(shard, "directory_sync".into())));
        assert!(events.contains(&(wal_root, "directory_sync".into())));
        drop(events);
        drop(wal);
        fs::remove_dir_all(root)?;
    }
    super::startup_tests::redb_crashes()?;
    for wal in [false, true] {
        let root = fixture("commit");
        fs::create_dir_all(&root)?;
        let (_guard, events) = capture(&root);
        for _ in 0..2 {
            let store = if wal {
                crate::RouterRedbStore::open_with_wal(root.join("db"), root.join("wal"))?
            } else {
                crate::RouterRedbStore::open_without_wal(root.join("db"))?
            };
            assert!(store.load_router()?.is_none());
        }
        assert_eq!(
            events
                .lock()
                .expect("events")
                .iter()
                .filter(|(_, op)| op == "immediate_commit")
                .count(),
            2
        );
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn segment_directory_before_ack() -> TestResult {
    super::fatal_tests::first_segment_failures()?;
    if std::env::var_os("RAMFLUX_FATAL_CHILD").is_some() {
        return Ok(());
    }
    super::identity_tests::head_matrix()?;
    super::segment_tests::matrix()?;
    for pipeline in [false, true] {
        let root = fixture("segment");
        let (_guard, events) = capture(&root);
        let mut writer = RouterWalWriterState::open(root.join("shard"), 0, 0, 1)?;
        let payload = RouterWalPayload::Submission {
            replay_key: crate::tests::request_replay_fixture("key"),
            replay_expires_at: i64::MAX,
            entry: None,
            accepted_at: Some(router_wal_now()),
            local_delivery: None,
        };
        for _ in 0..2 {
            if pipeline {
                let group = writer.append_batch_no_sync(std::slice::from_ref(&payload))?;
                sync_router_wal_files(&group.sync_files)?;
            } else {
                writer.append_batch(std::slice::from_ref(&payload))?;
            }
            let segment = router_wal_segment_path(&writer.root, writer.segment_id);
            let events = events.lock().expect("events");
            let header = events
                .iter()
                .position(|e| e == &(segment.clone(), "header_write".into()))
                .expect("header write");
            let sync = events
                .iter()
                .position(|e| e == &(segment.clone(), "sync_all".into()))
                .expect("header sync");
            assert!(header < sync);
            assert!(
                events
                    .iter()
                    .skip(sync + 1)
                    .any(|e| e == &(writer.root.clone(), "directory_sync".into()))
            );
        }
        drop(writer);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn held_directory_sync_blocks_segment_open() -> TestResult {
    let root = fixture("held");
    fs::create_dir_all(&root)?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let expected = root.clone();
    let _guard = observe(
        root.to_path_buf(),
        Arc::new(move |path, op, completed| {
            if path == expected && op == "directory_sync" && !completed {
                entered_tx.send(()).map_err(io::Error::other)?;
                release_rx
                    .lock()
                    .expect("release")
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(io::Error::other)?;
            }
            Ok(())
        }),
    );
    let worker_root = root.clone();
    let worker = thread::spawn(move || {
        let writer =
            RouterWalWriterState::open(worker_root.to_path_buf(), 0, 0, 1024).expect("open");
        done_tx.send(()).expect("done");
        writer
    });
    entered_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(done_rx.try_recv().is_err());
    release_tx.send(())?;
    drop(worker.join().expect("worker"));
    done_rx.recv_timeout(Duration::from_secs(5))?;
    Ok(())
}

#[test]
fn failed_recovery_sync_refuses_open() -> TestResult {
    let Some(child_root) = std::env::var_os("RAMFLUX_FAILED_RECOVERY_CHILD") else {
        let root = fixture("failed");
        let directory = root.parent().ok_or("test: crash fixture has no directory")?.to_path_buf();
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "router_wal::durability_tests::failed_recovery_sync_refuses_open",
                "--nocapture",
            ])
            .env("RAMFLUX_FAILED_RECOVERY_CHILD", &root)
            .spawn()?;
        wait_for_abort(child)?;
        drop(root);
        assert!(!directory.exists(), "parent must clean the fixture after the child aborts");
        return Ok(());
    };
    let root = PathBuf::from(child_root);
    fs::create_dir_all(&root)?;
    let segment = router_wal_segment_path(&root, 0);
    fs::write(&segment, ROUTER_WAL_MAGIC)?;
    let reached = Arc::new(AtomicBool::new(false));
    let reached_hook = Arc::clone(&reached);
    let _guard = observe(
        root.clone(),
        Arc::new(move |_, op, completed| {
            if op == "sync_all" && !completed {
                reached_hook.store(true, Ordering::SeqCst);
                return Err(io::Error::other("injected recovery sync failure"));
            }
            Ok(())
        }),
    );
    let _ = RouterWalStore::open_with_shards_config(&root, 1, false);
    loop {
        thread::park_timeout(Duration::from_secs(1));
    }
}

#[test]
fn interrupted_roll_empty_header() -> TestResult {
    if std::env::var_os("RAMFLUX_P3_QUARANTINE_CHILD").is_some() {
        return super::maintenance_tests::quarantine_matrix();
    }
    if std::env::var_os("RAMFLUX_P2_ROTATION_CHILD").is_some() {
        return super::identity_tests::loss_matrix();
    }
    if let Some(root) = std::env::var_os("RAMFLUX_EMPTY_HEADER_CHILD") {
        let root = PathBuf::from(root);
        let wal = RouterWalStore::open_with_shards_config(&root, 1, false)?;
        let entry = super::tests::router_wal_inbox_entry("ack-before-crash", "residue-target");
        wal.record_submission(
            &crate::tests::request_replay_fixture("ack-before-crash"),
            i64::MAX,
            Some(&entry),
        )?;
        let kind = std::env::var("RAMFLUX_EMPTY_HEADER_KIND")?;
        let residue = match kind.as_str() {
            "empty" => Vec::new(),
            "partial" => b"ramflux".to_vec(),
            "zero" => vec![0; ROUTER_WAL_MAGIC.len()],
            _ => vec![b'x'; ROUTER_WAL_MAGIC.len()],
        };
        fs::write(router_wal_segment_path(&root, 1), residue)?;
        std::process::abort();
    }
    super::maintenance_tests::quarantine_matrix()?;
    super::identity_tests::loss_matrix()?;
    for kind in ["empty", "partial", "zero", "torn"] {
        let root = fixture("residue");
        fs::create_dir_all(&root)?;
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "router_wal::durability_tests::interrupted_roll_empty_header",
                "--nocapture",
            ])
            .env("RAMFLUX_EMPTY_HEADER_CHILD", &root)
            .env("RAMFLUX_EMPTY_HEADER_KIND", kind)
            .spawn()?;
        wait_for_abort(child)?;
        for _ in 0..2 {
            let wal = RouterWalStore::open_with_shards_config(&root, 1, false)?;
            assert_eq!(wal.submissions(0).len(), 1);
        }
        fs::write(
            router_wal_segment_path(&root, 1),
            [vec![0; ROUTER_WAL_MAGIC.len()], vec![1, 2, 3]].concat(),
        )?;
        assert!(RouterWalStore::open_with_shards_config(&root, 1, false).is_err());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn wait_for_abort(mut child: std::process::Child) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(!status.success());
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(6));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("crash child watchdog");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn record_k_child(root: PathBuf) -> TestResult {
    let mut writer = RouterWalWriterState::open(root.clone(), 2, 0, u64::MAX)?;
    let record_count = std::sync::atomic::AtomicUsize::new(0);
    let _guard = observe(
        root,
        Arc::new(move |_, operation, completed| {
            if operation == "record_write"
                && !completed
                && record_count.fetch_add(1, Ordering::SeqCst) == 2
            {
                return Err(io::Error::other("record-k failure"));
            }
            Ok(())
        }),
    );
    let payloads: Vec<_> = (0..3)
        .map(|index| RouterWalPayload::Submission {
            replay_key: crate::tests::request_replay_fixture(&format!("crash-{index}")),
            replay_expires_at: i64::MAX,
            entry: Some(Box::new(super::tests::router_wal_inbox_entry(
                &format!("crash-{index}"),
                "recovery-target",
            ))),
            accepted_at: Some(router_wal_now()),
            local_delivery: None,
        })
        .collect();
    let failed = if std::env::var("RAMFLUX_RECORD_K_PIPELINE").as_deref() == Ok("1") {
        writer.append_batch_no_sync(&payloads).is_err()
    } else {
        writer.append_batch(&payloads).is_err()
    };
    assert!(failed);
    loop {
        thread::park_timeout(Duration::from_secs(1));
    }
}
