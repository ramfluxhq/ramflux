// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fatal paths run in isolated processes; the parent checks both death and disk.
#![allow(clippy::expect_used, clippy::panic, reason = "fault injection and child watchdog")]
use super::*;
use crate::{RouterRedbStore, durability_test_hooks::observe};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn entry(seq: u64) -> InboxEntry {
    let mut entry = super::tests::router_wal_inbox_entry(&format!("fatal-{seq}"), "fatal-target");
    entry.inbox_seq = seq;
    entry.envelope.created_at = i64::try_from(crate::now_unix_seconds()).expect("time");
    entry
}
fn payload(seq: u64) -> RouterWalPayload {
    RouterWalPayload::Submission {
        replay_key: format!("fatal-{seq}"),
        replay_expires_at: i64::MAX,
        entry: Some(Box::new(entry(seq))),
        accepted_at: None,
        local_delivery: None,
    }
}
fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "fatal-{label}-{}-{}",
        std::process::id(),
        crate::now_unix_seconds()
    ))
}
fn command(name: &str, root: &Path, case: &str, mode: u8) -> Command {
    let mut cmd = Command::new(std::env::current_exe().expect("test exe"));
    cmd.args(["--exact", &format!("router_wal::fatal_tests::{name}"), "--nocapture"])
        .env("RAMFLUX_FATAL_CHILD", root)
        .env("RAMFLUX_FATAL_CASE", case)
        .env("RAMFLUX_FATAL_MODE", mode.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}
fn wait_abort(child: Child) -> TestResult {
    wait_abort_kind(child, "fatal_")
}
fn wait_abort_kind(mut child: Child, marker: &str) -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        if let Some(status) = child.try_wait()? {
            assert_eq!(status.signal(), Some(6), "expected supervisor SIGABRT, got {status}");
            let output = child.wait_with_output()?;
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(marker),
                "fatal metadata log absent"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("fatal child watchdog");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn wait_file(root: &Path, name: &str, child: &mut Child) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.join(name).exists() {
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_string(&mut stderr)?;
            }
            panic!("child exited before {name}: {status}; {stderr}");
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("barrier {name}");
        }
        thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}
fn child_config() -> Option<(PathBuf, String, u8)> {
    Some((
        PathBuf::from(std::env::var_os("RAMFLUX_FATAL_CHILD")?),
        std::env::var("RAMFLUX_FATAL_CASE").expect("case"),
        std::env::var("RAMFLUX_FATAL_MODE").expect("mode").parse().expect("mode number"),
    ))
}
fn park() -> ! {
    loop {
        thread::park_timeout(Duration::from_secs(1));
    }
}

#[test]
#[allow(clippy::too_many_lines, reason = "error-site matrix with isolated child legs")]
fn uncertain_write_fail_stop() -> TestResult {
    if let Some((root, case, mode)) = child_config() {
        fs::create_dir_all(&root)?;
        if case.starts_with("redb_")
            || matches!(case.as_str(), "ack" | "nack" | "checkpoint" | "startup" | "rotation")
        {
            return redb_child(&root, &case, mode);
        }
        let store = crate::router_store::incarnation::test_store(
            &root,
            mode,
            if case.starts_with("roll")
                || matches!(case.as_str(), "header_write" | "head_commit" | "directory_sync")
            {
                1
            } else {
                u64::MAX
            },
        )?;
        store.record_submission_increment("before", i64::MAX, Some(&entry(1)))?;
        if case == "writer_channel_loss" {
            let (sender, receiver) = mpsc::sync_channel(1);
            drop(receiver);
            let writer = RouterWalWriter {
                shards: vec![RouterWalWriterShard {
                    sender: Some(sender),
                    thread: None,
                    fsync_thread: None,
                }],
            };
            let _ = writer.append(payload(2));
            park();
        }
        if case == "index_lock" {
            let wal = store.submission_wal.as_ref().expect("wal");
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _held = wal.state.lock().expect("state");
                panic!("poison the real index mutex");
            }));
            let _response = enqueue(&store, entry(2), mode)?;
            park();
        }
        if case == "fsync_channel_loss" {
            let wal = store.submission_wal.as_ref().expect("wal");
            let recovered = recover_router_wal(&root.join("wal"))?;
            let shard = recovered.shards.get(&0).expect("shard");
            let writer = RouterWalWriterState::open_associated(
                router_wal_shard_root(&root.join("wal"), 0),
                shard.last_segment_id.expect("segment"),
                shard.current_offset,
                u64::MAX,
                wal.association.clone(),
            )?;
            let (sender, receiver) = mpsc::sync_channel(1);
            let (reply, _response) = mpsc::sync_channel(1);
            sender.send(RouterWalAppendRequest {
                payload: payload(2),
                reply: RouterWalAppendReply::Sync(reply),
            })?;
            let (fsync_sender, fsync_receiver) = mpsc::sync_channel(1);
            drop(fsync_receiver);
            router_wal_pipeline_writer_loop(writer, &receiver, fsync_sender, 1, Duration::ZERO);
            park();
        }
        let count = AtomicUsize::new(0);
        let selected = if case == "wal_panic" { "wal_serialize".to_owned() } else { case.clone() };
        let inject_panic = case == "wal_panic";
        let _observer = observe(
            root.clone(),
            Arc::new(move |path, op, done| {
                if op == selected
                    && !done
                    && (count.fetch_add(1, Ordering::SeqCst)
                        == if selected.starts_with("wal_") || selected.starts_with("record_") {
                            2
                        } else {
                            0
                        })
                {
                    assert!(!inject_panic, "panic after earlier batch members wrote");
                    if selected.starts_with("record_") {
                        let mut file = OpenOptions::new().append(true).open(path)?;
                        file.write_all(&[0xA5, 0x5A])?;
                    }
                    return Err(io::Error::other("in-writer injected fault"));
                }
                Ok(())
            }),
        );
        if case.starts_with("wal_") || case.starts_with("record_") {
            // The actual writer batch has already written earlier members.
            let wal = store.submission_wal.as_ref().expect("wal");
            let directory = router_wal_shard_root(&root.join("wal"), 0);
            let recovered = recover_router_wal(&root.join("wal"))?;
            let shard = recovered.shards.get(&0).expect("shard");
            let mut writer = RouterWalWriterState::open_associated(
                directory,
                shard.last_segment_id.expect("segment"),
                shard.current_offset,
                u64::MAX,
                wal.association.clone(),
            )?;
            let batch = [payload(2), payload(3), payload(4)];
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if mode == 2 {
                    let _ = writer.append_batch_no_sync(&batch);
                } else {
                    let _ = writer.append_batch(&batch);
                }
            }));
            // If a mutation classifies the failed conversion as definite non-write,
            // returning normally is observable by the parent instead of a fake abort.
            if crate::fatal_durability::check().is_err() {
                park();
            }
            return Ok(());
        }
        let _ = store.record_submission_increment("fault", i64::MAX, Some(&entry(2)));
        park();
    }
    for mode in [1, 2] {
        for case in [
            "wal_convert",
            "wal_serialize",
            "wal_frame_len",
            "wal_panic",
            "writer_channel_loss",
            "index_lock",
            "fsync_channel_loss",
            "record_length",
            "record_crc",
            "record_payload",
            "sync_all",
            "roll_open",
            "header_write",
            "head_commit",
            "directory_sync",
            "index_update",
            "writer_reply",
            "fsync_enqueue",
        ] {
            if matches!(case, "fsync_enqueue" | "fsync_channel_loss") && mode == 1 {
                continue;
            }
            let root = root(&format!("{mode}-{case}"));
            wait_abort(command("uncertain_write_fail_stop", &root, case, mode).spawn()?)?;
            let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            assert!(
                store.load_delivery_state(0)?.0.pending_entries().any(|row| row.inbox_seq == 1),
                "pre-fence success lost: {case}"
            );
            let core = store.publication_core()?;
            let id = store.inbox_status("fatal-target")?.0.expect("incarnation");
            assert!(core.view("fatal-target", &id).1.is_empty(), "uncertain bytes were tombstoned");
            drop(core);
            drop(store);
            fs::remove_dir_all(root)?;
        }
    }
    for case in [
        "redb_begin",
        "redb_apply",
        "redb_commit",
        "redb_panic",
        "ack",
        "nack",
        "checkpoint",
        "startup",
        "rotation",
    ] {
        let root = root(case);
        wait_abort(command("uncertain_write_fail_stop", &root, case, 0).spawn()?)?;
        let store = RouterRedbStore::open_without_wal(root.join("db"))?;
        store.load_router()?;
        assert!(store.load_delivery_state(0)?.0.pending_entries().any(|row| row.inbox_seq == 1));
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn redb_child(root: &Path, case: &str, mode: u8) -> TestResult {
    let store = crate::router_store::incarnation::test_store(root, mode, u64::MAX)?;
    store.record_submission_increment("before", i64::MAX, Some(&entry(1)))?;
    let selected = match case {
        "redb_begin" => "begin_write",
        "redb_apply" | "redb_panic" => "commit_apply",
        "redb_commit" => "commit",
        "ack" | "nack" => "direct_commit",
        "checkpoint" => "checkpoint_commit",
        "startup" => "immediate_commit",
        "rotation" => "rotation_commit",
        _ => unreachable!(),
    };
    let panic = case == "redb_panic";
    let _observer = observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == selected && !done {
                assert!(!panic, "panic inside held redb transaction");
                return Err(io::Error::other("redb writer injected fault"));
            }
            Ok(())
        }),
    );
    let mut cursor = crate::CursorAckState {
        target_delivery_id: "fatal-target".into(),
        ..crate::CursorAckState::default()
    };
    cursor.inbox_seq = 1;
    cursor.issued_inbox_seq = 1;
    cursor.last_acknowledged_inbox_seq = Some(1);
    match case {
        "ack" => {
            let _ = store.record_ack_increment(&cursor, "fatal-1");
        }
        "nack" => {
            let _ = store.record_nack_increment(&cursor);
        }
        "checkpoint" => {
            let _ = store.retain_cursor_checkpoint(&cursor);
        }
        "startup" => {
            let _ = store.load_router();
        }
        "rotation" => {
            drop(store);
            let _ = RouterRedbStore::rotate_inbox_incarnations_at(&root.join("db"), None, None);
            park();
        }
        _ => {
            let _ = store.record_submission_increment("fault", i64::MAX, Some(&entry(2)));
        }
    }
    park();
}

#[test]
fn guard_tombstone_storage_fault() -> TestResult {
    if let Some((root, _, mode)) = child_config() {
        let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
        let id = store.initialize_inbox("fatal-target")?;
        let core = store.publication_core()?;
        let _observer = observe(
            root,
            Arc::new(|_, op, done| {
                if op == "tombstone_commit" && !done {
                    return Err(io::Error::other("tombstone fault"));
                }
                Ok(())
            }),
        );
        drop(core.reserve("fatal-target", &id, &[])?);
        park();
    }
    for mode in 0..=2 {
        let root = root(&format!("tombstone-{mode}"));
        wait_abort_kind(
            command("guard_tombstone_storage_fault", &root, "tombstone", mode).spawn()?,
            "fatal_tombstone_persistence",
        )?;
        let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
        store.load_router()?;
        assert_eq!(store.inbox_status("fatal-target")?.1, 0);
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines, reason = "queued and pipeline fence child plus disk oracle")]
fn writer_fence_blocks_later_batch() -> TestResult {
    if let Some((root, _, mode)) = child_config() {
        fs::create_dir_all(&root)?;
        let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
        store.record_submission_increment("before", i64::MAX, Some(&entry(1)))?;
        let id = store.inbox_status("fatal-target")?.0.expect("E");
        let core = store.publication_core()?;
        let first = core.reserve("fatal-target", &id, &[])?;
        let success = first.hand_off().expect("handoff");
        store.record_submission_increment("held-success", i64::MAX, Some(&entry(2)))?;
        let op = if mode == 0 { "commit" } else { "sync_all" };
        let (entered, reached) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        let resume = Mutex::new(resume);
        let faulted = Arc::new(AtomicBool::new(false));
        let mark = Arc::clone(&faulted);
        let (appended, appended_rx) = mpsc::channel();
        let writes = AtomicUsize::new(0);
        let _observer = observe(
            root.clone(),
            Arc::new(move |_, operation, done| {
                assert!(crate::fatal_durability::check().is_ok(), "physical operation after fence");
                if operation == "record_write" && done && writes.fetch_add(1, Ordering::SeqCst) == 1
                {
                    appended.send(()).map_err(io::Error::other)?;
                }
                if operation == op && !done && !mark.swap(true, Ordering::SeqCst) {
                    entered.send(()).map_err(io::Error::other)?;
                    resume
                        .lock()
                        .expect("release receiver")
                        .recv_timeout(Duration::from_secs(10))
                        .map_err(io::Error::other)?;
                    return Err(io::Error::other("batch1 fault"));
                }
                Ok(())
            }),
        );
        // Both operations are handed to the actual bounded production queue.
        // No request task is needed to observe or classify the failed completion.
        let response1 = enqueue(&store, entry(3), mode)?;
        reached.recv_timeout(Duration::from_secs(10))?;
        let mut later = entry(4);
        later.target_delivery_id = "other-target".into();
        later.envelope.target_delivery_id = later.target_delivery_id.clone();
        let response2 = enqueue(&store, later, mode)?;
        if mode == 2 {
            appended_rx.recv_timeout(Duration::from_secs(10))?;
        }
        release.send(())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while crate::fatal_durability::check().is_ok() {
            assert!(Instant::now() < deadline, "writer fence watchdog");
            thread::yield_now();
        }
        assert!(faulted.load(Ordering::SeqCst));
        // Park both notifications until after the writer has already fenced.
        assert!(!response1.recv_timeout(Duration::from_secs(1)).is_ok_and(|result| result.is_ok()));
        assert!(
            !response2.recv_timeout(Duration::from_millis(50)).is_ok_and(|result| result.is_ok())
        );
        assert_eq!(
            store.inbox_status("other-target")?.1,
            0,
            "queued completion advanced issued view"
        );
        success.accepted_durable();
        assert_eq!(core.view("fatal-target", &id).0, 1, "stale Ok crossed final gate");
        assert!(store.record_submission_increment("later", i64::MAX, Some(&entry(4))).is_err());
        assert!(core.reserve("fatal-target", &id, &[]).is_err());
        fs::write(root.join("checked"), [])?;
        park();
    }
    for mode in 0..=2 {
        let root = root(&format!("fence-{mode}"));
        fs::create_dir_all(&root)?;
        let mut child = command("writer_fence_blocks_later_batch", &root, "fence", mode)
            .env("RAMFLUX_FATAL_HOLD", &root)
            .env("RAMFLUX_ROUTER_GROUP_COMMIT", if mode == 0 { "1" } else { "0" })
            .env("RAMFLUX_ROUTER_COMMIT_WINDOW_US", "0")
            .spawn()?;
        wait_file(&root, "fenced", &mut child)?;
        wait_file(&root, "checked", &mut child)?;
        fs::write(root.join("abort"), [])?;
        wait_abort(child)?;
        let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
        store.load_router()?;
        assert!(store.load_delivery_state(0)?.0.pending_entries().any(|row| row.inbox_seq == 1));
        assert!(store.load_delivery_state(0)?.0.pending_entries().any(|row| row.inbox_seq == 2));
        if mode != 2 {
            assert!(
                !store.load_delivery_state(0)?.0.pending_entries().any(|row| row.inbox_seq == 4)
            );
        }
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

pub(crate) fn panic_in_write() -> TestResult {
    let root = root("panic-closure");
    wait_abort(command("uncertain_write_fail_stop", &root, "redb_panic", 0).spawn()?)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn first_segment_failures() -> TestResult {
    if let Some((root, case, mode)) = child_config() {
        let selected = case.strip_prefix("first_").expect("first case").to_owned();
        fs::create_dir_all(&root)?;
        let _observer = observe(
            root.clone(),
            Arc::new(move |path, op, done| {
                let segment =
                    path.file_name().is_some_and(|name| name.to_string_lossy().ends_with(".wal"));
                if op == selected && !done && (segment || op == "directory_sync") {
                    return Err(io::Error::other("first segment failure"));
                }
                Ok(())
            }),
        );
        let _ = crate::router_store::incarnation::test_store(&root, mode, u64::MAX);
        park();
    }
    for mode in [1, 2] {
        for case in
            ["first_header_write", "first_sync_all", "first_directory_sync", "first_head_commit"]
        {
            let root = root(&format!("{case}-{mode}"));
            let mut cmd = Command::new(std::env::current_exe()?);
            cmd.args([
                "--exact",
                "router_wal::durability_tests::segment_directory_before_ack",
                "--nocapture",
            ])
            .env("RAMFLUX_FATAL_CHILD", &root)
            .env("RAMFLUX_FATAL_CASE", case)
            .env("RAMFLUX_FATAL_MODE", mode.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
            wait_abort(cmd.spawn()?)?;
            let store = crate::router_store::incarnation::test_store(&root, mode, u64::MAX)?;
            store.load_router()?;
            drop(store);
            fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

fn enqueue(
    store: &RouterRedbStore,
    entry: InboxEntry,
    mode: u8,
) -> Result<mpsc::Receiver<Result<(), NodeCoreError>>, NodeCoreError> {
    if mode == 0 {
        return store.enqueue_fence_test(entry);
    }
    let wal = store.submission_wal.as_ref().expect("wal");
    let payload = RouterWalPayload::Submission {
        replay_key: entry.envelope.envelope_id.clone(),
        replay_expires_at: i64::MAX,
        entry: Some(Box::new(entry)),
        accepted_at: None,
        local_delivery: None,
    };
    let shard = wal.writer.shard_for_payload(&payload)?;
    let (reply, response) = mpsc::sync_channel(1);
    wal.writer.submit(
        shard,
        RouterWalAppendRequest { payload, reply: RouterWalAppendReply::Sync(reply) },
    )?;
    let (done, normalized) = mpsc::sync_channel(1);
    thread::spawn(move || {
        if let Ok(value) = response.recv() {
            let _ = done.send(value.map(|_| ()));
        }
    });
    Ok(normalized)
}
