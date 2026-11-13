// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual writer acknowledgement channels, including pipeline fsync handoff.
#![allow(clippy::expect_used, reason = "test assertions and worker joins")]
use super::*;
use crate::durability_test_hooks::observe;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn store(root: &Path, pipeline: bool) -> std::result::Result<RouterWalStore, NodeCoreError> {
    let recovered = recover_router_wal(root)?;
    let state = Arc::new(Mutex::new(recovered.state));
    // A tiny segment limit exercises the real production writer and fsync loops.
    let writer = RouterWalWriter::start(root, 1, 1, &recovered.shards, &state, pipeline)?;
    Ok(RouterWalStore { root: root.to_path_buf(), state, writer, association: None })
}
pub(super) fn matrix() -> Result {
    for pipeline in [false, true] {
        new_ancestor_order(pipeline)?;
        for roll in [false, true] {
            for operation in ["header_write", "sync_all", "directory_sync"] {
                held_boundary(pipeline, roll, operation)?;
            }
        }
    }
    Ok(())
}
fn held_boundary(pipeline: bool, roll: bool, operation: &'static str) -> Result {
    let root = std::env::temp_dir()
        .join(format!("segment-matrix-{}-{pipeline}-{roll}-{operation}", std::process::id()));
    fs::create_dir_all(&root)?;
    let shard = router_wal_shard_root(&root, 0);
    fs::create_dir_all(&shard)?;
    let segment = router_wal_segment_path(&shard, u64::from(roll));
    let target = if operation == "directory_sync" { shard.clone() } else { segment.clone() };
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(!roll));
    let hook_armed = Arc::clone(&armed);
    let hook_segment = segment.clone();
    let _guard = observe(
        root.clone(),
        Arc::new(move |path, op, completed| {
            let header_ready = operation != "directory_sync"
                || log
                    .lock()
                    .expect("events")
                    .iter()
                    .any(|event| event == &(hook_segment.clone(), "header_write".into()));
            if header_ready
                && path == target
                && op == operation
                && !completed
                && hook_armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                entered_tx.send(()).map_err(io::Error::other)?;
                release_rx
                    .lock()
                    .expect("release")
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(io::Error::other)?;
            }
            if completed {
                log.lock().expect("events").push((path.to_path_buf(), op.to_owned()));
            }
            Ok(())
        }),
    );
    let (ack_tx, ack_rx) = mpsc::channel();
    let worker_root = root.clone();
    let worker = thread::spawn(move || -> std::result::Result<(), NodeCoreError> {
        let wal = store(&worker_root, pipeline)?;
        if roll {
            wal.record_submission(&crate::tests::request_replay_fixture("first"), i64::MAX, None)?;
            armed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let location = wal.record_submission(
            &crate::tests::request_replay_fixture("observed"),
            i64::MAX,
            None,
        )?;
        ack_tx.send(location).map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        Ok(())
    });
    entered_rx.recv_timeout(Duration::from_secs(10))?;
    assert!(
        ack_rx.try_recv().is_err(),
        "ack escaped held {operation} (roll={roll}, pipeline={pipeline})"
    );
    release_tx.send(())?;
    let location = ack_rx.recv_timeout(Duration::from_secs(10))?;
    assert_eq!(location.segment_id, u64::from(roll));
    worker.join().expect("writer")?;
    let log = events.lock().expect("events");
    let position = |path: &Path, op: &str| {
        log.iter()
            .position(|event| event == &(path.to_path_buf(), op.to_owned()))
            .expect("required completion before ack")
    };
    let header = position(&segment, "header_write");
    let file_sync = position(&segment, "sync_all");
    let directory_sync = log
        .iter()
        .enumerate()
        .skip(file_sync + 1)
        .find(|(_, event)| *event == &(shard.clone(), "directory_sync".into()))
        .expect("parent completion after header sync")
        .0;
    let frame = position(&segment, "record_write");
    let group_sync = log
        .iter()
        .enumerate()
        .skip(frame + 1)
        .find(|(_, event)| *event == &(segment.clone(), "sync_all".into()))
        .expect("frame/group completion before ack")
        .0;
    assert!(
        header < file_sync
            && file_sync < directory_sync
            && directory_sync < frame
            && frame < group_sync
    );
    drop(log);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn new_ancestor_order(pipeline: bool) -> Result {
    let base =
        std::env::temp_dir().join(format!("segment-ancestors-{}-{pipeline}", std::process::id()));
    fs::create_dir_all(&base)?;
    let intermediate = base.join("new");
    let root = intermediate.join("wal");
    let shard = router_wal_shard_root(&root, 0);
    let events = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&events);
    let _guard = observe(
        base.clone(),
        Arc::new(move |path, op, done| {
            if done {
                output.lock().expect("events").push((path.to_path_buf(), op.to_owned()));
            }
            Ok(())
        }),
    );
    durability_io::create_dir_all(&root)?;
    let wal = store(&root, pipeline)?;
    wal.record_submission(&crate::tests::request_replay_fixture("first-ack"), i64::MAX, None)?;
    let events = events.lock().expect("events");
    let position = |path: &Path, op: &str| {
        events
            .iter()
            .position(|event| event == &(path.to_path_buf(), op.to_owned()))
            .expect("ancestor durability before ack")
    };
    assert!(position(&intermediate, "mkdir") < position(&base, "directory_sync"));
    assert!(position(&base, "directory_sync") < position(&root, "mkdir"));
    assert!(position(&root, "mkdir") < position(&intermediate, "directory_sync"));
    let shard_mkdir = position(&shard, "mkdir");
    let parent_sync = events
        .iter()
        .enumerate()
        .skip(shard_mkdir + 1)
        .find(|(_, event)| *event == &(root.clone(), "directory_sync".into()))
        .expect("new shard parent sync")
        .0;
    assert!(shard_mkdir < parent_sync);
    assert!(parent_sync < position(&router_wal_segment_path(&shard, 0), "record_write"));
    drop(events);
    drop(wal);
    fs::remove_dir_all(base)?;
    Ok(())
}
