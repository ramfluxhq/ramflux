// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Re-exec recovery matrix: each physical completion is independently held and failed.
#![allow(clippy::expect_used, clippy::panic, reason = "crash fixture assertions and watchdog")]
use super::*;
use crate::{RouterRedbStore, durability_test_hooks::observe};
use std::sync::atomic::AtomicBool;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const NAME: &str = "router_wal::durability_tests::recovery_sync_before_ready";

fn entry() -> InboxEntry {
    let mut entry = super::tests::router_wal_inbox_entry("startup-row", "startup-target");
    entry.envelope.created_at = i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX);
    entry.envelope.ttl = 3600;
    entry
}
fn open(root: &Path, mode: &str) -> std::result::Result<RouterRedbStore, NodeCoreError> {
    if mode == "redb" {
        RouterRedbStore::open_without_wal(root.join("db"))
    } else {
        RouterRedbStore::open_with_wal(root.join("db"), root.join("wal"))
    }
}
fn setup(root: &Path, mode: &str, populated: bool, due: bool) -> Result {
    fs::create_dir_all(root)?;
    let store = open(root, "redb")?;
    if populated {
        store.record_submission_increment("startup-row", i64::MAX, Some(&entry()))?;
        // Persisted redb rows do not mark a cursor checkpoint due merely by loading.
        let (mut inbox, _) = store.load_delivery_state(0)?;
        assert_eq!(inbox.take_checkpoint_due().len(), 0);
    }
    drop(store);
    if mode != "redb" {
        let wal = root.join("wal");
        fs::create_dir_all(&wal)?;
        for directory in
            [wal.clone(), router_wal_shard_root(&wal, 0), router_wal_shard_root(&wal, 1)]
        {
            fs::create_dir_all(&directory)?;
            fs::write(
                router_wal_segment_path(&directory, 0),
                [ROUTER_WAL_MAGIC, &[1, 2]].concat(),
            )?;
        }
        fs::write(router_wal_segment_path(&wal, 1), ROUTER_WAL_MAGIC)?;
        if due {
            let mut expired = entry();
            expired.inbox_seq = 7;
            expired.target_delivery_id = "expired-wal-target".into();
            expired.envelope.target_delivery_id = expired.target_delivery_id.clone();
            expired.envelope.created_at = 0;
            expired.envelope.ttl = 1;
            write_legacy_router_wal_segment(
                &router_wal_shard_root(&wal, 1),
                "expired",
                1,
                &expired,
            )?;
        }
    }
    Ok(())
}
fn required(root: &Path, mode: &str, due: bool) -> Vec<(PathBuf, &'static str)> {
    let mut operations = Vec::new();
    if mode != "redb" {
        let wal = root.join("wal");
        for directory in
            [wal.clone(), router_wal_shard_root(&wal, 0), router_wal_shard_root(&wal, 1)]
        {
            operations.push((router_wal_segment_path(&directory, 0), "sync_all"));
            operations.push((directory, "directory_sync"));
        }
        operations.push((router_wal_segment_path(&wal, 1), "sync_all"));
    }
    if due {
        operations.push((root.join("db"), "checkpoint_begin"));
        operations.push((root.join("db"), "checkpoint_commit"));
    }
    operations.push((root.join("db"), "begin_write"));
    operations.push((root.join("db"), "immediate_commit"));
    operations
}
fn command(root: &Path, mode: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().expect("test exe"));
    command
        .args(["--exact", NAME, "--nocapture"])
        .env("RAMFLUX_STARTUP_MATRIX_CHILD", root)
        .env("RAMFLUX_MATRIX_MODE", mode)
        .env("RAMFLUX_ROUTER_WAL_SHARDS", "2")
        .env("RAMFLUX_ROUTER_WAL_PIPELINE", if mode == "pipeline" { "1" } else { "0" })
        .env("RAMFLUX_ROUTER_GROUP_COMMIT", "0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    command
}
fn wait_file(path: &Path, child: &mut std::process::Child) -> Result {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(child.try_wait()?.is_none(), "child exited before {}", path.display());
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("startup hook watchdog");
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}
fn finish(mut child: std::process::Child, success: bool) -> Result {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            assert_eq!(status.success(), success, "startup child status {status}");
            if !success {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    assert_eq!(status.signal(), Some(6));
                }
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            panic!("startup exit watchdog");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
pub(super) fn matrix() -> Result {
    for mode in ["redb", "ordinary", "pipeline"] {
        for (populated, due) in [(false, false), (true, false), (true, true)] {
            if mode == "redb" && due {
                continue;
            }
            let root = std::env::temp_dir()
                .join(format!("startup-matrix-{}-{mode}-{populated}-{due}", std::process::id()));
            setup(&root, mode, populated, due)?;
            for (index, (path, operation)) in required(&root, mode, due).into_iter().enumerate() {
                for action in ["hold", "fail"] {
                    // Each cut starts from the same pre-checkpoint image. A successful
                    // earlier restart must not consume the due checkpoint for later cuts.
                    fs::remove_file(root.join("db"))?;
                    setup(&root, mode, populated, due)?;
                    let control = root.join(format!("control-{index}-{action}"));
                    fs::create_dir(&control)?;
                    let mut child = command(&root, mode)
                        .env("RAMFLUX_MATRIX_PATH", path.strip_prefix(&root)?)
                        .env("RAMFLUX_MATRIX_DUE", if due { "1" } else { "0" })
                        .env("RAMFLUX_MATRIX_OP", operation)
                        .env("RAMFLUX_MATRIX_ACTION", action)
                        .env("RAMFLUX_MATRIX_CONTROL", &control)
                        .spawn()?;
                    wait_file(&control.join("entered"), &mut child)?;
                    for surface in ["ready", "resume", "http-inbox", "submit-reply", "push"] {
                        assert!(
                            !control.join(surface).exists(),
                            "{surface} escaped {mode} {index} {action}"
                        );
                    }
                    if action == "hold" {
                        fs::write(control.join("release"), [])?;
                    }
                    finish(child, action == "hold")?;
                    for surface in ["ready", "resume", "http-inbox", "submit-reply", "push"] {
                        assert_eq!(control.join(surface).exists(), action == "hold");
                    }
                }
            }
            fs::remove_dir_all(root)?;
        }
    }
    redb_crashes()
}
pub(super) fn child() -> Result {
    let root = PathBuf::from(std::env::var_os("RAMFLUX_STARTUP_MATRIX_CHILD").expect("root"));
    let mode = std::env::var("RAMFLUX_MATRIX_MODE")?;
    if let Ok(crash) = std::env::var("RAMFLUX_MATRIX_CRASH") {
        return redb_crash_child(&root, &crash);
    }
    let control = PathBuf::from(std::env::var_os("RAMFLUX_MATRIX_CONTROL").expect("control"));
    let target = root.join(std::env::var_os("RAMFLUX_MATRIX_PATH").expect("path"));
    let operation = std::env::var("RAMFLUX_MATRIX_OP")?;
    let action = std::env::var("RAMFLUX_MATRIX_ACTION")?;
    let completed = Arc::new(Mutex::new(BTreeSet::new()));
    let observed = Arc::clone(&completed);
    let hook_control = control.clone();
    let once = AtomicBool::new(false);
    let _guard = observe(
        root.clone(),
        Arc::new(move |path, op, done| {
            if path == target
                && op == operation
                && !done
                && !once.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                fs::write(hook_control.join("entered"), [])?;
                if action == "fail" {
                    return Err(io::Error::other("injected startup durability failure"));
                }
                let deadline = Instant::now() + Duration::from_secs(10);
                while !hook_control.join("release").exists() {
                    if Instant::now() >= deadline {
                        return Err(io::Error::other("release watchdog"));
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            }
            if done {
                observed.lock().expect("completed").insert((path.to_path_buf(), op.to_owned()));
            }
            Ok(())
        }),
    );
    let result = open(&root, &mode).and_then(|store| {
        let router = store.load_router()?.unwrap_or_default();
        Ok((store, router))
    });
    let Ok((store, router)) = result else {
        std::process::abort();
    };
    for (path, op) in
        required(&root, &mode, std::env::var("RAMFLUX_MATRIX_DUE").as_deref() == Ok("1"))
    {
        assert!(
            completed.lock().expect("completed").contains(&(path, op.into())),
            "required completion before readiness"
        );
    }
    fs::write(control.join("ready"), [])?;
    legacy_surfaces(&router, &store, &control)?;
    Ok(())
}
fn legacy_surfaces(router: &crate::RouterCore, store: &RouterRedbStore, control: &Path) -> Result {
    let rows = router.resume("startup-target", 0, 100);
    fs::write(control.join("resume"), serde_json::to_vec(&rows)?)?;
    let response =
        router.mvp1_inbox_at("startup-target", 0, 100, i64::try_from(crate::now_unix_seconds())?);
    fs::write(control.join("http-inbox"), serde_json::to_vec(&response)?)?;
    // The existing submit reply cannot be produced until the store's durable call returns.
    let row = entry();
    store.record_submission_increment("post-startup-submit", i64::MAX, Some(&row))?;
    fs::write(control.join("submit-reply"), serde_json::to_vec(&row)?)?;
    let mut gateway = crate::GatewayState::new();
    gateway.open_session(crate::GatewaySession {
        session_id: "startup-session".into(),
        target_delivery_id: "startup-target".into(),
        device_id: "startup-device".into(),
        opened_at: 0,
        last_heartbeat_at: 0,
        lifecycle: crate::GatewaySessionLifecycle::Live,
    });
    gateway.deliver(crate::GatewayFrame::Deliver {
        session_id: "startup-session".into(),
        envelope_id: row.envelope.envelope_id,
        payload_hash: row.envelope.payload_hash,
    })?;
    fs::write(control.join("push"), serde_json::to_vec(&gateway)?)?;
    Ok(())
}
fn redb_crashes() -> Result {
    for kind in ["uncertain", "reply-loss"] {
        let root =
            std::env::temp_dir().join(format!("startup-redb-crash-{}-{kind}", std::process::id()));
        setup(&root, "redb", false, false)?;
        finish(command(&root, "redb").env("RAMFLUX_MATRIX_CRASH", kind).spawn()?, false)?;
        let store = open(&root, "redb")?;
        let router = store.load_router()?.expect("recovered committed row");
        let rows = router.resume("startup-target", 0, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inbox_seq, 1);
        assert_eq!(rows[0].envelope.envelope_id, "startup-row");
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
fn redb_crash_child(root: &Path, kind: &str) -> Result {
    let store = open(root, "redb")?;
    let uncertain = kind == "uncertain";
    let _guard = observe(
        root.to_path_buf(),
        Arc::new(move |_, op, done| {
            if op == "commit" && done {
                if uncertain {
                    return Err(io::Error::other("commit result lost after physical completion"));
                }
                std::process::abort();
            }
            Ok(())
        }),
    );
    assert!(store.record_submission_increment("startup-row", i64::MAX, Some(&entry())).is_err());
    std::process::abort();
}
