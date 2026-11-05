// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The production command parser/runner, including re-exec crash recovery.
use super::*;
use ramflux_node_core::{RouterRedbStore, durability_test_hooks::observe};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn args(path: &std::path::Path) -> Vec<String> {
    vec!["--config".into(), path.display().to_string(), "--rotate-inbox-incarnations".into()]
}
fn command(args: &[String]) -> anyhow::Result<Command> {
    parse(args)?.ok_or_else(|| anyhow::anyhow!("missing command"))
}
const NAME: &str = "inbox_maintenance::tests::restore_rotation_command_resume";
#[test]
fn restore_rotation_command_resume() -> anyhow::Result<()> {
    if let Ok(root) = std::env::var("RAMFLUX_P3_COMMAND_CHILD") {
        return child_mode(std::path::Path::new(&root));
    }
    mode_case("redb")
}
#[test]
fn restore_rotation_command_resume_ordinary() -> anyhow::Result<()> {
    mode_case("ordinary")
}
#[test]
fn restore_rotation_command_resume_pipeline() -> anyhow::Result<()> {
    mode_case("pipeline")
}
fn mode_case(mode: &str) -> anyhow::Result<()> {
    let root = std::fs::canonicalize(std::env::temp_dir())?
        .join(format!("p3-command-{}-{mode}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(
        root.join("config.toml"),
        format!(
            r#"node_id = "rotation-node"
service_id = "ramflux-router"
redb_path = {:?}
[mesh]
listen_addr = "127.0.0.1:0"
ca_cert = "unused.pem"
service_cert = "unused.pem"
service_key = "unused.key"
allowed_service_ids = ["ramflux-router"]
[mesh.endpoints]
router = "127.0.0.1:0"
"#,
            root.join("db")
        ),
    )?;
    // Setup is performed once; each durable cut/restart gets its own watchdog.
    let mut child = child_command(&root, mode)?.env("RAMFLUX_P3_COMMAND_PHASE", "setup").spawn()?;
    wait(&mut child, true)?;
    let mut cuts = vec![
        "none",
        "operator_rotation_pending",
        if mode == "redb" { "operator_rotation" } else { "rotation_pending" },
    ];
    if mode != "redb" {
        cuts.push("quarantine");
    }
    for cut in cuts {
        let mut child = child_command(&root, mode)?.env("RAMFLUX_P3_COMMAND_PHASE", cut).spawn()?;
        wait(&mut child, true)?;
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn child_command(root: &std::path::Path, mode: &str) -> anyhow::Result<std::process::Command> {
    let mut child = std::process::Command::new(std::env::current_exe()?);
    child
        .args(["--exact", NAME, "--nocapture"])
        .env("RAMFLUX_P3_COMMAND_CHILD", root)
        .env("RAMFLUX_ROUTER_WAL", if mode == "redb" { "0" } else { "1" })
        .env("RAMFLUX_ROUTER_WAL_PIPELINE", if mode == "pipeline" { "1" } else { "0" })
        // Keep multi-shard recovery without scaling fixture threads/fsyncs to host CPUs.
        .env("RAMFLUX_ROUTER_WAL_SHARDS", "2")
        .env_remove("RAMFLUX_P3_COMMAND_CUT")
        .env_remove("RAMFLUX_ROUTER_WAL_DIR")
        .env_remove("RAMFLUX_NODE_STATE_DIR")
        .stdout(std::process::Stdio::null());
    Ok(child)
}

fn wait(child: &mut std::process::Child, success: bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait()? {
            anyhow::ensure!(status.success() == success, "child: {status}");
            #[cfg(unix)]
            if !success {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(6), "crash must be a real abort");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("command child watchdog");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn rejects_conflicting_or_incomplete_rotation_flags() -> anyhow::Result<()> {
    for arguments in [
        vec!["--rotate-inbox-incarnations"],
        vec!["--quarantine-wal-segment", "segment"],
        vec!["--config", "config", "--rotate-inbox-incarnations", "--quarantine-wal-segment"],
        vec!["--config", "config", "--rotate-inbox-incarnations", "--checkpoint-identity-registry"],
        vec![
            "--config",
            "config",
            "--rotate-inbox-incarnations",
            "--discard-stale-identity-journal",
        ],
        vec!["--config", "config", "--rotate-inbox-incarnations", "--health-check"],
    ] {
        assert!(parse(&arguments.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
    }
    assert!(parse(&args(std::path::Path::new("config")))?.is_some());
    Ok(())
}

fn child_mode(root: &std::path::Path) -> anyhow::Result<()> {
    let arguments = args(&root.join("config.toml"));
    if let Ok(cut) = std::env::var("RAMFLUX_P3_COMMAND_CUT") {
        let _guard = observe(
            root.to_path_buf(),
            Arc::new(move |_, op, done| {
                if op == cut && done {
                    std::process::abort();
                }
                Ok(())
            }),
        );
        run(&arguments, &command(&arguments)?, &mut Vec::new())?;
        anyhow::bail!("crash cut not reached");
    }
    let db = root.join("db");
    let ids = root.join("incarnations.json");
    let phase = std::env::var("RAMFLUX_P3_COMMAND_PHASE")?;
    if phase == "setup" {
        let store = RouterRedbStore::open(&db)?;
        let mut old = Vec::new();
        for target in ["one", "two", "three"] {
            old.push(store.initialize_inbox(target)?);
        }
        // Offline command must refuse the live store's exclusive lock.
        assert!(run(&arguments, &command(&arguments)?, &mut Vec::new()).is_err());
        drop(store);
        if std::env::var("RAMFLUX_ROUTER_WAL").as_deref() != Ok("0") {
            let shards = std::fs::read_dir(root.join("db.wal"))?
                .collect::<std::io::Result<Vec<_>>>()?
                .iter()
                .filter(|entry| {
                    entry.file_name().to_string_lossy().starts_with("router-wal-shard-")
                })
                .count();
            assert_eq!(shards, 2, "rotation fixture work must not scale with host CPU count");
        }
        std::fs::write(ids, serde_json::to_vec(&old)?)?;
        return Ok(());
    }
    // Carry the preceding cut's IDs forward, retaining the original rotation chain.
    let old: Vec<String> = serde_json::from_slice(&std::fs::read(&ids)?)?;
    let cut = phase.as_str();
    let mut arguments = arguments.clone();
    if cut == "quarantine" {
        let segment = root.join("db.wal/router-wal-shard-0000/router-wal-00000000000000000001.wal");
        std::fs::write(&segment, vec![b'x'; 160])?;
        assert!(crate::startup::load(&db).is_err());
        arguments.extend(["--quarantine-wal-segment".into(), segment.display().to_string()]);
    }
    if cut == "none" || cut == "quarantine" {
        run_counts_only(&arguments, &old)?;
    } else {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", NAME, "--nocapture"])
            .env("RAMFLUX_P3_COMMAND_CUT", cut)
            .stdout(std::process::Stdio::null())
            .spawn()?;
        wait(&mut child, false)?;
    }
    // Production startup must finish a pending pass before returning the store.
    let (router, store) = crate::startup::load(&db)?;
    let mut new = Vec::new();
    for (index, target) in ["one", "two", "three"].iter().enumerate() {
        let (id, issued) = store.inbox_status(target)?;
        let id = id.ok_or_else(|| anyhow::anyhow!("missing E"))?;
        assert_ne!(id, old[index]);
        assert_eq!(issued, 0);
        assert_eq!(router.inbox_snapshot().incarnation_id(target), Some(id.as_str()));
        new.push(id);
    }
    drop(store);
    let (_, store) = crate::startup::load(&db)?;
    for (index, target) in ["one", "two", "three"].iter().enumerate() {
        assert_eq!(store.inbox_status(target)?.0, Some(new[index].clone()));
    }
    drop(store);
    std::fs::write(ids, serde_json::to_vec(&new)?)?;
    Ok(())
}

fn run_counts_only(arguments: &[String], old: &[String]) -> anyhow::Result<()> {
    let mut output = Vec::new();
    run(arguments, &command(arguments)?, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(output.starts_with("Restore procedure: 1. Stop every gateway"));
    assert!(output.contains("4. Start the router. 5. Start the gateways"));
    assert!(output.ends_with("inboxes=3\n"));
    for id in old {
        assert!(!output.contains(id));
    }
    for target in ["one", "two", "three"] {
        assert!(!output.contains(target));
    }
    Ok(())
}
