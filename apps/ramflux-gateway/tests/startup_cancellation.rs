// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use configured_shutdown::{Fixture, configured_command};
use std::{
    io::Read,
    net::TcpStream,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[path = "../../../tests/configured_shutdown.rs"]
mod configured_shutdown;

#[cfg(unix)]
#[tokio::test]
async fn sigterm_during_startup_reservation_exits_without_serving()
-> Result<(), Box<dyn std::error::Error>> {
    cancel_startup_reservation(env!("CARGO_BIN_EXE_ramflux-gateway")).await
}

#[cfg(unix)]
async fn cancel_startup_reservation(binary: &str) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new("ramflux-gateway")?;
    let directory = tempfile::TempDir::new()?;
    let log_path = directory.path().join("gateway.log");
    let store = ramflux_node_core::GatewayRedbStore::open(&fixture.database)?;
    let mut state = ramflux_node_core::GatewayState::new();
    let floor = ramflux_node_core::now_unix_seconds();
    state.observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(floor))?;
    store.save_admission_checkpoint(&state.admission_checkpoint(floor))?;
    drop(store);
    let mut command = tokio::process::Command::from(configured_command(
        binary,
        "ramflux-gateway",
        &fixture,
        "idle",
    )?);
    command.stdout(std::fs::File::create(&log_path)?).stderr(Stdio::null()).kill_on_drop(true);
    let mut child = command.spawn()?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut logs = String::new();
            std::fs::File::open(&log_path)?.take(65537).read_to_string(&mut logs)?;
            if logs.len() > 65536 {
                return Err("startup log exceeded bound".into());
            }
            if logs.contains("gateway waiting for committed crash reservation") {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if child.try_wait()?.is_some() {
                return Err("gateway exited before reservation wait".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(
        TcpStream::connect(&fixture.probe_addr).is_err(),
        "startup reservation must withhold the public listener"
    );
    let pid = child.id().ok_or("gateway process disappeared")?;
    let status = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    assert!(status.success(), "SIGTERM delivery must succeed");
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait()).await??;
    assert!(
        status.success(),
        "cancellation must drain and exit successfully before reservation expiration"
    );
    let store = ramflux_node_core::GatewayRedbStore::open(&fixture.database)?;
    let reopened = store.load_state()?.ok_or("reservation missing after cancellation")?;
    assert!(
        !reopened.admission_startup_delay(SystemTime::now())?.is_zero(),
        "SIGTERM must preserve the crash reservation"
    );
    assert!(
        TcpStream::connect(&fixture.probe_addr).is_err(),
        "cancelled startup must never start listening"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn clean_restart_is_immediate_and_true_rollback_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new("ramflux-gateway")?;
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("startup.log");
    for _ in 0..2 {
        let mut command = tokio::process::Command::from(configured_command(
            env!("CARGO_BIN_EXE_ramflux-gateway"),
            "ramflux-gateway",
            &fixture,
            "idle",
        )?);
        command
            .arg("--once")
            .stdout(std::fs::File::create(&path)?)
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let status = tokio::time::timeout(Duration::from_secs(10), command.status()).await??;
        assert!(status.success(), "fresh and clean restart must complete inside ten seconds");
        let mut logs = String::new();
        std::fs::File::open(&path)?.take(65537).read_to_string(&mut logs)?;
        assert!(logs.len() <= 65536, "startup log exceeded bound");
        assert!(
            !logs.contains("waiting for committed crash reservation"),
            "clean restart must skip reservation wait"
        );
    }
    let store = ramflux_node_core::GatewayRedbStore::open(&fixture.database)?;
    let state = store.load_state()?.ok_or("clean checkpoint missing")?;
    store.save_admission_checkpoint(
        &state.final_admission_checkpoint(ramflux_node_core::now_unix_seconds() + 60),
    )?;
    drop(store);
    let mut command = tokio::process::Command::from(configured_command(
        env!("CARGO_BIN_EXE_ramflux-gateway"),
        "ramflux-gateway",
        &fixture,
        "idle",
    )?);
    command.stdout(Stdio::null()).stderr(std::fs::File::create(&path)?).kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(10), command.status()).await??;
    assert_eq!(status.code(), Some(2), "true rollback must fail closed");
    let mut error = String::new();
    std::fs::File::open(&path)?.take(65537).read_to_string(&mut error)?;
    assert!(error.len() <= 65536, "rollback diagnostics exceeded bound");
    assert!(error.contains("clock_rollback"), "rollback must retain its typed diagnostic");
    Ok(())
}
