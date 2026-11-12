// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real process crash/wait, clean restart and committed-floor rollback acceptance.
use super::*;

#[allow(dead_code)] // Shared shutdown support is compiled by every node integration target.
pub fn crash_restart(binary: &str, enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new("ramflux-gateway")?;
    let cookie = fixture.root.join("admission-cookie.key");
    std::fs::write(&cookie, b"Hx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut config = std::fs::OpenOptions::new().append(true).open(&fixture.config)?;
    writeln!(
        config,
        "\n[gateway.pre_auth]\nenabled = {enabled}\nper_source_ip_handshake_rate = 1"
    )?;
    let spawn = || -> Result<ChildGuard, Box<dyn std::error::Error>> {
        Ok(ChildGuard(
            configured_command(binary, "ramflux-gateway", &fixture, "idle")?
                .env("RAMFLUX_GATEWAY_PRE_AUTH_COOKIE_KEY_FILE", &cookie)
                .spawn()?,
        ))
    };
    let mut child = spawn()?;
    let reader = spawn_shutdown_log_reader(child.0.stdout.take().ok_or("stdout")?);
    wait_for_ready(&reader.receiver, "ramflux-gateway", Duration::from_secs(10))?;
    child.0.kill()?;
    child.0.wait()?;
    reader.thread.join().map_err(|_| "reader panic")?;
    // The endpoint comes from the actual killed process; no database bytes are altered.
    let store = ramflux_node_core::GatewayRedbStore::open(&fixture.database)?;
    let state = store.load_state()?.ok_or("crash checkpoint")?;
    let started = Instant::now();
    let minimum = state.admission_startup_delay(SystemTime::now())?;
    assert!(!minimum.is_zero(), "crash fixture missed its reservation");
    drop(store);
    let mut child = spawn()?;
    let reader = spawn_shutdown_log_reader(child.0.stdout.take().ok_or("stdout")?);
    wait_for_ready(&reader.receiver, "ramflux-gateway", Duration::from_secs(35))?;
    assert!(started.elapsed() >= minimum, "crashed gateway served before reservation endpoint");
    assert!(TcpStream::connect(&fixture.probe_addr).is_ok(), "public listener missing after wait");
    let (status, _) =
        signal_and_wait(&mut child.0, "ramflux-gateway", "idle", Duration::from_secs(10), None)?;
    assert!(status.success());
    let logs = reader.thread.join().map_err(|_| "reader panic")?;
    assert_eq!(
        logs.matches("gateway waiting for committed crash reservation").count(),
        1,
        "{logs}"
    );
    let mut child = spawn()?;
    let reader = spawn_shutdown_log_reader(child.0.stdout.take().ok_or("stdout")?);
    wait_for_ready(&reader.receiver, "ramflux-gateway", Duration::from_secs(10))?;
    let (status, _) =
        signal_and_wait(&mut child.0, "ramflux-gateway", "idle", Duration::from_secs(10), None)?;
    assert!(status.success());
    let logs = reader.thread.join().map_err(|_| "reader panic")?;
    assert!(
        !logs.contains("waiting for committed crash reservation"),
        "clean restart waited: {logs}"
    );
    // A future committed observation models a real host rollback after shutdown.
    let store = ramflux_node_core::GatewayRedbStore::open(&fixture.database)?;
    let state = store.load_state()?.ok_or("clean checkpoint")?;
    store.save_admission_checkpoint(
        &state.final_admission_checkpoint(ramflux_node_core::now_unix_seconds() + 60),
    )?;
    drop(store);
    let mut child = spawn()?;
    let status = child.0.wait()?;
    let mut stderr = String::new();
    child.0.stderr.take().ok_or("stderr")?.read_to_string(&mut stderr)?;
    assert_eq!(status.code(), Some(2));
    assert!(stderr.contains("clock_rollback"), "rollback was not typed: {stderr}");
    Ok(())
}
