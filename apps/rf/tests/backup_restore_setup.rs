// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh import refuses missing setup before archive verification or job allocation.
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn fresh_import_without_local_passphrase_refuses_before_verifying_archive()
-> Result<(), Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("rf-restore-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let socket = root.join("bus.sock");
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "start", "--data-root"])
            .arg(root.join("data"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(daemon.0.try_wait()?.is_none(), "daemon exited before binding");
        assert!(Instant::now() < deadline, "daemon did not bind");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Neither this nonexistent archive nor an archive password is consulted.
    let output = Command::new(env!("CARGO_BIN_EXE_rf"))
        .arg("--socket")
        .arg(&socket)
        .args(["account", "backup", "import", "--in"])
        .arg(root.join("does-not-exist.rfb"))
        .env_remove("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("restore_setup_required"), "{stderr}");
    assert!(stderr.contains("--new-passphrase-env"), "{stderr}");
    assert!(!stderr.contains("networking_pending"), "{stderr}");
    let mut bus = ramflux_sdk::LocalBusClient::connect(&socket).await?;
    let jobs = bus.request(None, "account", "account.backup.jobs", serde_json::json!({})).await?;
    assert_eq!(jobs["jobs"], serde_json::json!([]));
    drop(bus);
    drop(daemon);
    Ok(())
}
