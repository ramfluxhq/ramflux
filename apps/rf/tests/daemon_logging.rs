// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Background process redirection must retain real daemon lifecycle diagnostics.
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn background_daemon_rust_log_writes_ready_info_to_its_stderr_file()
-> Result<(), Box<dyn std::error::Error>> {
    for enabled in [true, false] {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = PathBuf::from(format!("/tmp/rf-log-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        let socket = root.join("bus.sock");
        let logs = root.join("daemon.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rf"));
        command
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "start", "--data-root"])
            .arg(root.join("data"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&logs)?)
            .env_remove("RUST_LOG");
        if enabled {
            command.env("RUST_LOG", "ramflux_sdk=info");
        }
        // spawn() leaves the daemon in the background without a terminal, as shell '&' does.
        let mut daemon = Process(command.spawn()?);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(daemon.0.try_wait()?.is_none(), "daemon exited before readiness");
            if socket.exists() {
                let status = Command::new(env!("CARGO_BIN_EXE_rf"))
                    .arg("--socket")
                    .arg(&socket)
                    .args(["daemon", "status"])
                    .output()?;
                if status.status.success() {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "daemon did not become ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        let text = std::fs::read_to_string(&logs)?;
        assert_eq!(text.contains("local bus daemon ready"), enabled, "{text}");
        if enabled {
            assert!(text.contains("INFO"), "{text}");
        }
        let stopped = Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "stop"])
            .output()?;
        assert!(stopped.status.success());
        loop {
            if let Some(status) = daemon.0.try_wait()? {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "daemon did not stop");
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
