// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn wait(child: &mut Child) -> std::io::Result<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "daemon CLI did not exit",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn daemon_stop_exits_the_foreground_server_and_removes_its_socket()
-> Result<(), Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = PathBuf::from(format!("/tmp/rf-stop-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let socket = root.join("rfd.sock");
    let mut daemon = Process(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "start", "--data-root"])
            .arg(root.join("data"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            daemon.0.try_wait()?.is_none(),
            "foreground daemon exited before binding its socket"
        );
        assert!(Instant::now() < deadline, "foreground daemon did not bind");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output_path = root.join("stop.json");
    let mut stop = Process(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args(["daemon", "stop"])
            .stdout(std::fs::File::create(&output_path)?)
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    assert!(wait(&mut stop.0)?.success());
    let response: serde_json::Value = serde_json::from_slice(&std::fs::read(&output_path)?)?;
    assert_eq!(response["stopping"], true);
    assert!(wait(&mut daemon.0)?.success());
    assert!(!socket.exists(), "graceful shutdown must remove its socket");
    std::fs::remove_dir_all(root)?;
    Ok(())
}
