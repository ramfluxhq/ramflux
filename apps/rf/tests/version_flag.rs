// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `rf --version` reports the shared product version and the build commit.

use std::io::Read as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(30);

/// Owns the child: it is killed and reaped on every exit path, including a panic.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn version_flag_prints_product_version_and_commit() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Reaped(
        Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() > DEADLINE {
            return Err("rf --version did not exit within the deadline".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut text = String::new();
    child.0.stdout.take().ok_or("stdout was not piped")?.read_to_string(&mut text)?;
    assert!(status.success(), "rf --version must exit 0, got {status}");
    let expected = format!("ramflux {} (", env!("CARGO_PKG_VERSION"));
    assert!(
        text.starts_with(&expected),
        "output must start with '{expected}' (product version from [workspace.package]), got: {text}"
    );
    assert!(
        text.trim_end().ends_with(')'),
        "output must end with the closing paren of the commit, got: {text}"
    );
    Ok(())
}
