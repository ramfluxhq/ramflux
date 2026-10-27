// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[cfg(unix)]
#[test]
fn sigterm_exits_zero_with_bounded_graceful_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead as _, Read as _};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut child = Command::new(env!("CARGO_BIN_EXE_ramflux-notify"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = std::io::BufReader::new(child.stdout.take().ok_or("missing stdout")?);
    let mut ready = String::new();
    stdout.read_line(&mut ready)?;
    assert!(ready.contains("service initialized"), "unexpected startup log: {ready}");

    let started = Instant::now();
    let sent = Command::new("kill").args(["-TERM", &child.id().to_string()]).status()?;
    assert!(sent.success(), "kill failed: {sent}");
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "service exceeded shutdown bound");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "service exited with {status}");

    let mut logs = ready;
    stdout.read_to_string(&mut logs)?;
    child.stderr.take().ok_or("missing stderr")?.read_to_string(&mut logs)?;
    assert_eq!(logs.matches("graceful shutdown complete").count(), 1, "{logs}");
    Ok(())
}
