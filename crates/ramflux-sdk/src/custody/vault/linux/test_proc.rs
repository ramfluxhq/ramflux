// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only bounded subprocess execution shared by the Linux vault tests. Every child runs in
//! its own process group with a fail-loud deadline (kept well below CI's 60 s nextest
//! slow-timeout); the whole group is killed and the leader reaped on every exit path.
use std::{
    process::{Child, Command, Output},
    time::{Duration, Instant},
};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
/// Deadline used for vault subprocess fixtures.
pub(crate) const DEADLINE: Duration = Duration::from_secs(30);
const _: () = assert!(DEADLINE.as_secs() >= 10 && DEADLINE.as_secs() <= 40);

/// Kills the whole process group of a traced run on every exit path and reaps the leader.
pub(crate) struct GroupReaper(Child);
impl Drop for GroupReaper {
    fn drop(&mut self) {
        if let Some(pid) = rustix::process::Pid::from_raw(self.0.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
/// Runs `command` in its own process group with a fail-loud deadline; tracer and tracee are
/// killed and reaped when this returns, however it returns.
pub(crate) fn run_bounded(
    command: &mut Command,
    deadline: Duration,
) -> TestResult<std::process::ExitStatus> {
    run_bounded_pid(command, deadline, &mut 0)
}
/// Like `run_bounded`, and records the child's pid (also its process-group id) in `pid`.
pub(crate) fn run_bounded_pid(
    command: &mut Command,
    deadline: Duration,
    pid: &mut u32,
) -> TestResult<std::process::ExitStatus> {
    use std::os::unix::process::CommandExt;
    let mut child = GroupReaper(command.process_group(0).spawn()?);
    *pid = child.0.id();
    let end = Instant::now() + deadline;
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(format!("traced run timed out after {deadline:?}").into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Runs `command` bounded and returns its captured output (stdout/stderr go to private files so a
/// full pipe can never stall the child).
pub(crate) fn run_output(command: &mut Command, deadline: Duration) -> TestResult<Output> {
    let dir = tempfile::tempdir()?;
    let (out, err) = (dir.path().join("out"), dir.path().join("err"));
    command
        .stdout(std::fs::File::create(&out)?)
        .stderr(std::fs::File::create(&err)?)
        .stdin(std::process::Stdio::null());
    let status = run_bounded(command, deadline)?;
    Ok(Output { status, stdout: std::fs::read(&out)?, stderr: std::fs::read(&err)? })
}
