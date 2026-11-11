// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded process-group helpers for CLI e2e subprocesses.
use std::{
    fs::File,
    io::{Read, Write as _},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Kills the child's whole process group, remembered descendants, and reaps the leader
/// on every exit path, including after the leader has already exited.
pub(crate) struct ProcessGroup {
    child: Option<Child>,
    pid: u32,
    tracked: Vec<u32>,
}

impl ProcessGroup {
    pub(crate) fn spawn(command: &mut Command) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
        let child = command.spawn()?;
        let pid = child.id();
        Ok(Self { child: Some(child), pid, tracked: Vec::new() })
    }

    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    pub(crate) fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }

    pub(crate) fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        match self.child.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(None),
        }
    }

    pub(crate) fn track_descendants(&mut self) {
        for pid in descendant_pids(self.pid) {
            if pid != self.pid && !self.tracked.contains(&pid) {
                self.tracked.push(pid);
            }
        }
    }

    pub(crate) fn tracked_pids(&self) -> &[u32] {
        &self.tracked
    }

    pub(crate) fn kill_group(&mut self) {
        self.track_descendants();
        signal_tree(self.pid);
        for i in 0..self.tracked.len() {
            signal_tree(self.tracked[i]);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }

    pub(crate) fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self.child.as_mut() {
            Some(child) => child.wait(),
            None => Err(std::io::Error::other("process group already reaped")),
        }
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill_group();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
    }
}

fn signal_tree(pid: u32) {
    let Some(raw) = rustix::process::Pid::from_raw(pid.cast_signed()) else {
        return;
    };
    let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::KILL);
    let _ = rustix::process::kill_process(raw, rustix::process::Signal::KILL);
}

/// Direct children plus nested descendants of `leader`.
pub(crate) fn descendant_pids(leader: u32) -> Vec<u32> {
    let mut seen = std::collections::BTreeSet::new();
    let mut stack = direct_children(leader);
    let mut out = Vec::new();
    while let Some(pid) = stack.pop() {
        if pid == leader || !seen.insert(pid) {
            continue;
        }
        out.push(pid);
        stack.extend(direct_children(pid));
    }
    out
}

fn direct_children(pid: u32) -> Vec<u32> {
    proc_children(pid).unwrap_or_else(|| pgrep_children(pid))
}

fn proc_children(pid: u32) -> Option<Vec<u32>> {
    let mut kids = Vec::new();
    let entries = std::fs::read_dir(format!("/proc/{pid}/task")).ok()?;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("children")) else {
            continue;
        };
        for word in text.split_whitespace() {
            if let Ok(child) = word.parse::<u32>()
                && child != pid
                && !kids.contains(&child)
            {
                kids.push(child);
            }
        }
    }
    Some(kids)
}

fn pgrep_children(pid: u32) -> Vec<u32> {
    let Ok(output) = Command::new("pgrep").arg("-P").arg(pid.to_string()).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .filter(|&child| child != pid)
        .collect()
}

/// Runs `command` in its own process group under `deadline`. Stdout and stderr go to private
/// files so a full pipe cannot stall the child. The group is killed and reaped on every path.
pub(crate) fn run_group_output(
    command: &mut Command,
    deadline: Duration,
) -> Result<Output, Box<dyn std::error::Error>> {
    let stem = std::env::temp_dir().join(format!(
        "rf-cli-e2e-proc-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let out_path = PathBuf::from(format!("{}.out", stem.display()));
    let err_path = PathBuf::from(format!("{}.err", stem.display()));
    let result = (|| -> Result<Output, Box<dyn std::error::Error>> {
        command
            .stdin(Stdio::null())
            .stdout(File::create(&out_path)?)
            .stderr(File::create(&err_path)?);
        let mut group = ProcessGroup::spawn(command)?;
        let end = Instant::now() + deadline;
        loop {
            if let Some(status) = group.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: std::fs::read(&out_path).unwrap_or_default(),
                    stderr: std::fs::read(&err_path).unwrap_or_default(),
                });
            }
            if Instant::now() >= end {
                group.kill_group();
                let _ = group.wait();
                return Err(format!("subprocess timed out after {deadline:?}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    result
}

/// True when `kill(pid, 0)` still finds the process group.
pub(crate) fn process_group_alive(pid: u32) -> bool {
    let Some(group) = rustix::process::Pid::from_raw(pid.cast_signed()) else {
        return false;
    };
    !matches!(rustix::process::test_kill_process_group(group), Err(rustix::io::Errno::SRCH))
}

/// True when `kill(pid, 0)` still finds that process.
pub(crate) fn process_alive(pid: u32) -> bool {
    let Some(raw) = rustix::process::Pid::from_raw(pid.cast_signed()) else {
        return false;
    };
    !matches!(rustix::process::test_kill_process(raw), Err(rustix::io::Errno::SRCH))
}

/// Poll until the group is gone or `deadline` elapses.
pub(crate) fn wait_process_group_gone(
    pid: u32,
    deadline: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let end = Instant::now() + deadline;
    loop {
        if !process_group_alive(pid) {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(format!("process group {pid} still alive after {deadline:?}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Poll until `pid` is gone or `deadline` elapses.
pub(crate) fn wait_process_gone(
    pid: u32,
    deadline: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let end = Instant::now() + deadline;
    loop {
        if !process_alive(pid) {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(format!("process {pid} still alive after {deadline:?}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Writes `stdin_bytes` then runs the command bounded, capturing output through files.
pub(crate) fn run_group_output_with_stdin(
    command: &mut Command,
    stdin_bytes: &[u8],
    deadline: Duration,
) -> Result<Output, Box<dyn std::error::Error>> {
    let stem = std::env::temp_dir().join(format!(
        "rf-cli-e2e-proc-in-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let out_path = PathBuf::from(format!("{}.out", stem.display()));
    let err_path = PathBuf::from(format!("{}.err", stem.display()));
    let result = (|| -> Result<Output, Box<dyn std::error::Error>> {
        command
            .stdin(Stdio::piped())
            .stdout(File::create(&out_path)?)
            .stderr(File::create(&err_path)?);
        let mut group = ProcessGroup::spawn(command)?;
        if let Some(child) = group.child_mut()
            && let Some(mut stdin) = child.stdin.take()
        {
            stdin.write_all(stdin_bytes)?;
        }
        let end = Instant::now() + deadline;
        loop {
            if let Some(status) = group.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: std::fs::read(&out_path).unwrap_or_default(),
                    stderr: std::fs::read(&err_path).unwrap_or_default(),
                });
            }
            if Instant::now() >= end {
                group.kill_group();
                let _ = group.wait();
                return Err(format!("subprocess timed out after {deadline:?}").into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    result
}

/// Drain one pipe onto a shared buffer until EOF.
pub(crate) fn drain_pipe(
    mut pipe: impl Read + Send + 'static,
    sink: std::sync::Arc<std::sync::Mutex<String>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0_u8; 1024];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(chunk) = std::str::from_utf8(&buf[..n]) {
                        sink.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push_str(chunk);
                    }
                }
            }
        }
    })
}
