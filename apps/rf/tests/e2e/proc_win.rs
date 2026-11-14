// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded process helpers for the Windows CLI e2e. There is no POSIX process group:
//! `taskkill /T` ends the process tree, and waits use `WaitForSingleObject` with the caller's
//! deadline instead of a sleep loop.

#![allow(unsafe_code)]

use std::{
    fs::File,
    io::Read,
    os::windows::{
        io::{AsRawHandle, FromRawHandle},
        process::ExitStatusExt,
    },
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const STILL_ACTIVE: u32 = 259;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const SYNCHRONIZE: u32 = 0x0010_0000;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> *mut core::ffi::c_void;
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    fn GetExitCodeProcess(process: *mut core::ffi::c_void, code: *mut u32) -> i32;
    fn WaitForSingleObject(handle: *mut core::ffi::c_void, milliseconds: u32) -> u32;
    fn TerminateProcess(process: *mut core::ffi::c_void, code: u32) -> i32;
}

/// Kills the process tree and reaps the leader on every exit path.
pub(crate) struct ProcessGroup {
    child: Option<Child>,
    process: Option<File>,
    pid: u32,
}

impl ProcessGroup {
    pub(crate) fn spawn(command: &mut Command) -> std::io::Result<Self> {
        let child = command.spawn()?;
        let pid = child.id();
        Ok(Self { child: Some(child), process: None, pid })
    }

    /// A process created outside `std::process::Command`. `process` owns the handle.
    pub(crate) fn from_process(pid: u32, process: File) -> Self {
        Self { child: None, process: Some(process), pid }
    }

    pub(crate) fn id(&self) -> u32 {
        self.pid
    }

    pub(crate) fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }

    fn raw(&self) -> Option<*mut core::ffi::c_void> {
        if let Some(child) = &self.child {
            return Some(child.as_raw_handle());
        }
        self.process.as_ref().map(AsRawHandle::as_raw_handle)
    }

    pub(crate) fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(child) = self.child.as_mut() {
            return child.try_wait();
        }
        let Some(process) = self.process.as_ref() else {
            return Err(std::io::Error::other("process group has no handle"));
        };
        let mut code = 0_u32;
        // SAFETY: `process` is an open process handle and `code` is a writable `u32`.
        let ok = unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut code) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if code == STILL_ACTIVE { Ok(None) } else { Ok(Some(ExitStatus::from_raw(code))) }
    }

    pub(crate) fn track_descendants(&self) {}

    pub(crate) fn tracked_pids(&self) -> Vec<u32> {
        Vec::new()
    }

    pub(crate) fn kill_group(&mut self) {
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/PID", &self.pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        } else if let Some(process) = self.process.as_ref() {
            // SAFETY: `process` is an open process handle. The exit code is only a marker.
            let _ = unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        }
    }

    pub(crate) fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(child) = self.child.as_mut() {
            return child.wait();
        }
        let Some(raw) = self.raw() else {
            return Err(std::io::Error::other("process group has no handle"));
        };
        // SAFETY: `raw` is the open process handle. Ten seconds is the bound after a kill.
        let waited = unsafe { WaitForSingleObject(raw, 10_000) };
        if waited != WAIT_OBJECT_0 {
            return Err(std::io::Error::other("process was not reaped within 10s"));
        }
        self.try_wait()?.ok_or_else(|| std::io::Error::other("process is still active"))
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.kill_group();
        let _ = self.wait();
    }
}

/// Runs `command` under `deadline`. Stdout and stderr go to private files so a full pipe
/// cannot stall the child. The tree is killed on every path.
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
        let raw = group.raw().ok_or("spawned process has no handle")?;
        let millis = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: `raw` is the child's process handle and outlives this call.
        let waited = unsafe { WaitForSingleObject(raw, millis) };
        if waited == WAIT_TIMEOUT {
            group.kill_group();
            let _ = group.wait();
            return Err(format!("subprocess timed out after {deadline:?}").into());
        }
        if waited != WAIT_OBJECT_0 {
            group.kill_group();
            return Err("subprocess wait failed".into());
        }
        let status = group.wait()?;
        Ok(Output {
            status,
            stdout: std::fs::read(&out_path).unwrap_or_default(),
            stderr: std::fs::read(&err_path).unwrap_or_default(),
        })
    })();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    result
}

fn open_process(pid: u32, access: u32) -> *mut core::ffi::c_void {
    // SAFETY: the returned handle, when non-null, is owned by the caller and closed below.
    unsafe { OpenProcess(access, 0, pid) }
}

/// True when the process exists and has not exited.
pub(crate) fn process_alive(pid: u32) -> bool {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION);
    if handle.is_null() {
        return false;
    }
    let mut code = 0_u32;
    // SAFETY: `handle` came from `OpenProcess` and `code` is a writable `u32`.
    let ok = unsafe { GetExitCodeProcess(handle, &raw mut code) };
    // SAFETY: `handle` is the process handle just opened.
    unsafe { CloseHandle(handle) };
    ok != 0 && code == STILL_ACTIVE
}

/// Same question as [`process_alive`]: Windows has no separate process-group object here.
pub(crate) fn process_group_alive(pid: u32) -> bool {
    process_alive(pid)
}

/// Block until `pid` has exited or `deadline` elapses.
pub(crate) fn wait_process_gone(
    pid: u32,
    deadline: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let handle = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
    if handle.is_null() {
        return Ok(());
    }
    let millis = u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: `handle` came from `OpenProcess` with `SYNCHRONIZE`.
    let waited = unsafe { WaitForSingleObject(handle, millis) };
    // SAFETY: `handle` is the process handle just opened.
    unsafe { CloseHandle(handle) };
    if waited == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(format!("process {pid} still alive after {deadline:?}").into())
    }
}

pub(crate) fn wait_process_group_gone(
    pid: u32,
    deadline: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_process_gone(pid, deadline)
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

/// Wrap an owned process handle. The caller must not close `handle`.
pub(crate) fn owned_process(handle: *mut core::ffi::c_void) -> File {
    // SAFETY: `handle` is an owned process handle that has not been closed.
    unsafe { File::from_raw_handle(handle) }
}
