// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A stable advisory-lock inode with diagnostic process ownership and dead-owner recovery.

use super::{invalid, private_fs::PrivateDir};
use crate::RfError;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    pid: Option<u32>,
    started_at_unix_seconds: u64,
}

pub(super) struct OperationLock {
    file: File,
    started_at: u64,
}

fn running() -> RfError {
    invalid("DEMO_CUSTODY_OPERATION_RUNNING: another custody operation is running")
}

impl OperationLock {
    pub(super) fn acquire(directory: &PrivateDir, now: u64) -> Result<Self, RfError> {
        let (mut file, created) = directory.lock_file()?;
        match file.try_lock() {
            Ok(()) => (),
            Err(std::fs::TryLockError::WouldBlock) => return Err(running()),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let mut stale = None;
        if !created {
            let mut bytes = Vec::new();
            Read::by_ref(&mut file).take(1025).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 {
                return Err(invalid("DEMO_CUSTODY_LOCK_INVALID: oversized lock metadata"));
            }
            let owner: Owner = serde_json::from_slice(&bytes).map_err(|_| invalid(
                "DEMO_CUSTODY_LOCK_INVALID: incomplete or legacy lock; verify no custody operation is running before removing .lock"
            ))?;
            if let Some(pid) = owner.pid {
                let raw = i32::try_from(pid)
                    .map_err(|_| invalid("DEMO_CUSTODY_LOCK_INVALID: invalid pid"))?;
                let pid = rustix::process::Pid::from_raw(raw)
                    .ok_or_else(|| invalid("DEMO_CUSTODY_LOCK_INVALID: invalid pid"))?;
                match rustix::process::test_kill_process(pid) {
                    Err(rustix::io::Errno::SRCH) => stale = Some(owner),
                    Ok(()) | Err(rustix::io::Errno::PERM) => return Err(running()),
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
            }
        }
        let mut operation = Self { file, started_at: now };
        operation.store(Some(std::process::id()))?;
        if let Some(owner) = stale {
            eprintln!(
                "DEMO_CUSTODY_STALE_LOCK_RECLAIMED: dead pid {} started at Unix UTC seconds {}",
                owner.pid.unwrap_or_default(),
                owner.started_at_unix_seconds
            );
        }
        Ok(operation)
    }

    fn store(&mut self, pid: Option<u32>) -> Result<(), RfError> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&serde_json::to_vec(&Owner {
            pid,
            started_at_unix_seconds: self.started_at,
        })?)?;
        self.file.sync_all()?;
        Ok(())
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        // Keep the same inode so a concurrent opener can never lock a replacement file.
        let _ = self.store(None);
    }
}
