// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One controller-provisioned, stable file per host; never unlink/replace a live ledger.
//! Every transaction locks the file and verifies its checksum. A crash leaves its
//! claim occupied; only clean final-owner destruction releases it. Offline recovery
//! requires controller proof of death for every claim; PID reuse is never evidence.

use super::{BudgetError, FrozenBudget, Result, add};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

const RECORDS: usize = 64;
const HEADER: usize = 24;
const RECORD_SIZE: usize = 56;
const BODY: usize = HEADER + RECORDS * RECORD_SIZE;
const SIZE: usize = BODY + 32;
const MAGIC: &[u8; 8] = b"RFRAWQ01";

/// Clone this lease into every runtime/handle owner. The final clone releases the claim.
#[derive(Clone, Debug)]
pub struct HostReservation(Arc<Claim>);
#[derive(Debug)]
struct Claim {
    file: File,
    slot: usize,
    digest: [u8; 32],
    start: u64,
    end: u64,
    pid: u64,
}

struct Locked<'a>(&'a File);
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
fn lock(file: &File) -> Result<Locked<'_>> {
    file.lock()?;
    Ok(Locked(file))
}
fn number(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data[offset..offset + 8].try_into().map_err(|_| BudgetError::Invalid("ledger field"))?,
    ))
}
fn store(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn read(file: &mut File) -> Result<[u8; SIZE]> {
    if file.metadata()?.len() != SIZE as u64 {
        return Err(BudgetError::Invalid("ledger size/stale state"));
    }
    let mut bytes = [0; SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    if &bytes[..8] != MAGIC || blake3::hash(&bytes[..BODY]).as_bytes() != &bytes[BODY..] {
        return Err(BudgetError::Invalid("ledger checksum/stale state"));
    }
    Ok(bytes)
}
fn write(file: &mut File, bytes: &mut [u8; SIZE]) -> Result<()> {
    let digest = blake3::hash(&bytes[..BODY]);
    bytes[BODY..].copy_from_slice(digest.as_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
/// Reserve a controller-assigned interval in the shared host B before listener construction.
///
/// The ledger path must be the same protected, local-filesystem file for every product
/// process on the host. Provision its parent directory before startup. New ledgers
/// initialize under the same lock; an existing empty/corrupt ledger fails closed.
/// There is no automatic stale-claim reclamation and no networking side effect.
///
/// # Errors
/// Refuses overlap (live or stale), mismatched host policy, full/corrupt ledger,
/// arithmetic overflow, unavailable OS locking and I/O failures.
pub fn reserve_host_slice(
    path: &Path,
    budget: &FrozenBudget,
    start: u64,
) -> Result<HostReservation> {
    let end = add(start, budget.reserved)?;
    if end > budget.host {
        return Err(BudgetError::Invalid("host interval"));
    }
    let (mut file, created) =
        match OpenOptions::new().read(true).write(true).create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                (OpenOptions::new().read(true).write(true).open(path)?, false)
            }
            Err(e) => return Err(e.into()),
        };
    // The original descriptor remains open for the claim lifetime. Separate handles
    // serialize independent processes and threads through an OS file lock.
    let locking = file.try_clone()?;
    let _guard = lock(&locking)?;
    let mut bytes = if created {
        let mut bytes = [0; SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        store(&mut bytes, 8, budget.ram);
        store(&mut bytes, 16, budget.host);
        write(&mut file, &mut bytes)?;
        bytes
    } else {
        read(&mut file)?
    };
    if number(&bytes, 8)? != budget.ram || number(&bytes, 16)? != budget.host {
        return Err(BudgetError::Invalid("host policy mismatch"));
    }
    let mut empty = None;
    for slot in 0..RECORDS {
        let offset = HEADER + slot * RECORD_SIZE;
        let low = number(&bytes, offset)?;
        let high = number(&bytes, offset + 8)?;
        if high == 0 {
            empty.get_or_insert(slot);
            continue;
        }
        if low >= high || high > budget.host || (start < high && low < end) {
            return Err(BudgetError::Invalid("overlapping or stale host claim"));
        }
    }
    let slot = empty.ok_or(BudgetError::Invalid("host ledger full"))?;
    let offset = HEADER + slot * RECORD_SIZE;
    store(&mut bytes, offset, start);
    store(&mut bytes, offset + 8, end);
    let pid = u64::from(std::process::id());
    store(&mut bytes, offset + 16, pid);
    bytes[offset + 24..offset + 56].copy_from_slice(&budget.digest);
    write(&mut file, &mut bytes)?;
    Ok(HostReservation(Arc::new(Claim { file, slot, digest: budget.digest, start, end, pid })))
}
impl HostReservation {
    /// Number of retained final-owner references, useful for lifetime assertions.
    #[must_use]
    pub fn owners(&self) -> usize {
        Arc::strong_count(&self.0)
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        let result = (|| -> Result<()> {
            let locking = self.file.try_clone()?;
            let _guard = lock(&locking)?;
            let mut bytes = read(&mut self.file)?;
            let offset = HEADER + self.slot * RECORD_SIZE;
            if bytes[offset + 24..offset + 56] != self.digest
                || number(&bytes, offset)? != self.start
                || number(&bytes, offset + 8)? != self.end
                || number(&bytes, offset + 16)? != self.pid
            {
                return Err(BudgetError::Invalid("changed host claim"));
            }
            bytes[offset..offset + RECORD_SIZE].fill(0);
            write(&mut self.file, &mut bytes)
        })();
        if let Err(error) = result {
            tracing::error!(%error,"QUIC reservation retained; controller recovery required");
        }
    }
}
