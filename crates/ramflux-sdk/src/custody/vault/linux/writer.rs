// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded blocking operations and serialized, durable ciphertext publication.
use super::{
    codec,
    files::{Error, Store, open_file},
};
use rustix::fs::{self, FlockOperation, OFlags, RenameFlags};
use std::{
    fs::File,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Slot;
impl Slot {
    fn acquire() -> Result<Self, Error> {
        ACTIVE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < 4).then_some(n + 1))
            .map_err(|_| Error::Busy)?;
        Ok(Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) enum Operation {
    Read { reference: String, kind: u8, generation: u64 },
    Insert { reference: String, kind: u8, record: Vec<u8> },
    Replace { reference: String, expected: u64, record: Vec<u8> },
    Delete { reference: String, kind: u8, generation: u64 },
}
impl Store {
    /// Slots and account locks live inside the worker, including after caller cancellation.
    pub(super) async fn execute(self: Arc<Self>, operation: Operation) -> Result<Vec<u8>, Error> {
        let slot = Slot::acquire()?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            self.apply(operation, |_| {})
        })
        .await
        .map_err(|_| Error::Io)?
    }
    pub(super) fn apply(&self, operation: Operation, cut: impl Fn(&str)) -> Result<Vec<u8>, Error> {
        let lock = open_file(&self.account_dir, ".writer.lock", OFlags::RDWR | OFlags::CREATE)?;
        // Immediate refusal is within the five-second maximum; never sleep on a lock.
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|e| if e == rustix::io::Errno::WOULDBLOCK { Error::Busy } else { e.into() })?;
        let (reference, kind, record, replace) = match operation {
            Operation::Read { reference, kind, generation } => {
                return self.read(&reference, kind, generation);
            }
            Operation::Delete { reference, kind, generation } => {
                self.read(&reference, kind, generation)?;
                cut("before_delete");
                self.unlink(&reference)?;
                cut("after_delete");
                fs::fsync(&self.realm_dir)?;
                cut("delete_synced");
                return Ok(Vec::new());
            }
            Operation::Insert { reference, kind, record } => (reference, kind, record, false),
            Operation::Replace { reference, expected, record } => {
                if self.realm != 3 || !reference.starts_with("unlock:") {
                    return Err(Error::Replacement);
                }
                let generation = expected.checked_add(1).ok_or(Error::Generation)?;
                self.read(&reference, 4, expected).map_err(|e| {
                    if e == Error::Record(codec::Error::Authentication) {
                        Error::Generation
                    } else {
                        e
                    }
                })?;
                codec::validate_record(self.binding(4, &reference, generation), &record)
                    .map_err(Error::Record)?;
                (reference, 4, record, true)
            }
        };
        let generation = if replace {
            u64::from_be_bytes(record[28..36].try_into().map_err(|_| Error::Generation)?)
        } else {
            1
        };
        codec::validate_record(self.binding(kind, &reference, generation), &record)
            .map_err(Error::Record)?;
        let mut entries = 0;
        for item in fs::Dir::read_from(&self.realm_dir)? {
            let item = item?;
            if matches!(item.file_name().to_bytes(), b"." | b"..") {
                continue;
            }
            entries += 1;
            if entries >= 16 {
                return Err(Error::Full);
            }
        }
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Io)?;
        let temp = format!(".pending-{}", ramflux_protocol::encode_base64url(nonce));
        let fd = open_file(&self.realm_dir, &temp, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(&record).map_err(|_| Error::Io)?;
            cut("written");
            file.sync_all().map_err(|_| Error::Io)?;
            cut("file_synced");
            let flags = if replace { RenameFlags::empty() } else { RenameFlags::NOREPLACE };
            cut("before_publish");
            fs::renameat_with(&self.realm_dir, &temp, &self.realm_dir, &reference, flags)?;
            cut("published");
            fs::fsync(&self.realm_dir)?;
            cut("parent_synced");
            Ok(Vec::new())
        })();
        // Only this operation's exclusive temporary can be removed on failure.
        if result.is_err() {
            match self.unlink(&temp) {
                Ok(()) => fs::fsync(&self.realm_dir)?,
                Err(Error::Missing) => {}
                Err(e) => return Err(e),
            }
        }
        result
    }
}

#[cfg(test)]
mod tests;
