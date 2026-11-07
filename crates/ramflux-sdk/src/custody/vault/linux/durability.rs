// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! FD-scoped durability operations shared by the file writer and the installation initializer.
//! Every fsync, rename and unlink of a publication goes only through [`DurabilityOps`], so an
//! oracle implementing it observes (and can fail) the real calls at the syscall boundary.
use rustix::{
    fs::{self, AtFlags, RenameFlags},
    io::Errno,
};
use std::{fs::File, os::fd::OwnedFd};

pub(super) trait DurabilityOps {
    fn fsync_file(&self, file: &File) -> Result<(), Errno>;
    fn fsync_dir(&self, dir: &OwnedFd) -> Result<(), Errno>;
    fn rename(&self, dir: &OwnedFd, from: &str, to: &str, flags: RenameFlags) -> Result<(), Errno>;
    fn unlink(&self, dir: &OwnedFd, name: &str) -> Result<(), Errno>;
}

/// Production implementation: the real syscalls and nothing else.
pub(super) struct RealDurabilityOps;
impl DurabilityOps for RealDurabilityOps {
    fn fsync_file(&self, file: &File) -> Result<(), Errno> {
        file.sync_all().map_err(|e| Errno::from_io_error(&e).unwrap_or(Errno::IO))
    }
    fn fsync_dir(&self, dir: &OwnedFd) -> Result<(), Errno> {
        fs::fsync(dir)
    }
    fn rename(&self, dir: &OwnedFd, from: &str, to: &str, flags: RenameFlags) -> Result<(), Errno> {
        fs::renameat_with(dir, from, dir, to, flags)
    }
    fn unlink(&self, dir: &OwnedFd, name: &str) -> Result<(), Errno> {
        fs::unlinkat(dir, name, AtFlags::empty())
    }
}

/// Test oracle: records each operation when it is invoked, with the identity it acts on, then
/// either performs the real syscall or returns an injected error instead of performing it.
#[cfg(test)]
pub(super) mod recording {
    use super::*;
    use std::cell::RefCell;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Op {
        FileSync,
        Rename,
        Unlink,
        DirSync,
    }
    pub(crate) struct RecordingOps {
        pub(crate) log: RefCell<Vec<Op>>,
        /// Identity of each call: inode of an fsynced object, or the names renamed/unlinked.
        pub(crate) identity: RefCell<Vec<String>>,
        pub(crate) fail: Option<Op>,
    }
    impl RecordingOps {
        pub(crate) fn new(fail: Option<Op>) -> Self {
            Self { log: RefCell::new(Vec::new()), identity: RefCell::new(Vec::new()), fail }
        }
        fn step(
            &self,
            op: Op,
            who: String,
            real: impl FnOnce() -> Result<(), Errno>,
        ) -> Result<(), Errno> {
            self.log.borrow_mut().push(op);
            self.identity.borrow_mut().push(who);
            if self.fail == Some(op) { Err(Errno::IO) } else { real() }
        }
    }
    fn inode<F: std::os::fd::AsFd>(fd: &F) -> String {
        fs::fstat(fd).map_or_else(|_| "?".into(), |s| format!("ino{}", s.st_ino))
    }
    impl DurabilityOps for RecordingOps {
        fn fsync_file(&self, file: &File) -> Result<(), Errno> {
            self.step(Op::FileSync, format!("file:{}", inode(file)), || {
                RealDurabilityOps.fsync_file(file)
            })
        }
        fn fsync_dir(&self, dir: &OwnedFd) -> Result<(), Errno> {
            self.step(Op::DirSync, format!("dir:{}", inode(dir)), || {
                RealDurabilityOps.fsync_dir(dir)
            })
        }
        fn rename(
            &self,
            dir: &OwnedFd,
            from: &str,
            to: &str,
            flags: RenameFlags,
        ) -> Result<(), Errno> {
            self.step(Op::Rename, format!("{from}->{to}"), || {
                RealDurabilityOps.rename(dir, from, to, flags)
            })
        }
        fn unlink(&self, dir: &OwnedFd, name: &str) -> Result<(), Errno> {
            self.step(Op::Unlink, name.to_owned(), || RealDurabilityOps.unlink(dir, name))
        }
    }
}
