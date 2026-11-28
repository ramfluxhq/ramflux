// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Separate OS identities and protected paths are mandatory; JSON never supplies peer identity.
use super::{Result, error, refuse};
use std::{
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
};

pub fn owner(path: &Path, uid: u32, mode: u32, directory: bool) -> Result<()> {
    if std::fs::canonicalize(path)? != path {
        return refuse("protected path contains a symlink");
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.uid() != uid
        || meta.mode() & 0o7777 != mode
        || if directory { !meta.is_dir() } else { !meta.is_file() }
    {
        return refuse("protected directory ownership/mode mismatch");
    }
    Ok(())
}

pub fn self_uid(expected: u32) -> Result<()> {
    if rustix::process::geteuid().as_raw() != expected || expected == 0 {
        return refuse("directory process UID mismatch");
    }
    Ok(())
}

pub fn socket_path(path: &Path, uid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| error("witness socket parent"))?;
    owner(parent, uid, 0o750, true)?;
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket() || meta.uid() != uid || meta.mode() & 0o7777 != 0o660 {
            return refuse("witness socket ownership/mode mismatch");
        }
    }
    Ok(())
}

pub fn peer(stream: &UnixStream, expected: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Only the peer UID is authority here. The kernel reports pid 0 when the peer lives in
        // another PID namespace (witness and centre in separate containers); that is expected
        // and the PID is not used. rustix's UCred cannot represent pid 0 (NonZero), so read the
        // raw ucred through nix instead.
        let credentials =
            nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
        if credentials.uid() != expected {
            return refuse("witness peer UID mismatch");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stream, expected);
        refuse("protected username services require Linux peer credentials")
    }
}
