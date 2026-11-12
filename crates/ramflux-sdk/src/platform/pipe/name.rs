// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pipe name, its security descriptors, and the owner-only file that publishes the random part.
//!
//! The name is `\\.\pipe\ramflux-<user SID>-<128-bit random>`. Named pipes share one
//! machine-wide namespace, so the per-user name and the DACL provide the separation.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;

use super::win32::{self, SecurityDescriptor, Sid};
use crate::SdkError;

const NONCE_BYTES: usize = 16;
const NONCE_HEX_LEN: usize = NONCE_BYTES * 2;
/// `CreateNamedPipeW`: the entire pipe name string can be up to 256 characters long.
const MAX_PIPE_NAME_CHARS: usize = 256;

/// Pipe descriptor: owner is the user, the DACL is protected and holds only a deny for network
/// logons and full access for the user, and the label is medium integrity with no-write-up.
/// Everyone, Authenticated Users and ALL APPLICATION PACKAGES get nothing.
pub(super) fn pipe_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(D;;GA;;;NU)(A;;GA;;;{user_sid})S:(ML;;NW;;;ME)")
}

/// Name-file descriptor: owner is the user and the protected DACL holds only that user.
pub(super) fn name_file_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(A;;FA;;;{user_sid})")
}

/// # Errors
/// Returns an error when the nonce is not 32 lowercase hex digits or the name is too long.
pub(super) fn pipe_name(user_sid: &str, nonce: &str) -> Result<OsString, SdkError> {
    if !is_nonce(nonce) {
        return Err(SdkError::LocalBus("local bus pipe name file is malformed".to_owned()));
    }
    let name = format!(r"\\.\pipe\ramflux-{user_sid}-{nonce}");
    if name.chars().count() > MAX_PIPE_NAME_CHARS {
        return Err(SdkError::LocalBus("local bus pipe name is too long".to_owned()));
    }
    Ok(OsString::from(name))
}

fn is_nonce(value: &str) -> bool {
    value.len() == NONCE_HEX_LEN
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// 128 random bits as lowercase hex. A new value is drawn at every daemon start.
///
/// # Errors
/// Returns [`SdkError::CustodyRandomUnavailable`] when the system generator fails.
pub(super) fn fresh_nonce() -> Result<String, SdkError> {
    let mut bytes = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    let mut text = String::with_capacity(NONCE_HEX_LEN);
    for byte in bytes {
        text.push(hex_digit(byte >> 4));
        text.push(hex_digit(byte & 0x0f));
    }
    Ok(text)
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 { b'0' + nibble } else { b'a' + (nibble - 10) })
}

/// Publish the nonce in a new owner-only file. Fails if the path exists.
///
/// # Errors
/// Returns an error when the file cannot be created or written.
pub(super) fn write_name_file(
    path: &Path,
    descriptor: &SecurityDescriptor,
    nonce: &str,
) -> Result<(), SdkError> {
    let mut file = win32::create_new_file(path, descriptor)?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Read the nonce. The file must be owned by `expected`.
///
/// # Errors
/// Returns [`SdkError::LocalBusPermissionDenied`] when another user owns the file, and an error
/// when it cannot be read or is malformed.
pub(super) fn read_name_file(path: &Path, expected: &Sid) -> Result<String, SdkError> {
    let file = std::fs::File::open(path)?;
    if win32::file_owner(&file)? != *expected {
        return Err(SdkError::LocalBusPermissionDenied);
    }
    read_nonce(file)
}

fn read_nonce(file: std::fs::File) -> Result<String, SdkError> {
    let mut text = String::new();
    let limit = u64::try_from(NONCE_HEX_LEN + 1).map_err(std::io::Error::other)?;
    file.take(limit).read_to_string(&mut text)?;
    if is_nonce(&text) {
        Ok(text)
    } else {
        Err(SdkError::LocalBus("local bus pipe name file is malformed".to_owned()))
    }
}

/// Whether the name file still publishes `nonce`. A missing file is not a match.
///
/// # Errors
/// Returns an error when the file exists but cannot be read.
pub(super) fn publishes(path: &Path, nonce: &str) -> Result<bool, SdkError> {
    match std::fs::File::open(path) {
        Ok(file) => Ok(read_nonce(file).is_ok_and(|current| current == nonce)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
