// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only tokens: a low-integrity copy of this process's token and a second local user,
//! each impersonated on the calling thread until the guard is dropped.

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, GetLengthSid, ImpersonateLoggedOnUser, LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSID, RevertToSelf, SID_AND_ATTRIBUTES,
    SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenImpersonation, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{Sid, wide};

/// `SE_GROUP_INTEGRITY`.
const GROUP_INTEGRITY: u32 = 0x20;
/// The low mandatory level, `S-1-16-4096`.
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: the pointer came from ConvertStringSidToSidW and is freed only here.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn parse_sid(text: &str) -> io::Result<LocalSid> {
    let wide = wide(OsStr::new(text));
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `sid` receives an allocation owned by the guard.
    unsafe {
        if ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(LocalSid(sid))
}

/// # Errors
/// Returns the OS error when `text` is not a SID string.
pub(crate) fn sid_from_string(text: &str) -> io::Result<Sid> {
    let parsed = parse_sid(text)?;
    // SAFETY: `parsed` holds a SID the system just produced.
    unsafe { Sid::copy_from(parsed.0) }
}

/// Reverts the calling thread to the process token when dropped.
pub(crate) struct Impersonation {
    _token: OwnedHandle,
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        // SAFETY: no preconditions. A thread that cannot revert must not keep running.
        unsafe {
            if RevertToSelf() == 0 {
                std::process::abort();
            }
        }
    }
}

fn impersonate(token: OwnedHandle) -> io::Result<Impersonation> {
    // SAFETY: `token` is an open token handle with TOKEN_QUERY and TOKEN_IMPERSONATE.
    unsafe {
        if ImpersonateLoggedOnUser(token.as_raw_handle()) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Impersonation { _token: token })
}

/// Impersonate a copy of this process's token lowered to low integrity.
///
/// # Errors
/// Returns the OS error when the token cannot be duplicated, relabelled or impersonated.
pub(crate) fn impersonate_low_integrity() -> io::Result<Impersonation> {
    let access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT;
    let low = parse_sid(LOW_INTEGRITY_SID)?;
    let mut process_token: HANDLE = std::ptr::null_mut();
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: the process pseudo-handle is valid; each returned handle is owned. The label
    // structure points at `low`, which outlives the call.
    let copy = unsafe {
        if OpenProcessToken(GetCurrentProcess(), access, &raw mut process_token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let process_token = OwnedHandle::from_raw_handle(process_token);
        if DuplicateTokenEx(
            process_token.as_raw_handle(),
            access,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let copy = OwnedHandle::from_raw_handle(copy);
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES { Sid: low.0, Attributes: GROUP_INTEGRITY },
        };
        let length = u32::try_from(size_of::<TOKEN_MANDATORY_LABEL>())
            .map_err(io::Error::other)?
            .saturating_add(GetLengthSid(low.0));
        if SetTokenInformation(
            copy.as_raw_handle(),
            TokenIntegrityLevel,
            (&raw const label).cast(),
            length,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        copy
    };
    impersonate(copy)
}

/// Log a second local user on with explicit credentials and impersonate it.
///
/// # Errors
/// Returns the OS error when the logon or the impersonation fails.
pub(crate) fn impersonate_user(user: &str, password: &str) -> io::Result<Impersonation> {
    let user = wide(OsStr::new(user));
    let domain = wide(OsStr::new("."));
    let password = wide(OsStr::new(password));
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the three strings are NUL-terminated and outlive the call; the returned handle
    // is owned.
    let token = unsafe {
        if LogonUserW(
            user.as_ptr(),
            domain.as_ptr(),
            password.as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &raw mut token,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(token)
    };
    impersonate(token)
}
