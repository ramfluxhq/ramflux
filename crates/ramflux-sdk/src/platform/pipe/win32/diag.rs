// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only snapshot of the process token and of an object's security descriptor.
//!
//! These reads are not recorded by `note_call`, so they do not replace the name of the call
//! that failed.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSidSubAuthority, GetSidSubAuthorityCount, IsValidSid,
    LABEL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenElevationType, TokenElevationTypeDefault,
    TokenElevationTypeFull, TokenElevationTypeLimited, TokenIntegrityLevel, TokenIsAppContainer,
    TokenOwner, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::PWSTR;

const OWNER_DACL_LABEL: OBJECT_SECURITY_INFORMATION =
    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
const OWNER_DACL: OBJECT_SECURITY_INFORMATION =
    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
/// Bound for a security-descriptor string. A missing NUL stops the walk here.
const MAX_SDDL_UNITS: usize = 4096;

/// TokenUser, TokenOwner, elevation, integrity, and the app-container flag.
///
/// A query that fails is named in the string. The others are still reported.
#[must_use]
pub(crate) fn token_line() -> String {
    let token = match open_process_token() {
        Ok(token) => token,
        Err(error) => return format!("token=open-failed:{error}"),
    };
    format!(
        "{} {} {} {} {} {}",
        sid_part(&token, TokenUser, "user", token_user_sid),
        sid_part(&token, TokenOwner, "owner", token_owner_sid),
        elevation_part(&token),
        elevation_type_part(&token),
        integrity_part(&token),
        container_part(&token),
    )
}

/// SDDL read back from `path`. `pipe` selects a kernel object (`\\.\pipe\...`); a file or
/// directory uses the path as given, without a `\\?\` prefix.
///
/// On failure the string says why. It does not fail the caller.
#[must_use]
pub(crate) fn object_sddl(path: &Path, pipe: bool) -> String {
    let wide = match wide_name(path) {
        Ok(wide) => wide,
        Err(error) => return format!("read-back failed: {error}"),
    };
    let kind = if pipe { SE_KERNEL_OBJECT } else { SE_FILE_OBJECT };
    match query_sddl(&wide, kind, OWNER_DACL_LABEL) {
        Ok(text) => text,
        Err(label_error) => match query_sddl(&wide, kind, OWNER_DACL) {
            Ok(text) => format!("label read failed: {label_error}; {text}"),
            Err(error) => format!("read-back failed: label read failed: {label_error}; {error}"),
        },
    }
}

fn open_process_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is always valid. On success `token` is a live
    // process-token handle, and this function takes ownership of it.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedHandle::from_raw_handle(token))
    }
}

fn sid_part(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
    label: &str,
    pointer: impl FnOnce(&super::TokenBuffer) -> PSID,
) -> String {
    let buffer = match super::token_information(token, class) {
        Ok(buffer) => buffer,
        Err(error) => return format!("{label}=query-failed:{error}"),
    };
    // SAFETY: `pointer` returns the SID address written into `buffer` by the query above.
    // `copy_from` accepts a null pointer and copies the SID before `buffer` is dropped.
    let copied = unsafe { super::Sid::copy_from(pointer(&buffer)) };
    match copied {
        Ok(sid) => match sid.to_sddl_string() {
            Ok(text) => format!("{label}={text}"),
            Err(error) => format!("{label}=string-failed:{error}"),
        },
        Err(error) => format!("{label}=copy-failed:{error}"),
    }
}

fn token_user_sid(buffer: &super::TokenBuffer) -> PSID {
    // SAFETY: a successful TokenUser query writes a TOKEN_USER at the aligned start of the
    // buffer. The SID it names lives in that buffer.
    unsafe { (*buffer.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

fn token_owner_sid(buffer: &super::TokenBuffer) -> PSID {
    // SAFETY: a successful TokenOwner query writes a TOKEN_OWNER at the aligned start of the
    // buffer. The SID it names lives in that buffer.
    unsafe { (*buffer.0.as_ptr().cast::<TOKEN_OWNER>()).Owner }
}

fn elevation_part(token: &OwnedHandle) -> String {
    match u32_field(token, TokenElevation) {
        Ok(value) => format!("elevated={value}"),
        Err(error) => format!("elevated=query-failed:{error}"),
    }
}

fn elevation_type_part(token: &OwnedHandle) -> String {
    match i32_field(token, TokenElevationType) {
        Ok(value) => format!("elevation={}", elevation_name(value)),
        Err(error) => format!("elevation=query-failed:{error}"),
    }
}

fn elevation_name(value: i32) -> &'static str {
    if value == TokenElevationTypeDefault {
        "default"
    } else if value == TokenElevationTypeFull {
        "full"
    } else if value == TokenElevationTypeLimited {
        "limited"
    } else {
        "other"
    }
}

fn integrity_part(token: &OwnedHandle) -> String {
    let buffer = match super::token_information(token, TokenIntegrityLevel) {
        Ok(buffer) => buffer,
        Err(error) => return format!("integrity=query-failed:{error}"),
    };
    // SAFETY: a successful TokenIntegrityLevel query writes a TOKEN_MANDATORY_LABEL whose SID
    // pointer addresses this buffer. The SID is checked before its last sub-authority is read.
    let rid = unsafe {
        let label = (*buffer.0.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        if label.is_null() || IsValidSid(label) == 0 {
            return "integrity=missing".to_owned();
        }
        let count_ptr = GetSidSubAuthorityCount(label);
        if count_ptr.is_null() {
            return "integrity=no-count".to_owned();
        }
        let count = *count_ptr;
        if count == 0 {
            return "integrity=no-rid".to_owned();
        }
        let rid_ptr = GetSidSubAuthority(label, u32::from(count) - 1);
        if rid_ptr.is_null() {
            return "integrity=no-rid".to_owned();
        }
        *rid_ptr
    };
    format!("integrity={rid:#x}/{}", integrity_name(rid))
}

fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x1000 => "low",
        super::MEDIUM_INTEGRITY_RID => "medium",
        0x3000 => "high",
        0x4000 => "system",
        _ => "other",
    }
}

fn container_part(token: &OwnedHandle) -> String {
    match u32_field(token, TokenIsAppContainer) {
        Ok(value) => format!("app_container={}", value != 0),
        Err(error) => format!("app_container=query-failed:{error}"),
    }
}

fn u32_field(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<u32> {
    let buffer = super::token_information(token, class)?;
    let bytes: [u8; 4] = buffer
        .0
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::other("token field shorter than 4 bytes"))?;
    Ok(u32::from_ne_bytes(bytes))
}

fn i32_field(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<i32> {
    let buffer = super::token_information(token, class)?;
    let bytes: [u8; 4] = buffer
        .0
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| io::Error::other("token field shorter than 4 bytes"))?;
    Ok(i32::from_ne_bytes(bytes))
}

fn wide_name(path: &Path) -> io::Result<Vec<u16>> {
    let raw = path.as_os_str();
    if raw.encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL"));
    }
    Ok(super::wide(raw))
}

fn query_sddl(
    name: &[u16],
    kind: SE_OBJECT_TYPE,
    info: OBJECT_SECURITY_INFORMATION,
) -> io::Result<String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call. On success `descriptor` is one
    // LocalAlloc block. The owner, group, and list pointers address that block and are not
    // freed on their own.
    let code = unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut group: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sacl: *mut ACL = std::ptr::null_mut();
        GetNamedSecurityInfoW(
            name.as_ptr(),
            kind,
            info,
            &raw mut owner,
            &raw mut group,
            &raw mut dacl,
            &raw mut sacl,
            &raw mut descriptor,
        )
    };
    if code != 0 {
        free_local(descriptor.cast());
        return Err(super::os_error(code));
    }
    if descriptor.is_null() {
        return Err(io::Error::other("security descriptor was null"));
    }
    let mut text: PWSTR = std::ptr::null_mut();
    // SAFETY: `descriptor` is the block just returned and is still owned here. On success
    // `text` is a separate LocalAlloc wide string.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            info,
            &raw mut text,
            std::ptr::null_mut(),
        )
    };
    free_local(descriptor.cast());
    if ok == 0 {
        free_local(text.cast());
        return Err(io::Error::last_os_error());
    }
    let value = wide_to_string(text);
    free_local(text.cast());
    if value.is_empty() {
        Err(io::Error::other("security descriptor string was empty"))
    } else {
        Ok(value)
    }
}

fn wide_to_string(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let mut units = Vec::with_capacity(64);
    // SAFETY: `text` is a LocalAlloc wide string from the convert call, or null (already
    // returned). The walk stops at the first NUL or at `MAX_SDDL_UNITS`.
    unsafe {
        let mut index = 0_usize;
        while index < MAX_SDDL_UNITS {
            let unit = *text.add(index);
            if unit == 0 {
                break;
            }
            units.push(unit);
            index += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

fn free_local(pointer: *mut std::ffi::c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: `pointer` is non-null and is a LocalAlloc block from GetNamedSecurityInfoW or
    // ConvertSecurityDescriptorToStringSecurityDescriptorW. It is freed only here.
    unsafe {
        LocalFree(pointer);
    }
}
