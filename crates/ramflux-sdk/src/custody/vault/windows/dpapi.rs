// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The two DPAPI calls of the Windows vault. User scope only: the machine-scope flag is never
//! passed, and no prompt structure is supplied, so neither call can show UI.
// Only this private FFI boundary permits unsafe.
#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

/// Upper bound for a protected blob read from disk or returned by the system.
pub(super) const MAX_BLOB_BYTES: usize = 16 * 1024;

fn blob(bytes: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(io::Error::other)?,
        // The system only reads through the input and entropy blobs.
        pbData: bytes.as_ptr().cast_mut(),
    })
}

/// Copy a system-allocated output blob into a zeroizing buffer, wipe the system's copy, and
/// release it with `LocalFree`.
///
/// # Safety
/// `output` must be a blob a successful DPAPI call returned and that has not been freed.
unsafe fn take(output: &CRYPT_INTEGER_BLOB) -> io::Result<Zeroizing<Vec<u8>>> {
    if output.pbData.is_null() {
        return Err(io::Error::other("DPAPI returned no data"));
    }
    let len = usize::try_from(output.cbData).map_err(io::Error::other);
    // SAFETY: the caller guarantees `pbData` points at `cbData` bytes the system allocated;
    // the slice is dropped before the allocation is released.
    unsafe {
        let copied = len.and_then(|len| {
            let bytes = std::slice::from_raw_parts_mut(output.pbData, len);
            let copied = if len <= MAX_BLOB_BYTES {
                Ok(Zeroizing::new(bytes.to_vec()))
            } else {
                Err(io::Error::other("DPAPI blob too large"))
            };
            bytes.zeroize();
            copied
        });
        LocalFree(output.pbData.cast());
        copied
    }
}

/// Protect `plaintext` for the current user. `entropy` must be supplied again to unprotect.
///
/// # Errors
/// Returns the OS error when the user's DPAPI keys are unavailable.
pub(super) fn protect(plaintext: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = blob(plaintext)?;
    let entropy = blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: the input and entropy blobs point at live slices; the description, reserved and
    // prompt pointers are null as documented; `output` receives a system allocation that
    // `take` releases.
    unsafe {
        if CryptProtectData(
            &raw const input,
            std::ptr::null(),
            &raw const entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        take(&output)
    }
}

/// Unprotect a blob the same user protected with the same `entropy`.
///
/// # Errors
/// Returns the OS error for another user, another machine, other entropy or a damaged blob.
pub(super) fn unprotect(protected: &[u8], entropy: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    if protected.len() > MAX_BLOB_BYTES {
        return Err(io::Error::other("DPAPI blob too large"));
    }
    let input = blob(protected)?;
    let entropy = blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: as in `protect`; the description out-pointer is null, so nothing else is
    // allocated.
    unsafe {
        if CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            &raw const entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        take(&output)
    }
}
