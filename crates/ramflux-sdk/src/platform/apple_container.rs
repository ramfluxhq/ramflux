// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! iOS app-container rules for the data root: the directory is excluded from device
//! backups, and the directory and everything in it carries the data-protection class
//! "complete until first user authentication", so the database opens in the background
//! after the first unlock since boot and is encrypted at rest before it.
//!
//! The host application passes the directory (`Library/Application Support/ramflux` in its
//! own container, never an App Group). Both properties are set on the directory because
//! files SQLite recreates (the WAL and shm) inherit the directory's class and lose any
//! per-file flag. `CFURLSetResourcePropertyForKey` ignores a property the volume does not
//! support without reporting an error, so every write is read back through a new URL.
// Only this private CoreFoundation boundary permits unsafe.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;

use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    error::{CFError, CFErrorRef},
    string::{CFString, CFStringRef},
    url::{CFURL, CFURLRef, CFURLSetResourcePropertyForKey},
};

use crate::SdkError;

/// Directory levels walked below the data root when protecting files that already exist.
const MAX_DEPTH: usize = 8;

// The pinned sys crate leaves these documented CoreFoundation symbols commented out.
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    #[link_name = "kCFURLIsExcludedFromBackupKey"]
    static EXCLUDED_FROM_BACKUP_KEY: CFStringRef;
    #[link_name = "kCFURLFileProtectionKey"]
    static FILE_PROTECTION_KEY: CFStringRef;
    #[link_name = "kCFURLFileProtectionCompleteUntilFirstUserAuthentication"]
    static FILE_PROTECTION_UNTIL_FIRST_AUTHENTICATION: CFStringRef;
    #[link_name = "CFURLCopyResourcePropertyForKey"]
    fn copy_resource_property(
        url: CFURLRef,
        key: CFStringRef,
        value: *mut c_void,
        error: *mut CFErrorRef,
    ) -> u8;
}

fn failure(what: &str, path: &Path) -> SdkError {
    // The path is inside the app container and names no account; it is safe to report.
    SdkError::Io(std::io::Error::other(format!("{what}: {}", path.display())))
}

fn file_url(path: &Path, directory: bool) -> Result<CFURL, SdkError> {
    CFURL::from_path(path, directory).ok_or_else(|| failure("not a file URL", path))
}

fn set_property(
    path: &Path,
    directory: bool,
    key: CFStringRef,
    value: &CFType,
) -> Result<(), SdkError> {
    let url = file_url(path, directory)?;
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `url` and `value` are live owned CoreFoundation objects for the whole
    // synchronous call, `key` is a process-lifetime constant, and `error` points at a
    // local that receives either null or a create-rule CFError.
    let written = unsafe {
        CFURLSetResourcePropertyForKey(
            url.as_concrete_TypeRef(),
            key,
            value.as_CFTypeRef(),
            &raw mut error,
        )
    };
    // SAFETY: a non-null error follows the create rule; wrapping it releases it on drop.
    let _error = (!error.is_null()).then(|| unsafe { CFError::wrap_under_create_rule(error) });
    if written == 0 {
        return Err(failure("resource property was not written", path));
    }
    Ok(())
}

/// Read one property from disk through a new URL, so no value cached on the URL that wrote
/// it can answer.
fn copy_property(path: &Path, directory: bool, key: CFStringRef) -> Result<Option<CFType>, SdkError> {
    let url = file_url(path, directory)?;
    let mut value: CFTypeRef = std::ptr::null();
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: `url` is live for the synchronous call and `key` is a process-lifetime
    // constant. `value` and `error` point at locals of the pointer types the function
    // documents; each receives null or a create-rule object.
    let read = unsafe {
        copy_resource_property(
            url.as_concrete_TypeRef(),
            key,
            (&raw mut value).cast::<c_void>(),
            &raw mut error,
        )
    };
    // SAFETY: non-null results follow the create rule; wrap both before branching so
    // every exit releases them.
    let owned = (!value.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(value) });
    // SAFETY: as above, for the error object.
    let _error = (!error.is_null()).then(|| unsafe { CFError::wrap_under_create_rule(error) });
    if read == 0 {
        return Err(failure("resource property was not readable", path));
    }
    Ok(owned)
}

fn excluded_key() -> CFStringRef {
    // SAFETY: reading an immutable, process-lifetime CoreFoundation constant.
    unsafe { EXCLUDED_FROM_BACKUP_KEY }
}

fn protection_key() -> CFStringRef {
    // SAFETY: reading an immutable, process-lifetime CoreFoundation constant.
    unsafe { FILE_PROTECTION_KEY }
}

fn protection_class() -> CFString {
    // SAFETY: the constant is a valid process-lifetime CFString; the get rule retains it.
    unsafe { CFString::wrap_under_get_rule(FILE_PROTECTION_UNTIL_FIRST_AUTHENTICATION) }
}

fn exclude_from_backup(directory: &Path) -> Result<(), SdkError> {
    set_property(directory, true, excluded_key(), &CFBoolean::true_value().into_CFType())?;
    let stored = copy_property(directory, true, excluded_key())?;
    let excluded = stored
        .is_some_and(|value| value.as_CFTypeRef() == CFBoolean::true_value().as_CFTypeRef());
    if excluded { Ok(()) } else { Err(failure("directory is not excluded from backup", directory)) }
}

fn protect(path: &Path, directory: bool) -> Result<(), SdkError> {
    let class = protection_class();
    set_property(path, directory, protection_key(), &class.clone().into_CFType())?;
    let stored = copy_property(path, directory, protection_key())?
        .and_then(|value| value.downcast::<CFString>())
        .map(|value| value.to_string());
    match stored {
        Some(stored) if stored == class.to_string() => Ok(()),
        // The simulator's host file system has no data-protection classes and reports
        // none. A device must report the class that was written.
        None if cfg!(target_abi = "sim") => Ok(()),
        _ => Err(failure("data-protection class was not applied", path)),
    }
}

fn protect_tree(directory: &Path, depth: usize) -> Result<(), SdkError> {
    protect(directory, true)?;
    if depth >= MAX_DEPTH {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            protect_tree(&entry.path(), depth + 1)?;
        } else if kind.is_file() {
            // Files created before their directory carried the class keep their own.
            protect(&entry.path(), false)?;
        }
    }
    Ok(())
}

/// Apply the backup exclusion and the data-protection class to the data root. Idempotent;
/// called before every start and resume, while the supervisor does not hold a store.
///
/// # Errors
/// Fails closed when either property cannot be written or does not read back. Before the
/// first unlock since boot the container is not accessible and this fails; the host
/// retries once protected data becomes available.
pub(crate) fn protect_data_root(root: &Path) -> Result<(), SdkError> {
    exclude_from_backup(root)?;
    protect_tree(root, 0)
}
