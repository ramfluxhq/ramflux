// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Win32 calls for owner-only files and directories: creation with an explicit security
//! descriptor, access-list reset, file identity, moves, known folders, and long paths.

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_RoamingAppData, SHGetKnownFolderPath,
};

use super::{SecurityDescriptor, Sid, owner_of, process_facts};

/// `MAX_PATH` minus the 8.3 file name a directory must still be able to hold.
const LEGACY_DIRECTORY_LIMIT: usize = 248;
const VERBATIM: &str = r"\\?\";

/// User SID of this process.
///
/// # Errors
/// Returns the OS error when the process token cannot be read.
pub(crate) fn current_user() -> io::Result<Sid> {
    Ok(process_facts()?.user)
}

/// Descriptor whose owner is the current user and whose protected access list holds only that
/// user. A directory's entry is inherited by the files and directories created inside it.
fn owner_descriptor(directory: bool) -> io::Result<(SecurityDescriptor, Sid)> {
    let user = current_user()?;
    let sid = user.to_sddl_string()?;
    let sddl = if directory {
        format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
    } else {
        format!("O:{sid}D:P(A;;FA;;;{sid})")
    };
    Ok((SecurityDescriptor::from_sddl(&sddl)?, user))
}

/// Wide, NUL-terminated form of `path`. An absolute path too long for the legacy limit gets the
/// `\\?\` prefix, which the file functions accept for names of up to 32,767 characters.
///
/// # Errors
/// Returns an error when the path holds an interior NUL or cannot be made absolute.
pub(crate) fn extended(path: &Path) -> io::Result<Vec<u16>> {
    let raw = path.as_os_str();
    if raw.encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL"));
    }
    let text = raw.to_string_lossy();
    if raw.len() < LEGACY_DIRECTORY_LIMIT || text.starts_with(VERBATIM) {
        return Ok(super::wide(raw));
    }
    // `absolute` resolves `.` and `..` and normalizes separators without touching the disk;
    // a verbatim path is passed to the file system as written, so it must already be normal.
    let absolute = std::path::absolute(path)?;
    let text = absolute.to_string_lossy();
    let mut verbatim = OsString::from(VERBATIM);
    if let Some(share) = text.strip_prefix(r"\\") {
        verbatim.push("UNC\\");
        verbatim.push(share);
    } else {
        verbatim.push(absolute.as_os_str());
    }
    Ok(super::wide(&verbatim))
}

/// Open or create `path` with the owner-only descriptor.
///
/// A file that already existed keeps its old descriptor (`CreateFileW` ignores the descriptor
/// when it opens an existing file), so its owner is checked and its access list is reset on the
/// open handle before the handle is returned.
///
/// # Errors
/// Returns the OS error; `PermissionDenied` when an existing file belongs to another user.
pub(crate) fn open_owner_only(
    path: &Path,
    access: u32,
    disposition: u32,
    flags: u32,
) -> io::Result<File> {
    let wide = extended(path)?;
    let (descriptor, user) = owner_descriptor(false)?;
    let attributes = descriptor.attributes()?;
    // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor outlive the call; the
    // returned handle is owned by the `File`. The last-error value is read before any other
    // call can replace it.
    let (file, existed) = super::assigning_owner(|| unsafe {
        SetLastError(0);
        let handle = CreateFileW(
            wide.as_ptr(),
            access | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            disposition,
            FILE_ATTRIBUTE_NORMAL | flags,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let existed = GetLastError() == ERROR_ALREADY_EXISTS;
        Ok((File::from_raw_handle(handle), existed))
    })?;
    if existed {
        if owner_of(file.as_raw_handle(), SE_FILE_OBJECT)? != user {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        reset_access_list(&file, &descriptor)?;
    }
    Ok(file)
}

fn access_list(descriptor: &SecurityDescriptor) -> io::Result<*mut ACL> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut list: *mut ACL = std::ptr::null_mut();
    // SAFETY: `descriptor` owns a valid self-relative descriptor; the returned pointer points
    // into it and is used only while `descriptor` is alive.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.raw,
            &raw mut present,
            &raw mut list,
            &raw mut defaulted,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || list.is_null() {
        // A missing list would grant everyone full access. Never apply it.
        return Err(io::Error::other("descriptor has no access list"));
    }
    Ok(list)
}

fn reset_access_list(file: &File, descriptor: &SecurityDescriptor) -> io::Result<()> {
    let list = access_list(descriptor)?;
    // SAFETY: `file` is open with WRITE_DAC; `list` points into `descriptor`, alive here.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            list,
            std::ptr::null(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(i32::try_from(status).map_err(io::Error::other)?))
    }
}

/// Replace the access list of an existing file or directory with the owner-only one. The path
/// must already belong to the current user.
///
/// # Errors
/// Returns the OS error; `PermissionDenied` when the path belongs to another user.
pub(crate) fn restrict(path: &Path, directory: bool) -> io::Result<()> {
    let wide = extended(path)?;
    let (descriptor, user) = owner_descriptor(directory)?;
    // SAFETY: `wide` is NUL-terminated; the handle is owned by the `File`. Backup semantics is
    // the documented way to obtain a directory handle; it grants nothing without the privilege.
    let file = unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        File::from_raw_handle(handle)
    };
    if owner_of(file.as_raw_handle(), SE_FILE_OBJECT)? != user {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    reset_access_list(&file, &descriptor)
}

/// Create one directory with the owner-only, inheritable descriptor. Fails if it exists.
///
/// # Errors
/// Returns the OS error; `AlreadyExists` when the path exists.
pub(crate) fn create_dir_owner_only(path: &Path) -> io::Result<()> {
    let wide = extended(path)?;
    let (descriptor, _) = owner_descriptor(true)?;
    let attributes = descriptor.attributes()?;
    // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor outlive the call.
    super::assigning_owner(|| {
        if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

/// Owner SID of an existing file or directory, without following a final reparse point.
///
/// # Errors
/// Returns the OS error when the path cannot be opened or its owner cannot be read.
pub(crate) fn path_owner(path: &Path) -> io::Result<Sid> {
    let file = open_for_facts(path, READ_CONTROL)?;
    owner_of(file.as_raw_handle(), SE_FILE_OBJECT)
}

fn open_for_facts(path: &Path, access: u32) -> io::Result<File> {
    let wide = extended(path)?;
    // SAFETY: `wide` is NUL-terminated; the handle is owned by the `File`.
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(File::from_raw_handle(handle))
    }
}

/// Volume serial number and file index of an open file: the Windows file identity.
///
/// # Errors
/// Returns the OS error when the information cannot be read.
pub(crate) fn identity(file: &File) -> io::Result<(u64, u64)> {
    // SAFETY: the all-zero bit pattern is a valid BY_HANDLE_FILE_INFORMATION.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is an open handle and `information` is a writable structure of the
    // documented size.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((u64::from(information.dwVolumeSerialNumber), index))
}

/// Identity of the object at `path`, without following a final reparse point. `None` when the
/// path does not exist.
///
/// # Errors
/// Returns the OS error for any failure other than a missing path.
pub(crate) fn path_identity(path: &Path) -> io::Result<Option<(u64, u64)>> {
    match open_for_facts(path, 0) {
        Ok(file) => identity(&file).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Move `from` to `to` on the same volume and return only when the move is on disk.
/// With `replace`, an existing destination file is replaced in one step; without it, an
/// existing destination fails with `AlreadyExists`.
///
/// # Errors
/// Returns the OS error.
pub(crate) fn move_file(from: &Path, to: &Path, replace: bool) -> io::Result<()> {
    let from = extended(from)?;
    let to = extended(to)?;
    let flags = MOVEFILE_WRITE_THROUGH | if replace { MOVEFILE_REPLACE_EXISTING } else { 0 };
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A per-user known folder.
#[derive(Clone, Copy)]
pub(crate) enum KnownFolder {
    /// `%LOCALAPPDATA%`: stays on this machine.
    LocalAppData,
    /// `%APPDATA%`: may be copied to other machines with a roaming profile.
    RoamingAppData,
}

/// Path of a known folder of the current user, without a trailing backslash.
///
/// # Errors
/// Returns an error when the shell does not report the folder.
pub(crate) fn known_folder(folder: KnownFolder) -> io::Result<PathBuf> {
    static LOCAL: windows_sys::core::GUID = FOLDERID_LocalAppData;
    static ROAMING: windows_sys::core::GUID = FOLDERID_RoamingAppData;
    let id = match folder {
        KnownFolder::LocalAppData => &raw const LOCAL,
        KnownFolder::RoamingAppData => &raw const ROAMING,
    };
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `id` points at a constant GUID; a null token asks for the current user. The
    // returned buffer is released with CoTaskMemFree whether or not the call succeeds.
    unsafe {
        let status = SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &raw mut text);
        let result = if status == 0 && !text.is_null() {
            let mut len = 0_usize;
            while *text.add(len) != 0 {
                len += 1;
            }
            Ok(PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(text, len))))
        } else {
            Err(io::Error::other(format!("known folder unavailable ({status:#010x})")))
        };
        CoTaskMemFree(text.cast());
        result
    }
}
