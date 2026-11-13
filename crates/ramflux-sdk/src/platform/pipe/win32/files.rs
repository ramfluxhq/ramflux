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
    ERROR_ALREADY_EXISTS, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE, SetLastError,
};
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    GetFinalPathNameByHandleW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS, WRITE_DAC,
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
/// user. `FA` is `FILE_ALL_ACCESS`: specific read, write, standard, and `SYNCHRONIZE` rights.
/// `CreateFile` adds `SYNCHRONIZE` even to an owner open that asked only for `READ_CONTROL`,
/// and the owner's implicit rights do not include it. A directory has one entry for itself and
/// one inherit-only entry, so a file created inside it receives the same list.
pub(crate) fn owner_only_sddl(directory: bool) -> io::Result<String> {
    let sid = current_user()?.to_sddl_string()?;
    Ok(if directory {
        format!("O:{sid}D:P(A;;FA;;;{sid})(A;OICIIO;FA;;;{sid})")
    } else {
        format!("O:{sid}D:P(A;;FA;;;{sid})")
    })
}

fn owner_descriptor(directory: bool) -> io::Result<(SecurityDescriptor, Sid)> {
    let user = current_user()?;
    let sddl = owner_only_sddl(directory)?;
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
/// A new file keeps the descriptor passed to `CreateFileW`. A file that already existed keeps
/// its old descriptor (`CreateFileW` ignores the descriptor on an existing file), so its owner
/// is checked and its access list is reset before the handle is returned.
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
        super::note_call("CreateFileW(open_owner_only)");
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
        if !super::owner_matches_user(&owner_of(file.as_raw_handle(), SE_FILE_OBJECT)?, &user)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        reset_access_list(&file, &descriptor)?;
    }
    Ok(file)
}

/// Open an existing file without truncating it, or create a new empty file.
///
/// `CREATE_ALWAYS` truncates before the owner can be read. This opens with `OPEN_EXISTING`
/// and `FILE_FLAG_OPEN_REPARSE_POINT`, refuses a reparse point or another user's file while
/// the bytes are still intact, applies the protected access list, and only then truncates
/// that same handle. A missing file is created with `CREATE_NEW` and the owner-only descriptor.
///
/// # Errors
/// `PermissionDenied` when the file is a reparse point, a directory, or owned by another user.
/// `NotFound` is not returned: a missing file is created. Any other failure is the OS error.
pub(crate) fn open_owner_only_truncate(path: &Path) -> io::Result<File> {
    let wide = extended(path)?;
    let (descriptor, user) = owner_descriptor(false)?;
    match open_existing_no_truncate(&wide) {
        Ok(file) => {
            let attributes = file_information(&file)?.dwFileAttributes;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "truncate target is a link or a directory",
                ));
            }
            if !super::owner_matches_user(&owner_of(file.as_raw_handle(), SE_FILE_OBJECT)?, &user)?
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            reset_access_list(&file, &descriptor)?;
            file.set_len(0)?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_new_exclusive(&wide, &descriptor)
        }
        Err(error) => Err(error),
    }
}

fn open_existing_no_truncate(wide: &[u16]) -> io::Result<File> {
    // SAFETY: `wide` is NUL-terminated and the handle is owned by the `File`.
    // `OPEN_EXISTING` does not truncate. `FILE_FLAG_OPEN_REPARSE_POINT` returns the link
    // itself so a junction is not followed before the refusal below.
    super::note_call("CreateFileW(open_existing_no_truncate)");
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(File::from_raw_handle(handle))
        }
    }
}

fn create_new_exclusive(wide: &[u16], descriptor: &SecurityDescriptor) -> io::Result<File> {
    let attributes = descriptor.attributes()?;
    super::assigning_owner(|| {
        super::note_call("CreateFileW(create_new_exclusive)");
        // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor outlive the call;
        // the handle is owned by the `File`. `CREATE_NEW` fails if the name appeared after
        // the `OPEN_EXISTING` miss, so this never truncates an existing file.
        unsafe {
            let handle = CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(File::from_raw_handle(handle))
            }
        }
    })
}

fn reset_access_list(file: &File, descriptor: &SecurityDescriptor) -> io::Result<()> {
    super::set_handle_dacl(file.as_raw_handle(), SE_FILE_OBJECT, descriptor)
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
    super::note_call("CreateFileW(restrict)");
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
    if is_reparse_point(&file)? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "reparse point"));
    }
    if !super::owner_matches_user(&owner_of(file.as_raw_handle(), SE_FILE_OBJECT)?, &user)? {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    reset_access_list(&file, &descriptor)
}

/// Create every missing component of `root` as an owner-only directory and require the final
/// directory to belong to the current user.
///
/// Each existing component is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and held until this
/// function returns, so a junction cannot be given our access list and a child is not created
/// through one. A reparse point, a resolved path under the roaming profile, or another user's
/// directory is `PermissionDenied` before any create or access-list write.
///
/// # Errors
/// `PermissionDenied` for a reparse point, a roaming location, or another user's directory.
/// Otherwise the OS error.
pub(crate) fn prepare_owner_only_directory(root: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(root)?;
    let prefixes = ancestors_inclusive(&absolute)?;
    let roaming = known_folder(KnownFolder::RoamingAppData)?;
    let mut held = Vec::with_capacity(prefixes.len());
    for (index, prefix) in prefixes.iter().enumerate() {
        // `FILE_READ_ATTRIBUTES` is what `GetFinalPathNameByHandleW` requires. Access 0 can
        // read the reparse bit and still fail the final-path query, which would refuse every
        // data root. It does not grant write or change the access list.
        let access = if index + 1 == prefixes.len() {
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES
        } else {
            FILE_READ_ATTRIBUTES
        };
        let file = match open_for_facts(prefix, access) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match create_dir_owner_only(prefix) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                open_for_facts(prefix, access)?
            }
            Err(error) => return Err(error),
        };
        // The handle is the object. Refuse it before any later create or access-list write,
        // and keep it open so the name we just checked cannot be replaced underneath us.
        if is_reparse_point(&file)? {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "reparse point"));
        }
        let resolved = final_path(&file)?;
        if directory_is_inside(&resolved, &roaming) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "roaming profile"));
        }
        held.push(file);
    }
    let Some(directory) = held.last() else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "empty path"));
    };
    let (descriptor, user) = owner_descriptor(true)?;
    let owner = owner_of(directory.as_raw_handle(), SE_FILE_OBJECT)?;
    if !super::owner_matches_user(&owner, &user)? {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    reset_access_list(directory, &descriptor)?;
    let resolved = final_path(directory)?;
    drop(held);
    Ok(resolved)
}

fn ancestors_inclusive(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut chain = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        chain.push(cursor.clone());
        match cursor.parent() {
            Some(parent) if parent != cursor && !parent.as_os_str().is_empty() => {
                cursor = parent.to_path_buf();
            }
            _ => break,
        }
    }
    if chain.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    }
    chain.reverse();
    Ok(chain)
}

fn directory_is_inside(path: &Path, ancestor: &Path) -> bool {
    let path = normalized_path(path);
    let ancestor = normalized_path(ancestor);
    path == ancestor || path.strip_prefix(&ancestor).is_some_and(|rest| rest.starts_with('\\'))
}

fn normalized_path(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    text.trim_end_matches('\\').to_lowercase()
}

/// Create one directory with the owner-only, inheritable descriptor. Fails if it exists.
///
/// # Errors
/// Returns the OS error; `AlreadyExists` when the path exists.
pub(crate) fn create_dir_owner_only(path: &Path) -> io::Result<()> {
    let wide = extended(path)?;
    let descriptor = SecurityDescriptor::from_sddl(&owner_only_sddl(true)?)?;
    let attributes = descriptor.attributes()?;
    // The descriptor is applied by `CreateDirectoryW`. A follow-up owner write returns access
    // denied on an elevated token and used to delete the directory.
    super::assigning_owner(|| {
        super::note_call("CreateDirectoryW");
        // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor outlive the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

/// Whether `owner` is acceptable for an object that must belong to `user`.
///
/// An elevated token may leave BUILTIN\Administrators as the owner. The access list still
/// names only the user. See `owner_matches_user` on the parent module.
///
/// # Errors
/// Returns the OS error when the process token cannot be read.
#[cfg(test)]
pub(crate) fn owner_matches_user(owner: &Sid, user: &Sid) -> io::Result<bool> {
    super::owner_matches_user(owner, user)
}

/// Owner SID of an existing file or directory, without following a final reparse point.
///
/// # Errors
/// Returns the OS error when the path cannot be opened or its owner cannot be read.
#[cfg(test)]
pub(crate) fn path_owner(path: &Path) -> io::Result<Sid> {
    let file = open_for_facts(path, READ_CONTROL)?;
    owner_of(file.as_raw_handle(), SE_FILE_OBJECT)
}

fn open_for_facts(path: &Path, access: u32) -> io::Result<File> {
    let wide = extended(path)?;
    // SAFETY: `wide` is NUL-terminated; the handle is owned by the `File`.
    super::note_call("CreateFileW(open_for_facts)");
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
    let information = file_information(file)?;
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((u64::from(information.dwVolumeSerialNumber), index))
}

fn file_information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: the all-zero bit pattern is a valid BY_HANDLE_FILE_INFORMATION.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is an open handle and `information` is a writable structure of the
    // documented size.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

/// `FILE_ATTRIBUTE_REPARSE_POINT` on this handle. The handle must have been opened with
/// `FILE_FLAG_OPEN_REPARSE_POINT`, or a junction would already have been followed.
///
/// # Errors
/// Returns the OS error when the information cannot be read.
pub(crate) fn is_reparse_point(file: &File) -> io::Result<bool> {
    Ok(file_information(file)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0_u16; 512];
    loop {
        // SAFETY: `file` is an open handle. `buffer` is writable and its length fits in `u32`
        // because it starts at 512 and only grows by the size the call reports.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                VOLUME_NAME_DOS,
            )
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        let written = usize::try_from(written).map_err(io::Error::other)?;
        if written < buffer.len() {
            buffer.truncate(written);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        buffer.resize(written + 1, 0);
    }
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

/// Replace only the access list. The owner is left as it is.
///
/// # Errors
/// Returns the OS error when the path cannot be opened or the list cannot be written.
#[cfg(test)]
pub(crate) fn replace_dacl(path: &Path, sddl: &str) -> io::Result<()> {
    let descriptor = super::SecurityDescriptor::from_sddl(sddl)?;
    let file = open_for_facts(path, READ_CONTROL | WRITE_DAC)?;
    if is_reparse_point(&file)? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "reparse point"));
    }
    reset_access_list(&file, &descriptor)
}

#[cfg(test)]
unsafe extern "system" {
    fn DeviceIoControl(
        device: *mut core::ffi::c_void,
        code: u32,
        input: *const u8,
        input_size: u32,
        output: *mut u8,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
}

/// Create a directory junction `link` -> `target`. This does not need the symbolic-link
/// privilege. `link` must not exist; `target` must be an existing directory.
///
/// # Errors
/// Returns the OS error when the junction cannot be created.
#[cfg(test)]
pub(crate) fn plant_mount_point(link: &Path, target: &Path) -> io::Result<()> {
    std::fs::create_dir(link)?;
    let target = std::path::absolute(target)?;
    let substitute = format!(r"\??\{}", target.display());
    let print = target.display().to_string();
    let substitute: Vec<u16> = substitute.encode_utf16().collect();
    let print: Vec<u16> = print.encode_utf16().collect();
    let substitute_bytes = u16::try_from(substitute.len() * 2).map_err(io::Error::other)?;
    let print_bytes = u16::try_from(print.len() * 2).map_err(io::Error::other)?;
    let print_offset = substitute_bytes
        .checked_add(2)
        .ok_or_else(|| io::Error::other("reparse buffer is too large"))?;
    let data_len = 8_u16
        .checked_add(substitute_bytes)
        .and_then(|len| len.checked_add(2))
        .and_then(|len| len.checked_add(print_bytes))
        .and_then(|len| len.checked_add(2))
        .ok_or_else(|| io::Error::other("reparse buffer is too large"))?;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&0xA000_0003_u32.to_le_bytes());
    buffer.extend_from_slice(&data_len.to_le_bytes());
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    buffer.extend_from_slice(&substitute_bytes.to_le_bytes());
    buffer.extend_from_slice(&print_offset.to_le_bytes());
    buffer.extend_from_slice(&print_bytes.to_le_bytes());
    for unit in &substitute {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    for unit in &print {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    buffer.extend_from_slice(&0_u16.to_le_bytes());
    let wide = extended(link)?;
    // SAFETY: `wide` is NUL-terminated. Backup semantics is the documented way to open a
    // directory, and `FILE_FLAG_OPEN_REPARSE_POINT` keeps this call on the empty directory
    // rather than a link. The handle is closed at the end of this function.
    super::note_call("CreateFileW(plant_mount_point)");
    let file = unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
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
    let mut returned = 0_u32;
    let input_size = u32::try_from(buffer.len()).map_err(io::Error::other)?;
    // SAFETY: `file` is the directory handle above. `buffer` is a mount-point reparse buffer
    // of `input_size` bytes. No output buffer is required for this control code.
    super::note_call("DeviceIoControl(FSCTL_SET_REPARSE_POINT)");
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00A4,
            buffer.as_ptr(),
            input_size,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
