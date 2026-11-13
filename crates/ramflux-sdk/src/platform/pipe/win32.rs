// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Win32 calls for the named-pipe carrier: SIDs, token facts, security descriptors, pipe
//! instances, owner lookups, and the privilege required to assign the user as owner. Every
//! `unsafe` block of the carrier lives in this file.
#![allow(unsafe_code)]

use std::cell::{Cell, UnsafeCell};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode};
use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_NOT_ALL_ASSIGNED, ERROR_PIPE_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CopySid, DACL_SECURITY_INFORMATION, GetLengthSid,
    GetSecurityDescriptorDacl, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    IsValidSid, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SECURITY_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    TokenIntegrityLevel, TokenIsAppContainer, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, READ_CONTROL, SECURITY_IDENTIFICATION, WRITE_DAC,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, INFINITE, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

#[cfg(test)]
thread_local! {
    static LAST_CALL: Cell<&'static str> = const { Cell::new("") };
}

/// Remember the Win32 call that is about to run, so a test can name the one that failed.
pub(crate) fn note_call(name: &'static str) {
    #[cfg(test)]
    LAST_CALL.with(|slot| slot.set(name));
    #[cfg(not(test))]
    let _ = name;
}

/// The call named by the last [`note_call`] on this thread.
#[cfg(test)]
pub(crate) fn last_call() -> &'static str {
    LAST_CALL.with(|slot| slot.get())
}

/// `SECURITY_MAX_SID_SIZE`: the largest binary SID.
const MAX_SID_BYTES: usize = 68;

/// `SECURITY_MANDATORY_MEDIUM_RID`: the integrity RID of a normal desktop process.
pub(super) const MEDIUM_INTEGRITY_RID: u32 = 0x2000;

#[derive(Clone, Copy)]
#[repr(C, align(4))]
struct SidBytes([u8; MAX_SID_BYTES]);

/// Owned binary SID. Equality is binary equality of the valid prefix, which is what `EqualSid`
/// compares.
#[derive(Clone, Copy)]
pub(crate) struct Sid {
    len: usize,
    bytes: SidBytes,
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Sid {}

impl Sid {
    fn as_bytes(&self) -> &[u8] {
        self.bytes.0.get(..self.len).unwrap_or(&[])
    }

    /// Copy a SID the system returned.
    ///
    /// # Safety
    /// `source` must be null or point at memory readable as a SID.
    unsafe fn copy_from(source: PSID) -> io::Result<Self> {
        if source.is_null() {
            return Err(io::Error::other("null SID"));
        }
        // SAFETY: the caller guarantees `source` is readable as a SID; `IsValidSid` checks the
        // revision and sub-authority count before the length is trusted.
        unsafe {
            if IsValidSid(source) == 0 {
                return Err(io::Error::other("invalid SID"));
            }
            let len = usize::try_from(GetLengthSid(source)).map_err(io::Error::other)?;
            if len == 0 || len > MAX_SID_BYTES {
                return Err(io::Error::other("SID length out of range"));
            }
            let mut bytes = SidBytes([0; MAX_SID_BYTES]);
            let capacity = u32::try_from(MAX_SID_BYTES).map_err(io::Error::other)?;
            if CopySid(capacity, bytes.0.as_mut_ptr().cast(), source) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { len, bytes })
        }
    }

    fn as_psid(&self) -> PSID {
        self.bytes.0.as_ptr().cast_mut().cast()
    }

    /// The `S-1-…` string form.
    ///
    /// # Errors
    /// Returns the OS error when the SID cannot be converted.
    pub(crate) fn to_sddl_string(&self) -> io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `self` holds a SID validated by `copy_from`; on success `text` is a
        // NUL-terminated buffer the system allocated, released below with `LocalFree`.
        unsafe {
            if ConvertSidToStringSidW(self.as_psid(), &raw mut text) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0_usize;
            while *text.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            value.map_err(io::Error::other)
        }
    }
}

/// What the carrier needs to know about a token.
#[derive(Clone, Copy)]
pub(crate) struct TokenFacts {
    pub(crate) user: Sid,
    pub(super) integrity_rid: u32,
    pub(super) app_container: bool,
}

/// Buffer for fixed-size token information classes; aligned for the pointer the structures hold.
#[repr(C, align(8))]
struct TokenBuffer([u8; 128]);

fn token_information(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
) -> io::Result<TokenBuffer> {
    let mut buffer = TokenBuffer([0; 128]);
    let mut returned = 0_u32;
    let capacity = u32::try_from(buffer.0.len()).map_err(io::Error::other)?;
    // SAFETY: `token` is an open token handle with TOKEN_QUERY; the buffer and its length match.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buffer.0.as_mut_ptr().cast(),
            capacity,
            &raw mut returned,
        )
    };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(buffer) }
}

fn token_facts(token: &OwnedHandle) -> io::Result<TokenFacts> {
    let user_buffer = token_information(token, TokenUser)?;
    // SAFETY: a successful TokenUser query fills a TOKEN_USER whose SID pointer points into the
    // same buffer, which is alive and suitably aligned.
    let user = unsafe { Sid::copy_from((*user_buffer.0.as_ptr().cast::<TOKEN_USER>()).User.Sid)? };

    let label_buffer = token_information(token, TokenIntegrityLevel)?;
    // SAFETY: a successful TokenIntegrityLevel query fills a TOKEN_MANDATORY_LABEL whose SID
    // points into the buffer; the SID is validated before its last sub-authority is read.
    let integrity_rid = unsafe {
        let label = (*label_buffer.0.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        if label.is_null() || IsValidSid(label) == 0 {
            return Err(io::Error::other("token has no integrity label"));
        }
        let count = *GetSidSubAuthorityCount(label);
        if count == 0 {
            return Err(io::Error::other("integrity label has no RID"));
        }
        *GetSidSubAuthority(label, u32::from(count) - 1)
    };

    let container_buffer = token_information(token, TokenIsAppContainer)?;
    let mut flag = [0_u8; 4];
    flag.copy_from_slice(container_buffer.0.get(..4).unwrap_or(&[0; 4]));
    Ok(TokenFacts { user, integrity_rid, app_container: u32::from_ne_bytes(flag) != 0 })
}

/// Facts about this process's own token.
///
/// # Errors
/// Returns the OS error when the process token cannot be opened or queried.
pub(crate) fn process_facts() -> io::Result<TokenFacts> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of the current process is always valid; `token` receives an
    // owned handle on success.
    let token = unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(token)
    };
    token_facts(&token)
}

/// Facts about the token of the client connected to `pipe`.
///
/// The calling thread impersonates the client only inside this function. It does not yield, and
/// it reverts before returning. A failed revert ends the process, because the thread would keep
/// running as the client.
///
/// # Errors
/// Returns the OS error when the client cannot be impersonated or its token cannot be read.
pub(super) fn client_facts(pipe: &NamedPipeServer) -> io::Result<TokenFacts> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `pipe` is the open server end of a connected instance. The thread token is opened
    // with the process identity (`openasself`), because an identification-level token cannot
    // open objects itself.
    let opened = unsafe {
        if ImpersonateNamedPipeClient(pipe.as_raw_handle()) == 0 {
            return Err(io::Error::last_os_error());
        }
        let opened = if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedHandle::from_raw_handle(token))
        };
        if RevertToSelf() == 0 {
            std::process::abort();
        }
        opened
    };
    token_facts(&opened?)
}

/// Self-relative security descriptor allocated by the system.
pub(crate) struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is an immutable heap block owned by this value and freed once in `Drop`.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: shared references only read the immutable block.
unsafe impl Sync for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `raw` came from ConvertStringSecurityDescriptorToSecurityDescriptorW, whose
        // result is released with LocalFree, and is freed only here.
        unsafe {
            LocalFree(self.raw);
        }
    }
}

impl SecurityDescriptor {
    /// # Errors
    /// Returns the OS error when the SDDL string is rejected.
    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = wide(OsStr::new(sddl));
        let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `raw` receives an allocation
        // owned by the returned value.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { raw })
    }

    fn attributes(&self) -> io::Result<SECURITY_ATTRIBUTES> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
            lpSecurityDescriptor: self.raw,
            bInheritHandle: 0,
        })
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Run `body` while this process can assign its user SID as an object owner.
///
/// An elevated token's default owner is the Administrators group. A descriptor that names the
/// user SID then fails with `ERROR_INVALID_OWNER` (1307) unless `SeRestorePrivilege` is enabled.
/// A token that does not hold the privilege is left unchanged and still runs `body`. The
/// privilege is process-wide, so callers must not re-enter this function.
///
/// # Errors
/// Returns the OS error when the process token cannot be opened or the privilege cannot be
/// adjusted. A token that simply lacks `SeRestorePrivilege` still runs `body`.
pub(crate) fn assigning_owner<T>(body: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    static LOCK: Mutex<()> = Mutex::new(());
    let lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let privilege = RestorePrivilege::enable()?;
    let result = body();
    // Restore while the lock is still held so another thread cannot create in between.
    drop(privilege);
    drop(lock);
    result
}

/// `SeRestorePrivilege` enabled for the current process, restored when dropped.
struct RestorePrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}

impl RestorePrivilege {
    fn enable() -> io::Result<Option<Self>> {
        let mut raw: HANDLE = std::ptr::null_mut();
        // SAFETY: the process pseudo-handle is always valid. On success `raw` is a live process
        // token opened for privilege adjustment, which this function owns.
        note_call("OpenProcessToken");
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &raw mut raw,
            )
        };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `OpenProcessToken` succeeded, so `raw` is an open handle this function owns.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut luid = LUID::default();
        // SAFETY: a null system name looks the privilege up on this machine. `SE_RESTORE_NAME`
        // is a static NUL-terminated name, and `luid` is a writable out-parameter.
        let looked_up = unsafe {
            LookupPrivilegeValueW(std::ptr::null::<u16>(), SE_RESTORE_NAME, &raw mut luid)
        };
        if looked_up == 0 {
            return Err(io::Error::last_os_error());
        }
        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned = 0_u32;
        let length = u32::try_from(size_of::<TOKEN_PRIVILEGES>()).map_err(io::Error::other)?;
        // SAFETY: `token` was opened with `TOKEN_ADJUST_PRIVILEGES`. `requested` names one
        // privilege. `previous` has room for that privilege's prior state, and `returned`
        // receives how many bytes were required. `Drop` writes `previous` back.
        // `SetLastError` distinguishes "not held" from a real adjustment failure.
        note_call("AdjustTokenPrivileges");
        let adjusted = unsafe {
            SetLastError(0);
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &raw const requested,
                length,
                &raw mut previous,
                &raw mut returned,
            )
        };
        if adjusted == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: reads the status `AdjustTokenPrivileges` just stored. No pointers.
        let last_error = unsafe { GetLastError() };
        if last_error == ERROR_NOT_ALL_ASSIGNED {
            // The privilege is absent, so nothing was changed. An unelevated token can already
            // assign its user SID; an elevated token without the privilege still fails at create.
            return Ok(None);
        }
        if returned > length {
            return Err(io::Error::other("privilege state did not fit the previous-state buffer"));
        }
        Ok(Some(Self { token, previous }))
    }
}

impl Drop for RestorePrivilege {
    fn drop(&mut self) {
        // SAFETY: `token` is the process token opened with `TOKEN_ADJUST_PRIVILEGES`. `previous`
        // is the prior state of `SeRestorePrivilege`. The output pointers are null, so the
        // length is ignored. A failed restore cannot be reported from `Drop`; the privilege
        // then stays as this guard left it until process exit.
        unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &raw const self.previous,
                0,
                std::ptr::null_mut::<TOKEN_PRIVILEGES>(),
                std::ptr::null_mut::<u32>(),
            );
        }
    }
}

/// One listening pipe instance. It is not registered with the runtime until
/// [`ListeningPipe::into_server`], which happens only after `ConnectNamedPipe` has finished.
/// Registering earlier loses the completion: the runtime treats a second connect attempt as
/// not-ready and clears the wakeup.
pub(super) struct ListeningPipe {
    handle: OwnedHandle,
}

impl ListeningPipe {
    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    /// Wrap the connected instance as a runtime pipe.
    ///
    /// # Errors
    /// Returns an error when this is called outside a runtime that polls I/O.
    pub(super) fn into_server(self) -> io::Result<NamedPipeServer> {
        let raw = self.handle.into_raw_handle();
        // SAFETY: `raw` is an overlapped pipe handle this value owns, and no I/O is in flight.
        // `from_raw_handle` takes ownership and closes the handle on failure.
        unsafe { NamedPipeServer::from_raw_handle(raw) }
    }
}

/// Make `owner` the owner of `handle`. An elevated token's default owner is Administrators, and
/// a descriptor's `O:` entry is not always stored; this call is what the owner check reads back.
///
/// # Errors
/// Returns the OS error when the owner cannot be set.
pub(super) fn set_handle_owner(
    handle: RawHandle,
    kind: SE_OBJECT_TYPE,
    owner: &Sid,
) -> io::Result<()> {
    note_call("SetSecurityInfo(owner)");
    // SAFETY: `handle` is open with WRITE_OWNER (or the restore privilege stands in for it).
    // `owner` is a SID that outlives the call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            kind,
            OWNER_SECURITY_INFORMATION,
            owner.as_psid(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    if status == 0 { Ok(()) } else { Err(os_error(status)) }
}

/// Make `owner` the owner and replace the access list with `descriptor`'s list.
///
/// The list must already use specific rights (`FA`), not `GA`. A later `CreateFile` asks for
/// `SYNCHRONIZE`, which the generic bit does not grant. Both writes happen together while the
/// restore privilege is held.
///
/// # Errors
/// Returns the OS error when either write fails.
pub(super) fn assign_user(
    handle: RawHandle,
    kind: SE_OBJECT_TYPE,
    owner: &Sid,
    descriptor: &SecurityDescriptor,
) -> io::Result<()> {
    set_handle_owner(handle, kind, owner)?;
    set_handle_dacl(handle, kind, descriptor)
}

/// Replace the protected access list. The handle must be open with `WRITE_DAC`, or the restore
/// privilege must stand in for it.
///
/// # Errors
/// Returns the OS error when the descriptor has no list or the list cannot be written.
pub(super) fn set_handle_dacl(
    handle: RawHandle,
    kind: SE_OBJECT_TYPE,
    descriptor: &SecurityDescriptor,
) -> io::Result<()> {
    let list = dacl_of(descriptor)?;
    note_call("SetSecurityInfo(dacl)");
    // SAFETY: `handle` is open with WRITE_DAC or the restore privilege is enabled. `list`
    // points into `descriptor`, which the caller keeps alive through this call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            kind,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            list,
            std::ptr::null(),
        )
    };
    if status == 0 { Ok(()) } else { Err(os_error(status)) }
}

fn dacl_of(descriptor: &SecurityDescriptor) -> io::Result<*mut ACL> {
    let mut present = 0;
    let mut defaulted = 0;
    let mut list: *mut ACL = std::ptr::null_mut();
    // SAFETY: `descriptor.raw` is a system security descriptor owned by `descriptor`. The
    // returned list pointer addresses that block and is used only while `descriptor` is alive.
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

/// Wait until a client connects to `pipe`, or until the wait is cancelled.
///
/// `ERROR_PIPE_CONNECTED` and `ERROR_NO_DATA` are a finished connect: the client is already
/// there, or it opened the pipe and left. The caller still receives that instance.
///
/// # Errors
/// Returns the OS error when `ConnectNamedPipe` fails for another reason, or when the wait is
/// cancelled.
pub(super) async fn connect_server(pipe: &ListeningPipe) -> io::Result<()> {
    let event = manual_event()?;
    let mut overlapped = OVERLAPPED::default();
    // The low bit asks the kernel to signal this event even when the pipe handle is attached
    // to a completion port. The wait below uses the event handle with that bit clear.
    let event_bits = event.as_raw_handle() as usize;
    overlapped.hEvent = (event_bits | 1) as HANDLE;
    let operation = Arc::new(ConnectOperation { event, overlapped: UnsafeCell::new(overlapped) });
    // The kernel writes this overlapped until the wait below drops `operation`. No Rust
    // reference reads those fields. `UnsafeCell::get` is the pointer `ConnectNamedPipe` stores.
    let overlapped_ptr = operation.overlapped.get();
    // SAFETY: `pipe` is the listening instance and `overlapped_ptr` points into `operation`,
    // which stays alive through this call. A pending operation keeps it alive in `ConnectWait`.
    let code = unsafe { issued_connect(pipe.raw(), overlapped_ptr) };
    if code != ERROR_IO_PENDING {
        return finished_connect(code);
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // `HANDLE` is a raw pointer, so the wait thread receives it as an address.
    let pipe_handle = pipe.raw() as usize;
    let waited = Arc::clone(&operation);
    let thread = std::thread::spawn(move || {
        let _ = sender.send(wait_for_connect(pipe_handle as HANDLE, &waited));
    });
    let mut wait =
        ConnectWait { pipe: pipe_handle, operation, thread: Some(thread), finished: false };
    let result = receiver
        .await
        .unwrap_or_else(|_| Err(io::Error::other("pipe connect wait ended before a result")));
    wait.finished = true;
    result
}

/// The overlapped and its event. Both stay allocated until the wait thread and the cancelling
/// task have finished with them.
struct ConnectOperation {
    event: OwnedHandle,
    overlapped: UnsafeCell<OVERLAPPED>,
}

// SAFETY: `OVERLAPPED` stores a copy of the event pointer, not an owned allocation. `event`
// owns that handle and is `Send`. Moving this value does not free or duplicate the event.
unsafe impl Send for ConnectOperation {}

// SAFETY: the wait thread and the task that drops `ConnectWait` share this value through `Arc`.
// The kernel is the only writer of the overlapped record. Both sides hold the `Arc` until
// `GetOverlappedResult` returns. `UnsafeCell` is why `Sync` is not automatic.
unsafe impl Sync for ConnectOperation {}

struct ConnectWait {
    pipe: usize,
    operation: Arc<ConnectOperation>,
    thread: Option<std::thread::JoinHandle<()>>,
    finished: bool,
}

impl Drop for ConnectWait {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: `overlapped` points into `operation`, which this value still holds. The
            // pipe address is the listening instance, which the caller keeps open until after
            // this join. Cancel completes the pending call and signals the manual-reset event,
            // including when the wait thread has not entered `WaitForSingleObject` yet.
            unsafe {
                CancelIoEx(self.pipe as HANDLE, self.operation.overlapped.get());
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn manual_event() -> io::Result<OwnedHandle> {
    // SAFETY: a null name creates an unnamed event. On success the handle is owned here.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `CreateEventW` returned a live handle. This owner closes it.
        Ok(unsafe { OwnedHandle::from_raw_handle(event) })
    }
}

/// SAFETY: `pipe` is a named-pipe server handle and `overlapped` stays valid through the call.
unsafe fn issued_connect(pipe: HANDLE, overlapped: *mut OVERLAPPED) -> u32 {
    // SAFETY: the caller guarantees the pointer and the handle. `SetLastError` makes a
    // synchronous success distinguishable from a stale code.
    unsafe {
        SetLastError(0);
        if ConnectNamedPipe(pipe, overlapped) != 0 { 0 } else { GetLastError() }
    }
}

fn finished_connect(code: u32) -> io::Result<()> {
    match code {
        0 | ERROR_PIPE_CONNECTED | ERROR_NO_DATA => Ok(()),
        other => Err(os_error(other)),
    }
}

fn wait_for_connect(pipe: HANDLE, operation: &ConnectOperation) -> io::Result<()> {
    let overlapped = operation.overlapped.get();
    // SAFETY: `event` is the manual-reset event stored in `overlapped`. It stays open while
    // this thread and `ConnectWait` both hold the operation. The kernel signals it when the
    // connect finishes or is cancelled, and a manual-reset event stays signaled if that
    // happened before this wait.
    unsafe {
        WaitForSingleObject(operation.event.as_raw_handle(), INFINITE);
    }
    // SAFETY: `overlapped` is the operation started on `pipe`. `bWait` is false because the
    // event has already been signaled.
    let mut transferred = 0_u32;
    let ok = unsafe { GetOverlappedResult(pipe, overlapped, &raw mut transferred, 0) };
    if ok != 0 {
        Ok(())
    } else {
        // SAFETY: `GetOverlappedResult` just failed, and no call since then replaced the error.
        finished_connect(unsafe { GetLastError() })
    }
}

fn os_error(code: u32) -> io::Error {
    match i32::try_from(code) {
        Ok(code) => io::Error::from_raw_os_error(code),
        Err(error) => io::Error::other(error),
    }
}

/// Create one byte-mode, duplex, local-only pipe instance with an explicit security descriptor.
/// `first` requests `FILE_FLAG_FIRST_PIPE_INSTANCE`. The returned instance is listening and is
/// not yet registered with the runtime.
///
/// # Errors
/// Returns the OS error; `ERROR_ACCESS_DENIED` when `first` is set and the name already exists.
pub(super) fn create_instance(
    name: &OsStr,
    descriptor: &SecurityDescriptor,
    owner: &Sid,
    first: bool,
) -> io::Result<ListeningPipe> {
    let wide = wide(name);
    let attributes = descriptor.attributes()?;
    // `WRITE_OWNER` is the same bit as `FILE_FLAG_FIRST_PIPE_INSTANCE`. Requesting it on every
    // instance would make the second instance look like a first instance and fail once the name
    // exists. `WRITE_DAC` is a different bit and is what the access-list write below needs.
    // The owner is set with the restore privilege, which does not need `WRITE_OWNER` on the handle.
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | WRITE_DAC;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `wide` is NUL-terminated. `attributes` and its descriptor outlive the call. The
    // returned handle is owned by `ListeningPipe`, which closes it.
    assigning_owner(|| unsafe {
        note_call("CreateNamedPipeW");
        let handle = CreateNamedPipeW(
            wide.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            65_536,
            65_536,
            0,
            &raw const attributes,
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedHandle::from_raw_handle(handle);
        assign_user(owned.as_raw_handle(), SE_KERNEL_OBJECT, owner, descriptor)?;
        Ok(ListeningPipe { handle: owned })
    })
}

/// Open the client end. The server may identify this process but not act as it:
/// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (the runtime adds `SECURITY_SQOS_PRESENT`).
///
/// # Errors
/// Returns the OS error when the pipe cannot be opened.
pub(super) fn open_client(name: &OsStr) -> io::Result<NamedPipeClient> {
    let mut options = ClientOptions::new();
    options.security_qos_flags(SECURITY_IDENTIFICATION).pipe_mode(PipeMode::Byte);
    options.open(name)
}

fn owner_of(handle: RawHandle, kind: SE_OBJECT_TYPE) -> io::Result<Sid> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is open with READ_CONTROL. On success `owner` points into `descriptor`,
    // which is copied from and then released with LocalFree.
    unsafe {
        let status = GetSecurityInfo(
            handle,
            kind,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(status).map_err(io::Error::other)?,
            ));
        }
        let copied = Sid::copy_from(owner);
        LocalFree(descriptor);
        copied
    }
}

/// Owner SID of the pipe object behind an open client end.
///
/// # Errors
/// Returns the OS error when the owner cannot be read.
pub(super) fn pipe_owner(pipe: &NamedPipeClient) -> io::Result<Sid> {
    owner_of(pipe.as_raw_handle(), SE_KERNEL_OBJECT)
}

/// Owner SID of an open file.
///
/// # Errors
/// Returns the OS error when the owner cannot be read.
pub(super) fn file_owner(file: &File) -> io::Result<Sid> {
    owner_of(file.as_raw_handle(), SE_FILE_OBJECT)
}

/// User SID of the process that created the server end of `pipe`.
///
/// # Errors
/// Returns the OS error when the server process or its token cannot be opened.
pub(super) fn server_process_user(pipe: &NamedPipeClient) -> io::Result<Sid> {
    let mut pid = 0_u32;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `pipe` is an open pipe handle; each returned handle is owned and closed on drop.
    let token = unsafe {
        if GetNamedPipeServerProcessId(pipe.as_raw_handle(), &raw mut pid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedHandle::from_raw_handle(process);
        if OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &raw mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(token)
    };
    Ok(token_facts(&token)?.user)
}

/// Create a new file for writing with an explicit security descriptor. Fails if the path exists.
///
/// # Errors
/// Returns the OS error; `AlreadyExists` when the path exists.
pub(super) fn create_new_file(path: &Path, descriptor: &SecurityDescriptor) -> io::Result<File> {
    let wide = wide(path.as_os_str());
    let attributes = descriptor.attributes()?;
    let owner = process_facts()?.user;
    // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor outlive the call; the
    // returned handle is owned by the `File`.
    assigning_owner(|| unsafe {
        note_call("CreateFileW(create_new_file)");
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedHandle::from_raw_handle(handle);
        if let Err(error) = assign_user(owned.as_raw_handle(), SE_FILE_OBJECT, &owner, descriptor) {
            drop(owned);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(File::from_raw_handle(owned.into_raw_handle()))
    })
}

pub(crate) mod files;

#[cfg(test)]
pub(crate) mod diag;

#[cfg(test)]
pub(crate) mod test_tokens;
