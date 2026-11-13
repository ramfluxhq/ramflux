// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! ConPTY session for `rf account create` on Windows. The child sees a real console, so the
//! ceremony's terminal check passes, and the parent writes the prompts' answers.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;

use super::proc::{self, ProcessGroup};

const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

unsafe extern "system" {
    fn CreatePipe(
        read: *mut *mut core::ffi::c_void,
        write: *mut *mut core::ffi::c_void,
        attributes: *const SecurityAttributes,
        size: u32,
    ) -> i32;
    fn CreatePseudoConsole(
        size: Coord,
        input: *mut core::ffi::c_void,
        output: *mut core::ffi::c_void,
        flags: u32,
        console: *mut *mut core::ffi::c_void,
    ) -> i32;
    fn ClosePseudoConsole(console: *mut core::ffi::c_void);
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    fn InitializeProcThreadAttributeList(
        list: *mut core::ffi::c_void,
        count: u32,
        flags: u32,
        bytes: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut core::ffi::c_void,
        flags: u32,
        attribute: usize,
        value: *mut core::ffi::c_void,
        size: usize,
        previous: *mut core::ffi::c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut core::ffi::c_void);
    fn CreateProcessW(
        application: *const u16,
        command: *mut u16,
        process_attributes: *mut core::ffi::c_void,
        thread_attributes: *mut core::ffi::c_void,
        inherit: i32,
        flags: u32,
        environment: *mut core::ffi::c_void,
        directory: *const u16,
        startup: *const StartupInfoW,
        information: *mut ProcessInformation,
    ) -> i32;
}

#[repr(C)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut core::ffi::c_void,
    inherit: i32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count: u32,
    y_count: u32,
    fill: u32,
    flags: u32,
    show: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    stdin: *mut core::ffi::c_void,
    stdout: *mut core::ffi::c_void,
    stderr: *mut core::ffi::c_void,
}

#[repr(C)]
struct StartupInfoExW {
    startup: StartupInfoW,
    attribute_list: *mut core::ffi::c_void,
}

#[repr(C)]
struct ProcessInformation {
    process: *mut core::ffi::c_void,
    thread: *mut core::ffi::c_void,
    process_id: u32,
    thread_id: u32,
}

pub(super) struct PseudoConsole(*mut core::ffi::c_void);

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from `CreatePseudoConsole` and has not been closed.
            unsafe { ClosePseudoConsole(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

struct AttributeList {
    memory: *mut u8,
    layout: std::alloc::Layout,
    ready: bool,
}

impl AttributeList {
    fn new() -> io::Result<Self> {
        let mut bytes = 0_usize;
        // SAFETY: a null list with a writable size asks only for the required byte count.
        let ok =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut bytes) };
        if ok != 0 {
            return Err(io::Error::other("attribute list size query succeeded unexpectedly"));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER) {
            return Err(error);
        }
        let layout = std::alloc::Layout::from_size_align(bytes, 16)
            .map_err(|_| io::Error::other("attribute list alignment"))?;
        // SAFETY: `layout` is non-zero. The block is freed in `Drop`.
        let memory = unsafe { std::alloc::alloc(layout) };
        if memory.is_null() {
            return Err(io::Error::other("attribute list allocation failed"));
        }
        let mut list = Self { memory, layout, ready: false };
        // SAFETY: `memory` is the aligned block of `bytes` and outlives the call.
        let ok =
            unsafe { InitializeProcThreadAttributeList(list.memory.cast(), 1, 0, &raw mut bytes) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        list.ready = true;
        Ok(list)
    }

    fn set_console(&mut self, console: &PseudoConsole) -> io::Result<()> {
        // The console host reads one pointer at `lpValue` and treats it as the
        // pseudoconsole. Passing the address of the field attaches the wrong object,
        // so the child has no console and `CONOUT$` never reaches this pipe.
        // SAFETY: `self.memory` is an initialized attribute list. `console.0` is the
        // live pseudoconsole from `CreatePseudoConsole` and stays open through
        // `CreateProcessW`.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.memory.cast(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                console.0,
                std::mem::size_of::<*mut core::ffi::c_void>(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.memory.is_null() {
            return;
        }
        if self.ready {
            // SAFETY: `memory` was initialized by `InitializeProcThreadAttributeList`.
            unsafe { DeleteProcThreadAttributeList(self.memory.cast()) };
        }
        // SAFETY: `memory` was allocated with `self.layout`.
        unsafe { std::alloc::dealloc(self.memory, self.layout) };
        self.memory = ptr::null_mut();
    }
}

pub(super) struct Spawned {
    pub group: ProcessGroup,
    pub stdin: File,
    pub stdout: File,
    pub console: PseudoConsole,
}

pub(super) fn spawn(rf: &Path, socket: &Path, display_name: &str) -> io::Result<Spawned> {
    let args = [
        rf.display().to_string(),
        "--socket".to_owned(),
        socket.display().to_string(),
        "account".to_owned(),
        "create".to_owned(),
        "--display-name".to_owned(),
        display_name.to_owned(),
    ];
    let command = args.iter().map(|arg| quote_arg(arg)).collect::<Vec<_>>().join(" ");
    let application = wide(&args[0]);
    let mut command_line = wide(&command);
    let (input_read, input_write) = inheritable_pipe()?;
    let (output_read, output_write) = inheritable_pipe()?;
    let mut console_handle = ptr::null_mut();
    // SAFETY: both pipe ends are inheritable and open. `console_handle` receives the new
    // pseudoconsole. The pipe handles stay alive for the call.
    let hr = unsafe {
        CreatePseudoConsole(
            Coord { x: 80, y: 24 },
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &raw mut console_handle,
        )
    };
    if hr != 0 {
        return Err(io::Error::other(format!("CreatePseudoConsole {hr:#010x}")));
    }
    let console = PseudoConsole(console_handle);
    drop(input_read);
    drop(output_write);
    let mut attributes = AttributeList::new()?;
    attributes.set_console(&console)?;
    // SAFETY: zero is the documented initial value of STARTUPINFOEXW before `cb` and the
    // attribute list are filled in.
    let mut extended: StartupInfoExW = unsafe { std::mem::zeroed() };
    extended.startup.cb = u32::try_from(std::mem::size_of::<StartupInfoExW>())
        .map_err(|_| io::Error::other("startup info size"))?;
    extended.attribute_list = attributes.memory.cast();
    // SAFETY: zero is a valid PROCESS_INFORMATION before CreateProcessW writes it.
    let mut info: ProcessInformation = unsafe { std::mem::zeroed() };
    // SAFETY: `application` and `command_line` are NUL-terminated and mutable for the command
    // line. `extended` begins with STARTUPINFOW whose `cb` is the size of the extended struct.
    // Handles are not inherited; the pseudoconsole arrives through the attribute list.
    let ok = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw const extended.startup,
            &raw mut info,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `info.thread` is an owned thread handle. Closing it does not end the process.
    unsafe { CloseHandle(info.thread) };
    drop(attributes);
    Ok(Spawned {
        group: ProcessGroup::from_process(info.process_id, proc::owned_process(info.process)),
        stdin: input_write,
        stdout: output_read,
        console,
    })
}

fn inheritable_pipe() -> io::Result<(File, File)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let attributes = SecurityAttributes {
        length: u32::try_from(std::mem::size_of::<SecurityAttributes>())
            .map_err(|_| io::Error::other("security attributes"))?,
        descriptor: ptr::null_mut(),
        inherit: 1,
    };
    // SAFETY: `read` and `write` receive owned pipe handles. `attributes` outlives the call.
    let ok = unsafe { CreatePipe(&raw mut read, &raw mut write, &raw const attributes, 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both pointers are owned pipe handles from `CreatePipe`.
    unsafe { Ok((File::from_raw_handle(read), File::from_raw_handle(write))) }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn quote_arg(arg: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0_usize;
    for ch in arg.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                out.extend(std::iter::repeat('\\').take(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            other => {
                out.extend(std::iter::repeat('\\').take(slashes));
                out.push(other);
                slashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat('\\').take(slashes * 2));
    out.push('"');
    out
}
