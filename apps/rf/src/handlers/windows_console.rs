// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Console mode for the account ceremony.
//!
//! `CONIN$` is the input buffer and `CONOUT$` is where prompts are written. Line input is
//! turned off so a newline written by a pseudoconsole arrives immediately. Echo is toggled
//! on that same input buffer and line input stays off.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;

unsafe extern "system" {
    fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
}

pub(crate) fn open_input() -> io::Result<File> {
    // `SetConsoleMode` needs write access. A read-only `CONIN$` handle still reports
    // that it is a console, then refuses the mode change.
    File::options().read(true).write(true).open(r"\\.\CONIN$")
}

pub(crate) fn open_output() -> io::Result<File> {
    File::options().write(true).open(r"\\.\CONOUT$")
}

fn mode(input: &File) -> io::Result<u32> {
    let mut mode = 0_u32;
    // SAFETY: `input` is an open console handle and `mode` is a writable `u32`.
    let ok = unsafe { GetConsoleMode(input.as_raw_handle(), &raw mut mode) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(mode) }
}

fn apply(input: &File, mode: u32) -> io::Result<()> {
    // SAFETY: `input` is the same console handle. The mode keeps every bit except the ones
    // the caller cleared or set.
    let ok = unsafe { SetConsoleMode(input.as_raw_handle(), mode) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Clear line input. Every other mode bit, including processed input, stays as it was.
///
/// # Errors
/// Returns the OS error when the console mode cannot be read or set.
pub(crate) fn disable_line_input(input: &File) -> io::Result<()> {
    apply(input, mode(input)? & !ENABLE_LINE_INPUT)
}

/// Show or hide typed characters. Line input stays off.
///
/// # Errors
/// Returns the OS error when the console mode cannot be read or set.
pub(crate) fn set_echo(input: &File, enabled: bool) -> io::Result<()> {
    let current = mode(input)?;
    let echoed = if enabled { current | ENABLE_ECHO_INPUT } else { current & !ENABLE_ECHO_INPUT };
    apply(input, echoed & !ENABLE_LINE_INPUT)
}
