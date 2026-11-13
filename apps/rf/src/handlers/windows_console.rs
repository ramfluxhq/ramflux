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

const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;
/// Input flags `SetConsoleMode` accepts. ConPTY also reports `ENABLE_AUTO_POSITION`
/// (`0x0100`) and then rejects that bit with `ERROR_INVALID_PARAMETER`.
const INPUT_MODE_MASK: u32 = ENABLE_PROCESSED_INPUT
    | ENABLE_LINE_INPUT
    | ENABLE_ECHO_INPUT
    | 0x0008
    | 0x0010
    | 0x0020
    | 0x0040
    | 0x0080
    | 0x0200;

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

/// Set an input mode that keeps line input off.
///
/// The reported mode is masked to flags `SetConsoleMode` accepts. If that still fails,
/// processed input alone is used so each byte arrives without echo unless requested.
///
/// # Errors
/// Returns the OS error when neither mode can be set.
fn apply_input_mode(input: &File, mode: u32) -> io::Result<()> {
    let requested = mode & INPUT_MODE_MASK & !ENABLE_LINE_INPUT;
    if apply(input, requested).is_ok() {
        return Ok(());
    }
    let fallback = ENABLE_PROCESSED_INPUT | (requested & ENABLE_ECHO_INPUT);
    apply(input, fallback).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("SetConsoleMode {requested:#x} then {fallback:#x}: {error}"),
        )
    })
}

/// Clear line input. Every other accepted mode bit stays as it was.
///
/// # Errors
/// Returns the OS error when the console mode cannot be read or set.
pub(crate) fn disable_line_input(input: &File) -> io::Result<()> {
    apply_input_mode(input, mode(input)?)
}

/// Show or hide typed characters. Line input stays off.
///
/// # Errors
/// Returns the OS error when the console mode cannot be read or set.
pub(crate) fn set_echo(input: &File, enabled: bool) -> io::Result<()> {
    let current = mode(input)?;
    let echoed = if enabled { current | ENABLE_ECHO_INPUT } else { current & !ENABLE_ECHO_INPUT };
    apply_input_mode(input, echoed)
}
