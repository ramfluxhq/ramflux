// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Console mode for the account ceremony.
//!
//! `CONIN$` is the input buffer and `CONOUT$` is where prompts are written. Line input stays
//! on: echo without it is `ERROR_INVALID_PARAMETER`. A hidden prompt is line input with echo
//! off, which is the console password mode.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;

unsafe extern "system" {
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

fn apply(input: &File, mode: u32) -> io::Result<()> {
    // SAFETY: `input` is an open console input handle. `mode` is a cooked input mode:
    // processed and line input, with echo only when the caller asked for it.
    let ok = unsafe { SetConsoleMode(input.as_raw_handle(), mode) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        Err(io::Error::new(error.kind(), format!("SetConsoleMode {mode:#x}: {error}")))
    } else {
        Ok(())
    }
}

/// Select cooked input and leave echo on.
///
/// Echo without line input is rejected. The ceremony hides a secret by turning echo off
/// while line input stays on.
///
/// # Errors
/// Returns the OS error when the console mode cannot be set.
pub(crate) fn prepare_input(input: &File) -> io::Result<()> {
    apply(input, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
}

/// Show or hide typed characters. Line input stays on so echo remains valid.
///
/// # Errors
/// Returns the OS error when the console mode cannot be set.
pub(crate) fn set_echo(input: &File, enabled: bool) -> io::Result<()> {
    let echo = if enabled { ENABLE_ECHO_INPUT } else { 0 };
    apply(input, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | echo)
}
