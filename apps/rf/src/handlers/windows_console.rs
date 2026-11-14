// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Console mode for the account ceremony.
//!
//! `CONIN$` is the input buffer and `CONOUT$` is where prompts are written. Line input stays
//! on: echo without it is `ERROR_INVALID_PARAMETER`. A hidden prompt is line input with echo
//! off, which is the console password mode.
//!
//! Recovery words are hidden with virtual-terminal sequences. Those sequences are literal text
//! unless the output buffer has `ENABLE_VIRTUAL_TERMINAL_PROCESSING`. That flag is an output
//! mode; it is the same bit as echo on the input buffer and must not be set on input. When the
//! console rejects the flag, the ceremony erases the whole screen buffer, including scrollback,
//! through the console API.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;
/// Output-mode flag. Not valid on an input handle.
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
const SPACE: u16 = 0x0020;

unsafe extern "system" {
    fn GetConsoleMode(handle: *mut core::ffi::c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(handle: *mut core::ffi::c_void, mode: u32) -> i32;
    fn GetConsoleScreenBufferInfo(
        handle: *mut core::ffi::c_void,
        info: *mut ConsoleScreenBufferInfo,
    ) -> i32;
    fn FillConsoleOutputCharacterW(
        handle: *mut core::ffi::c_void,
        character: u16,
        length: u32,
        origin: Coord,
        written: *mut u32,
    ) -> i32;
    fn FillConsoleOutputAttribute(
        handle: *mut core::ffi::c_void,
        attribute: u16,
        length: u32,
        origin: Coord,
        written: *mut u32,
    ) -> i32;
    fn SetConsoleCursorPosition(handle: *mut core::ffi::c_void, origin: Coord) -> i32;
    fn SetConsoleWindowInfo(
        handle: *mut core::ffi::c_void,
        absolute: i32,
        window: *const SmallRect,
    ) -> i32;
    fn SetConsoleScreenBufferSize(handle: *mut core::ffi::c_void, size: Coord) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SmallRect {
    left: i16,
    top: i16,
    right: i16,
    bottom: i16,
}

#[repr(C)]
struct ConsoleScreenBufferInfo {
    size: Coord,
    cursor: Coord,
    attributes: u16,
    window: SmallRect,
    maximum_window: Coord,
}

pub(crate) fn open_input() -> io::Result<File> {
    // `SetConsoleMode` needs write access. A read-only `CONIN$` handle still reports
    // that it is a console, then refuses the mode change.
    File::options().read(true).write(true).open(r"\\.\CONIN$")
}

pub(crate) fn open_output() -> io::Result<File> {
    // Screen-buffer queries need read access. Write-only `CONOUT$` can fail them.
    File::options().read(true).write(true).open(r"\\.\CONOUT$")
}

fn apply(console: &File, mode: u32) -> io::Result<()> {
    // SAFETY: `console` is an open console handle. `mode` is a mode word for that handle.
    let ok = unsafe { SetConsoleMode(console.as_raw_handle(), mode) };
    if ok == 0 {
        let error = io::Error::last_os_error();
        Err(io::Error::new(error.kind(), format!("SetConsoleMode {mode:#x}: {error}")))
    } else {
        Ok(())
    }
}

/// Read the current console mode.
///
/// # Errors
/// Returns the OS error when the handle is not a console or the mode cannot be read.
pub(crate) fn console_mode(console: &File) -> io::Result<u32> {
    let mut mode = 0_u32;
    // SAFETY: `console` is an open console handle and `mode` is a writable `u32`.
    let ok = unsafe { GetConsoleMode(console.as_raw_handle(), &raw mut mode) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(mode) }
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

/// Turn on virtual-terminal processing without dropping the other output bits.
///
/// # Errors
/// Returns the OS error when the console rejects the mode. The caller then erases the
/// screen buffer instead of writing escape sequences that would stay on screen.
pub(crate) fn enable_virtual_terminal(output: &File, mode: u32) -> io::Result<()> {
    apply(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

/// Put both handles back to the modes captured before the ceremony changed them.
///
/// # Errors
/// Returns the first OS error. The other handle is still restored when it can be.
pub(crate) fn restore_modes(
    input: &File,
    input_mode: u32,
    output: &File,
    output_mode: u32,
) -> io::Result<()> {
    let input_result = apply(input, input_mode);
    let output_result = apply(output, output_mode);
    match (input_result, output_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(input_error), Err(output_error)) => Err(io::Error::new(
            input_error.kind(),
            format!("input {input_error}; output {output_error}"),
        )),
    }
}

/// Report whether this output handle can erase its screen buffer.
///
/// # Errors
/// Returns the OS error when the handle is not a console screen buffer.
pub(crate) fn screen_buffer_usable(output: &File) -> io::Result<()> {
    let info = buffer_info(output)?;
    cell_count(info.size).map(|_| ())
}

/// Erase every cell in the screen buffer, then drop the scrollback rows.
///
/// Filling only the visible window would leave the words above it. The fill covers
/// `dwSize`, the window moves home, and the buffer is shrunk to the window and grown
/// back so the old rows no longer exist.
///
/// # Errors
/// Returns the OS error when any step fails. A failed erase must not be treated as hidden.
pub(crate) fn clear_screen_and_scrollback(output: &File) -> io::Result<()> {
    let info = buffer_info(output)?;
    let cells = cell_count(info.size)?;
    let handle = output.as_raw_handle();
    let origin = Coord { x: 0, y: 0 };
    fill_cells(handle, SPACE, info.attributes, cells, origin)?;
    set_cursor(handle, origin)?;
    let home = origin_window(&info)?;
    set_window(handle, &home)?;
    let visible = Coord { x: home.right.saturating_add(1), y: home.bottom.saturating_add(1) };
    set_buffer_size(handle, visible)?;
    set_buffer_size(handle, info.size)?;
    set_window(handle, &home)?;
    set_cursor(handle, origin)?;
    Ok(())
}

fn buffer_info(output: &File) -> io::Result<ConsoleScreenBufferInfo> {
    let mut info = ConsoleScreenBufferInfo {
        size: Coord { x: 0, y: 0 },
        cursor: Coord { x: 0, y: 0 },
        attributes: 0,
        window: SmallRect { left: 0, top: 0, right: 0, bottom: 0 },
        maximum_window: Coord { x: 0, y: 0 },
    };
    // SAFETY: `output` is an open console screen buffer and `info` is writable.
    let ok = unsafe { GetConsoleScreenBufferInfo(output.as_raw_handle(), &raw mut info) };
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(info) }
}

fn fill_cells(
    handle: *mut core::ffi::c_void,
    character: u16,
    attribute: u16,
    cells: u32,
    origin: Coord,
) -> io::Result<()> {
    let mut written = 0_u32;
    // SAFETY: `handle` is the open screen buffer from `buffer_info`. `written` is writable.
    let ok =
        unsafe { FillConsoleOutputCharacterW(handle, character, cells, origin, &raw mut written) };
    if ok == 0 {
        return Err(labeled("FillConsoleOutputCharacterW"));
    }
    if written != cells {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "console clear did not cover the screen buffer",
        ));
    }
    written = 0;
    // SAFETY: same screen buffer. `written` is writable and the fill length matches the buffer.
    let ok =
        unsafe { FillConsoleOutputAttribute(handle, attribute, cells, origin, &raw mut written) };
    if ok == 0 {
        return Err(labeled("FillConsoleOutputAttribute"));
    }
    if written != cells {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "console clear did not cover the screen attributes",
        ));
    }
    Ok(())
}

fn set_cursor(handle: *mut core::ffi::c_void, origin: Coord) -> io::Result<()> {
    // SAFETY: `handle` is the open screen buffer and `origin` is inside it after a full fill.
    let ok = unsafe { SetConsoleCursorPosition(handle, origin) };
    if ok == 0 { Err(labeled("SetConsoleCursorPosition")) } else { Ok(()) }
}

fn set_window(handle: *mut core::ffi::c_void, window: &SmallRect) -> io::Result<()> {
    // SAFETY: `handle` is the open screen buffer. `window` is a rectangle inside that buffer.
    let ok = unsafe { SetConsoleWindowInfo(handle, 1, window) };
    if ok == 0 { Err(labeled("SetConsoleWindowInfo")) } else { Ok(()) }
}

fn set_buffer_size(handle: *mut core::ffi::c_void, size: Coord) -> io::Result<()> {
    // SAFETY: `handle` is the open screen buffer. `size` is at least the current window.
    let ok = unsafe { SetConsoleScreenBufferSize(handle, size) };
    if ok == 0 { Err(labeled("SetConsoleScreenBufferSize")) } else { Ok(()) }
}

fn labeled(action: &str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn cell_count(size: Coord) -> io::Result<u32> {
    if size.x <= 0 || size.y <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "console buffer is empty"));
    }
    let cells = i32::from(size.x)
        .checked_mul(i32::from(size.y))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "console buffer is too large"))?;
    u32::try_from(cells)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "console buffer is too large"))
}

fn origin_window(info: &ConsoleScreenBufferInfo) -> io::Result<SmallRect> {
    let width = inclusive_span(info.window.left, info.window.right)?;
    let height = inclusive_span(info.window.top, info.window.bottom)?;
    Ok(SmallRect {
        left: 0,
        top: 0,
        right: width.saturating_sub(1),
        bottom: height.saturating_sub(1),
    })
}

fn inclusive_span(start: i16, end: i16) -> io::Result<i16> {
    let span = i32::from(end).saturating_sub(i32::from(start)).saturating_add(1);
    if span <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "console window is empty"));
    }
    i16::try_from(span)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "console window does not fit"))
}
