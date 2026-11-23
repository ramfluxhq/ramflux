// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Allocate final output storage before copying secrets; erase every temporary copy.
use super::super::{CAbiError, RamfluxBuffer, RamfluxErrorCode};

pub(super) fn write_json_buffer<T: serde::Serialize>(
    out: *mut *mut RamfluxBuffer,
    value: &T,
) -> Result<(), CAbiError> {
    let bytes = ramflux_protocol::canonical_json_bytes(value)
        .map_err(|_| CAbiError::new(RamfluxErrorCode::Internal, "encoding"))?;
    write_buffer(out, bytes)
}

pub(super) fn write_buffer(out: *mut *mut RamfluxBuffer, bytes: Vec<u8>) -> Result<(), CAbiError> {
    let bytes = zeroize::Zeroizing::new(bytes);
    if out.is_null() {
        return Err(CAbiError::new(RamfluxErrorCode::InvalidArgument, "output"));
    }
    // Any shrink/reallocation happens while this destination still contains only zeroes.
    let mut exact = vec![0; bytes.len()].into_boxed_slice();
    exact.copy_from_slice(&bytes);
    let len = exact.len();
    let ptr = exact.as_mut_ptr();
    let buffer = Box::new(RamfluxBuffer { ptr, len });
    std::mem::forget(exact);
    // SAFETY: the host provides aligned writable output storage for the duration of this call.
    unsafe {
        out.write(Box::into_raw(buffer));
    }
    Ok(())
}

pub(super) fn discard_output(out: *mut *mut RamfluxBuffer) {
    if out.is_null() {
        return;
    }
    // SAFETY: the caller owns this output slot for the duration of the call.
    let buffer = unsafe { out.replace(std::ptr::null_mut()) };
    if buffer.is_null() {
        return;
    }
    // SAFETY: the pointer was produced by write_buffer and has not been freed.
    let buffer = unsafe { Box::from_raw(buffer) };
    if buffer.ptr.is_null() {
        return;
    }
    let raw = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
    // SAFETY: write_buffer allocated this exact boxed slice and stored its length.
    let mut bytes = unsafe { Box::from_raw(raw) };
    zeroize::Zeroize::zeroize(bytes.as_mut());
}
