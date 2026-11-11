// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate C ABI codecs for generated `MessageRequest` / `MessageUpdate`.
//! These functions do not submit, persist, or open a gateway session.

use super::{
    CAbiError, RamfluxBuffer, RamfluxErrorCode, clear_out_ptr, ffi_result, parse_json_input,
    write_json_buffer,
};
use crate::SdkError;
use crate::bindings::{self, AdapterError};
use serde_json::Value;
use std::os::raw::c_uchar;

/// Decode and re-encode a generated message request through the shared adapter core.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_message_request_adapt(
    request_json: *const c_uchar,
    request_json_len: usize,
    out_request_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_request_json)?;
        let value: Value = parse_json_input(request_json, request_json_len)?;
        let request =
            bindings::decode_message_request(&value).map_err(|error| map_adapter_error(&error))?;
        let encoded = bindings::encode_message_request(&request)
            .map_err(|error| map_adapter_error(&error))?;
        write_json_buffer(out_request_json, &encoded)
    })
}

/// Decode and re-encode a generated message update through the shared adapter core.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_message_update_adapt(
    update_json: *const c_uchar,
    update_json_len: usize,
    out_update_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(out_error_json, || {
        clear_out_ptr(out_update_json)?;
        let value: Value = parse_json_input(update_json, update_json_len)?;
        let update =
            bindings::decode_message_update(&value).map_err(|error| map_adapter_error(&error))?;
        let encoded =
            bindings::encode_message_update(&update).map_err(|error| map_adapter_error(&error))?;
        write_json_buffer(out_update_json, &encoded)
    })
}

fn map_adapter_error(error: &SdkError) -> CAbiError {
    let mapped = AdapterError::from_sdk(error);
    let code = if mapped.code == AdapterError::INVALID_JSON {
        RamfluxErrorCode::InvalidCanonicalJson
    } else {
        RamfluxErrorCode::InvalidArgument
    };
    CAbiError::new(code, mapped.message)
}
