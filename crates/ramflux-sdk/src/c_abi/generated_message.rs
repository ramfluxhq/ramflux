// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate C ABI codecs for generated `MessageRequest` / `MessageUpdate`.
//! These functions do not submit, persist, or open a gateway session.

use super::{
    CAbiError, RamfluxBuffer, RamfluxErrorCode, clear_out_ptr, parse_json_input, write_json_buffer,
};
use crate::SdkError;
use crate::bindings::{self, AdapterError, GeneratedErrorCode};
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
    generated_ffi_result(out_error_json, || {
        clear_out_ptr(out_request_json).map_err(map_cabi_error)?;
        let value: Value =
            parse_json_input(request_json, request_json_len).map_err(map_cabi_error)?;
        let request =
            bindings::decode_message_request(&value).map_err(|error| map_adapter_error(&error))?;
        let encoded = bindings::encode_message_request(&request)
            .map_err(|error| map_adapter_error(&error))?;
        write_json_buffer(out_request_json, &encoded).map_err(map_cabi_error)
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
    generated_ffi_result(out_error_json, || {
        clear_out_ptr(out_update_json).map_err(map_cabi_error)?;
        let value: Value =
            parse_json_input(update_json, update_json_len).map_err(map_cabi_error)?;
        let update =
            bindings::decode_message_update(&value).map_err(|error| map_adapter_error(&error))?;
        let encoded =
            bindings::encode_message_update(&update).map_err(|error| map_adapter_error(&error))?;
        write_json_buffer(out_update_json, &encoded).map_err(map_cabi_error)
    })
}

fn map_adapter_error(error: &SdkError) -> AdapterError {
    AdapterError::from_sdk(error)
}

fn map_cabi_error(error: CAbiError) -> AdapterError {
    let code = match error.code {
        RamfluxErrorCode::InvalidCanonicalJson => GeneratedErrorCode::InvalidJson,
        RamfluxErrorCode::InvalidArgument => GeneratedErrorCode::InvalidArgument,
        _ => GeneratedErrorCode::Internal,
    };
    AdapterError::new(code, error.message)
}

// Generated entrypoints use the generated error namespace, without renumbering legacy APIs.
// Failures return AdapterError directly; release builds abort on a panic.
fn generated_ffi_result(
    out_error_json: *mut *mut RamfluxBuffer,
    function: impl FnOnce() -> Result<(), AdapterError>,
) -> i32 {
    super::clear_optional_out_error(out_error_json);
    let error = match function() {
        Ok(()) => return 0,
        Err(error) => error,
    };
    if !out_error_json.is_null() {
        let _ignored = write_json_buffer(out_error_json, &error);
    }
    error.code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_c_abi_returns_shared_error_codes_and_details()
    -> Result<(), Box<dyn std::error::Error>> {
        use GeneratedErrorCode as C;
        let codes = [
            C::InvalidArgument,
            C::InvalidJson,
            C::PeerUpgradeRequired,
            C::StorageCapacity,
            C::SchemaResetRequired,
            C::ResyncRequired,
            C::EditConflict,
            C::NotAuthorized,
            C::TargetNotFound,
            C::TargetDeleted,
            C::PayloadTooLarge,
            C::RateLimited,
            C::EphemeralUnavailable,
            C::CryptoFailure,
            C::NotConnected,
            C::Internal,
        ];
        for (index, code) in codes.into_iter().enumerate() {
            let mut error_json = std::ptr::null_mut();
            let expected = bindings::test_error_vector(code);
            let actual = generated_ffi_result(&raw mut error_json, || {
                Err(map_adapter_error(&SdkError::from(expected.clone())))
            });
            assert_eq!(actual, i32::try_from(index + 1)?);
            assert!(!error_json.is_null());
            // SAFETY: this non-null output buffer is allocated by the ABI and owned by this test
            // until ramflux_buffer_free below; its length describes that allocation.
            let bytes = unsafe { std::slice::from_raw_parts((*error_json).ptr, (*error_json).len) };
            let decoded = serde_json::from_slice::<Value>(bytes);
            super::super::ramflux_buffer_free(error_json);
            assert_eq!(decoded?, serde_json::to_value(expected)?);
        }
        let mut error_json = std::ptr::null_mut();
        let mut request_json = std::ptr::null_mut();
        let invalid = b"{";
        assert_eq!(
            ramflux_message_request_adapt(
                invalid.as_ptr(),
                invalid.len(),
                &raw mut request_json,
                &raw mut error_json
            ),
            2
        );
        assert!(request_json.is_null());
        assert!(!error_json.is_null());
        // SAFETY: this checked non-null buffer is owned by the test until it is freed below.
        let bytes = unsafe { std::slice::from_raw_parts((*error_json).ptr, (*error_json).len) };
        let decoded = serde_json::from_slice::<Value>(bytes);
        super::super::ramflux_buffer_free(error_json);
        assert_eq!(decoded?["name"], "invalid_json");
        Ok(())
    }
}
