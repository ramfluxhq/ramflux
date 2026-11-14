// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Additive attended pairing ABI; outputs use the existing allocated-buffer convention.
use super::{
    CAbiError, CAbiResult, RamfluxBuffer, RamfluxClient, RamfluxErrorCode, clear_out_ptr,
    client_inner, ffi_result, input_bytes, reject_if_closing, write_buffer,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    local_dto::{LocalResult, Outcome},
};
use std::ffi::{c_char, c_void};
mod credential;
mod request;
mod state;
pub use credential::CredentialCallback;
pub(super) use state::State;
fn invalid() -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, "invalid pairing ABI argument")
}
fn method(value: *const c_char) -> CAbiResult<String> {
    if value.is_null() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    for offset in 0..128 {
        // SAFETY: the C caller supplies a readable NUL-terminated method string.
        // The bounded scan accepts at most 127 bytes and never follows body lengths.
        let byte = unsafe { value.add(offset).read() };
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| invalid());
        }
        bytes.push(u8::from_ne_bytes(byte.to_ne_bytes()));
    }
    Err(invalid())
}
/// Invoke one closed pairing/transfer DTO using the configured same-user local daemon.
/// Configure `pairing_socket` and, for a new target, `pairing_account_id` in client JSON.
/// `out` follows existing APIs: pass writable pointer storage, free the returned allocation
/// with `ramflux_buffer_free`. Inputs remain readable and the client remains live throughout.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_pairing_call(
    client: *mut RamfluxClient,
    method_name: *const c_char,
    body: *const u8,
    body_len: usize,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(std::ptr::null_mut(), || {
        clear_out_ptr(out)?;
        if body_len > LocalResult::LIMIT {
            return Err(invalid());
        }
        let inner = client_inner(client)?;
        reject_if_closing(inner)?;
        let _permit = inner.pairing.enter()?;
        let method = method(method_name)?;
        let body = request::body(&method, &input_bytes(body, body_len)?)?;
        let stale = inner.pairing.stale(&body)?;
        let result = if stale {
            request::refusal("WrongContext")?
        } else {
            let account = if let Some(id) = &inner.pairing.account {
                id.clone()
            } else {
                let client = inner.client.lock().map_err(|_| invalid())?;
                client
                    .account_index()
                    .map_err(|error| super::map_sdk_error(&error))?
                    .active_account()
                    .map_err(|error| super::map_sdk_error(&error.into()))?
                    .ok_or_else(invalid)?
            };
            inner.runtime.block_on(inner.pairing.call(account, &method, body))?
        };
        reject_if_closing(inner)?;
        let bytes = result.to_wire_bytes().map_err(|_| invalid())?;
        inner.pairing.remember(&result)?;
        write_buffer(out, bytes)?;
        if stale {
            return Err(CAbiError::new(RamfluxErrorCode::PairingStale, "stale pairing generation"));
        }
        if matches!(result.outcome, Outcome::Error { .. }) {
            return Err(CAbiError::new(RamfluxErrorCode::PairingRefused, "pairing refused"));
        }
        Ok(())
    })
}
/// Return one queued public display snapshot or an empty SDK buffer. No callback runs here.
/// The caller owns the returned buffer and frees it with `ramflux_buffer_free`.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_pairing_event_poll(
    client: *mut RamfluxClient,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    ffi_result(std::ptr::null_mut(), || {
        clear_out_ptr(out)?;
        let inner = client_inner(client)?;
        reject_if_closing(inner)?;
        write_buffer(out, inner.pairing.poll()?)
    })
}
/// Install or unregister (NULL callback) the client's attended input provider.
/// Host output capacities are 1024 bytes; SDK storage is zeroized on every path.
/// Replacement/unregister/close waits for previous callback invocations to finish.
/// The host must keep `user_data` valid until that wait returns and must not reenter
/// this client from its callback; cancel its own waiting UI before closing the client.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_pairing_set_credential_provider(
    client: *mut RamfluxClient,
    callback: Option<CredentialCallback>,
    user_data: *mut c_void,
) -> i32 {
    ffi_result(std::ptr::null_mut(), || {
        let inner = client_inner(client)?;
        reject_if_closing(inner)?;
        inner.pairing.set_provider(callback, user_data)
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn registered_state_for_test(
    config: &[u8],
    body: &[u8],
) -> Result<serde_json::Value, String> {
    tests::registered_state(config, body)
}
