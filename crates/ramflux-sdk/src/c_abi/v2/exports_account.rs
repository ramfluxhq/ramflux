// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The exported `ramflux_v2_account_creation_*` symbols.

use super::ceremony::Ceremony;
use super::driver::Job;
use super::error::{V2Error, V2Result};
use super::exports::{core, guard};
use super::types::{
    RamfluxV2AccountCreation, RamfluxV2Core, RamfluxV2CreateConfirm, RamfluxV2CreateOptions,
    bounded_bytes, optional_text, read_versioned, required_text,
};
use super::super::{
    RamfluxBuffer, RamfluxErrorCode, clear_out_ptr, write_buffer, write_json_buffer, write_out_ptr,
};
use std::os::raw::c_uchar;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Longest word or passphrase accepted, in bytes. Far above any real value; it only keeps
/// a wrong length from becoming a large allocation.
const MAX_SECRET_BYTES: usize = 4096;

fn ceremony(handle: *mut RamfluxV2AccountCreation) -> V2Result<Arc<Ceremony>> {
    if handle.is_null() {
        return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "ceremony handle is null"));
    }
    Ok(Arc::clone(unsafe { &*handle.cast::<Arc<Ceremony>>() }))
}

/// Copy a borrowed secret into a buffer that erases itself.
fn secret_text(
    pointer: *const c_uchar,
    len: usize,
    what: &'static str,
) -> V2Result<Zeroizing<String>> {
    if len == 0 || len > MAX_SECRET_BYTES {
        return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, what));
    }
    let bytes = Zeroizing::new(bounded_bytes(pointer, len, what)?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| V2Error::new(RamfluxErrorCode::InvalidArgument, what))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Begin creating an account. `out_pending_json` receives
/// `{"ceremony_id":"...","expires_in_ms":"..."}`. The ceremony is cancelled when its handle
/// is freed before a successful confirmation.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_begin(
    core_handle: *mut RamfluxV2Core,
    options: *const RamfluxV2CreateOptions,
    out_creation: *mut *mut RamfluxV2AccountCreation,
    out_pending_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_creation)?;
        clear_out_ptr(out_pending_json)?;
        let inner = core(core_handle)?;
        let options = read_versioned(options)?;
        if options.flags != 0 {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "reserved flags are set"));
        }
        let display_name =
            required_text(options.display_name, options.display_name_len, "display_name")?;
        let node_id = optional_text(options.node_id, options.node_id_len, "node_id")?;
        let (ceremony, job) = Ceremony::new();
        inner.submit(Job::Ceremony(job))?;
        let pending = ceremony.begin(display_name, node_id)?;
        write_json_buffer(
            out_pending_json,
            &serde_json::json!({
                "ceremony_id": pending.ceremony_id,
                "expires_in_ms": pending.expires_in_ms.to_string(),
            }),
        )?;
        write_out_ptr(
            out_creation,
            Box::into_raw(Box::new(Arc::new(ceremony))).cast::<RamfluxV2AccountCreation>(),
        )?;
        Ok(())
    })
}

/// The recovery phrase, once. Release the buffer with `ramflux_v2_buffer_wipe_free`.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_show_once(
    creation: *mut RamfluxV2AccountCreation,
    out_phrase: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_phrase)?;
        let phrase = ceremony(creation)?.show_once()?;
        // The copy handed to the host is the host's to erase; ours erases on drop.
        write_buffer(out_phrase, phrase.as_bytes().to_vec())?;
        Ok(())
    })
}

/// Three one-based word positions to ask the user for, after the phrase was hidden.
/// `out_positions` points at three bytes.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_challenge(
    creation: *mut RamfluxV2AccountCreation,
    out_positions: *mut u8,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        if out_positions.is_null() {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "out_positions is null"));
        }
        let positions = ceremony(creation)?.challenge()?;
        unsafe {
            std::ptr::copy_nonoverlapping(positions.as_ptr(), out_positions, positions.len());
        }
        Ok(())
    })
}

/// Spend the single confirmation attempt and open the account. `out_account_json`
/// receives the created account. A `Timeout` here has `effect = "unknown"`: list the
/// accounts to learn whether it exists.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_confirm(
    creation: *mut RamfluxV2AccountCreation,
    confirm: *const RamfluxV2CreateConfirm,
    out_account_json: *mut *mut RamfluxBuffer,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || {
        clear_out_ptr(out_account_json)?;
        let ceremony = ceremony(creation)?;
        let confirm = read_versioned(confirm)?;
        if confirm.flags != 0 {
            return Err(V2Error::new(RamfluxErrorCode::InvalidArgument, "reserved flags are set"));
        }
        let words = Box::new([
            secret_text(confirm.words[0], confirm.word_lens[0], "words[0]")?,
            secret_text(confirm.words[1], confirm.word_lens[1], "words[1]")?,
            secret_text(confirm.words[2], confirm.word_lens[2], "words[2]")?,
        ]);
        let passphrase = secret_text(confirm.passphrase, confirm.passphrase_len, "passphrase")?;
        let account = ceremony.confirm(words, passphrase)?;
        write_json_buffer(out_account_json, &account)?;
        Ok(())
    })
}

/// Cancel a pending ceremony. Succeeds after a spent confirmation as well.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_cancel(
    creation: *mut RamfluxV2AccountCreation,
    out_error_json: *mut *mut RamfluxBuffer,
) -> i32 {
    guard(out_error_json, || ceremony(creation)?.cancel())
}

/// Release a ceremony. A ceremony that was not confirmed is cancelled. Must not race with
/// another call on the same handle.
#[unsafe(no_mangle)]
pub extern "C" fn ramflux_v2_account_creation_free(creation: *mut RamfluxV2AccountCreation) {
    let _ignored = catch_unwind(AssertUnwindSafe(|| {
        if !creation.is_null() {
            // Dropping the last sender ends the task, which drops the connection.
            drop(unsafe { Box::from_raw(creation.cast::<Arc<Ceremony>>()) });
        }
    }));
}
