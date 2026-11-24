// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read one committed account snapshot without starting a supervisor.
use super::super::{CAbiError, RamfluxBuffer, RamfluxErrorCode};
use super::input::{self as i, Decode};
use serde_json::Value;
use zeroize::Zeroizing;

struct SnapshotConfig {
    data_root: String,
    account_id: String,
}

impl Decode for SnapshotConfig {
    fn decode(value: &mut Value) -> Result<Self, CAbiError> {
        i::object(value, &["data_root", "account_id"])?;
        Ok(Self {
            data_root: i::string(value, "data_root")?.to_owned(),
            account_id: i::string(value, "account_id")?.to_owned(),
        })
    }
}

fn invalid(message: &'static str) -> CAbiError {
    CAbiError::new(RamfluxErrorCode::InvalidArgument, message)
}

fn snapshot_config(config: *const u8, config_len: usize) -> Result<SnapshotConfig, CAbiError> {
    if config.is_null() || config_len == 0 || config_len > super::state::MAX_FRAME_BYTES {
        return Err(invalid("input"));
    }
    // SAFETY: the host lends `config_len` readable bytes until this synchronous call returns.
    let bytes = unsafe { std::slice::from_raw_parts(config, config_len) };
    i::decode(bytes)
}

fn account_code(code: *const u8, code_len: usize) -> Result<Zeroizing<Vec<u8>>, CAbiError> {
    if code.is_null() || code_len == 0 || code_len > 1024 {
        return Err(invalid("account code"));
    }
    // SAFETY: the host lends `code_len` readable bytes until this synchronous call returns.
    let bytes = unsafe { std::slice::from_raw_parts(code, code_len) };
    if std::str::from_utf8(bytes).is_err() {
        return Err(invalid("account code"));
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// Read one committed account snapshot. Does not start a supervisor or take a writer lease.
///
/// Config is `{data_root, account_id}`. `code` is the account code, borrowed for this call.
/// Output JSON is `{account_id, direct_message_ids, message_ids}` and uses `ramflux_v2_buffer_free`.
/// A root owned by another daemon is still readable. A second `ramflux_v2_client_open` of that
/// root remains `AccountBusy`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_shared_snapshot(
    config: *const u8,
    config_len: usize,
    code: *const u8,
    code_len: usize,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    super::exports::call(|| {
        super::super::clear_out_ptr(out)?;
        let config = snapshot_config(config, config_len)?;
        let root = super::data_root::validate(&config.data_root)?;
        let code = account_code(code, code_len)?;
        let snapshot = crate::read_committed_snapshot(&root, &config.account_id, &code)
            .map_err(|error| super::super::map_sdk_error(&error))?;
        super::buffer::write_json_buffer(out, &snapshot)
    })
}
