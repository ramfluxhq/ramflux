// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read one committed account snapshot without starting a supervisor.
use super::super::{CAbiError, RamfluxBuffer, RamfluxErrorCode};
use super::input::{self as i, Decode};
use crate::custody::PrimaryVault;
use serde_json::Value;

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

/// Read one committed account snapshot. Does not start a supervisor or take a writer lease.
///
/// Config is `{data_root, account_id}`. The host supplies the shared OS custody provider.
/// A locked account requires ordinary unlock; this call never checks an account code.
/// Output JSON is `{account_id, direct_message_ids, message_ids}` and uses `ramflux_v2_buffer_free`.
/// A root owned by another daemon is still readable. A second `ramflux_v2_client_open` of that
/// root remains `AccountBusy`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_shared_snapshot(
    config: *const u8,
    config_len: usize,
    provider: *const super::custody::RamfluxV2CustodyProvider,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    super::exports::call(|| {
        super::super::clear_out_ptr(out)?;
        let config = snapshot_config(config, config_len)?;
        let root = super::data_root::validate(&config.data_root)?;
        if provider.is_null() {
            return Err(invalid("provider"));
        }
        // SAFETY: the host supplies one valid aligned provider table for this call.
        let vault = super::custody::HostVault::new(unsafe { provider.read() })
            .map_err(|error| super::super::map_sdk_error(&error))?;
        vault.preflight().map_err(|error| super::data_root::custody_error(&error))?;
        let snapshot = crate::read_committed_snapshot(&root, &config.account_id, vault.as_ref())
            .map_err(|error| super::super::map_sdk_error(&error))?;
        super::buffer::write_json_buffer(out, &snapshot)
    })
}
