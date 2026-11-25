// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Synchronous notification-extension entry point, independent of the full client registry.

use super::super::{CAbiError, RamfluxBuffer};
use super::input::{self as i, Decode};
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(zeroize::ZeroizeOnDrop)]
struct Config {
    data_root: String,
    account_id: String,
    deadline_ms: u64,
    lease_wait_ms: u64,
}

impl Decode for Config {
    fn decode(value: &mut Value) -> Result<Self, CAbiError> {
        i::object(value, &["data_root", "account_id", "deadline_ms", "lease_wait_ms"])?;
        let deadline_ms = i::string(value, "deadline_ms")?.parse().map_err(|_| i::invalid())?;
        let lease_wait_ms = i::unsigned(value, "lease_wait_ms", Some(50))?;
        if lease_wait_ms > 5_000 {
            return Err(i::invalid());
        }
        let account_id = i::string(value, "account_id")?;
        crate::custody::valid_id(account_id).map_err(|_| i::invalid())?;
        Ok(Self {
            data_root: i::string(value, "data_root")?.into(),
            account_id: account_id.into(),
            deadline_ms,
            lease_wait_ms,
        })
    }
}

/// Fetch and durably apply one inbox page, then ACK, without opening a full client.
/// Config: `{data_root,account_id,deadline_ms,lease_wait_ms?}`; `deadline_ms` is absolute Unix
/// milliseconds as a decimal string. Budget is capped at 20s; lease wait defaults to 50ms
/// and cannot exceed 5s or the remaining deadline. Invoke off the UI thread.
/// The root must already exist with owner-only permissions (0700 on Unix).
/// Supply the same ABI-v1 custody provider as the app; callbacks must return promptly.
/// On status 0, JSON has exactly `outcome` (fetched/busy/locked/deadline), `show` (boolean or
/// null), `unread_total` (decimal string or null), `clears` (`[]` or `["messages"]`), `calls`
/// (always `[]`) and `receipts_sent` (always `"0"`). Fetched means the whole page is durably
/// applied and the notification candidates were consumed exactly once in this call; show is
/// true only for a newly applied visible incoming message that is still unread and unmuted.
/// Busy, locked and deadline return show and `unread_total` null and clears empty. A deadline
/// or error may follow partial durable progress; the caller must invoke again.
/// Entries use ordinary fenced receive policy: terminal application/refusal or durable hold.
/// Only committed terminal intents are acknowledged; uncertain ACKs remain durable for replay.
/// No couriers, subscriptions, media, card runtime or downloads are started. No account code
/// is checked and an explicitly locked account stays locked. Network/auth failures retain
/// ordinary nonzero SDK statuses and leave output null. Free with `ramflux_v2_buffer_free`.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_wake_fetch(
    config: *const u8,
    config_len: usize,
    provider: *const super::custody::RamfluxV2CustodyProvider,
    out: *mut *mut RamfluxBuffer,
) -> i32 {
    let entered = Instant::now();
    let now = super::super::current_millis();
    super::exports::call(|| {
        super::super::clear_out_ptr(out)?;
        if config.is_null() || config_len == 0 || config_len > super::state::MAX_FRAME_BYTES {
            return Err(i::invalid());
        }
        // SAFETY: the caller lends config_len readable bytes until this call returns.
        let config: Config = i::decode(unsafe { std::slice::from_raw_parts(config, config_len) })?;
        let remaining = u128::from(config.deadline_ms).saturating_sub(now).min(20_000);
        let remaining = u64::try_from(remaining).map_err(|_| i::invalid())?;
        let deadline = entered + Duration::from_millis(remaining);
        let root = super::data_root::validate(&config.data_root)?;
        if provider.is_null() {
            return Err(i::invalid());
        }
        // SAFETY: the caller supplies one aligned, readable ABI-v1 provider table for this call.
        let vault = super::custody::HostVault::new(unsafe { provider.read() })
            .map_err(|error| super::super::map_sdk_error(&error))?;
        let bus = crate::LocalBusConfig::new(std::path::PathBuf::new(), root);
        let result = crate::bus::wake_fetch::run(
            &bus,
            &config.account_id,
            vault,
            deadline,
            Duration::from_millis(config.lease_wait_ms),
        )
        .map_err(|error| super::super::map_sdk_error(&error))?;
        super::buffer::write_json_buffer(out, &result)
    })
}
