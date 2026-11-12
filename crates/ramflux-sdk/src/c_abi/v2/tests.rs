// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Boundary tests of C ABI major 2. They call the exported symbols, not internal helpers,
//! wherever a symbol exists for the behaviour.

use super::driver::Stage;
use super::error::{Effect, refusal_code};
use super::subscription::{EventQueue, Terminal};
use super::types::{RamfluxV2Config, RamfluxV2Request, RamfluxV2Version};
use super::*;
use crate::c_abi::{RamfluxBuffer, RamfluxErrorCode, ramflux_buffer_free};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn take_json(buffer: *mut RamfluxBuffer) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if buffer.is_null() {
        return Err("buffer is null".into());
    }
    let owned = unsafe { &*buffer };
    let bytes = unsafe { std::slice::from_raw_parts(owned.ptr, owned.len) }.to_vec();
    ramflux_buffer_free(buffer);
    Ok(serde_json::from_slice(&bytes)?)
}

fn size_of_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(0)
}

fn config(root: &std::path::Path) -> RamfluxV2Config {
    let text = root.as_os_str().as_encoded_bytes();
    RamfluxV2Config {
        struct_size: size_of_u32::<RamfluxV2Config>(),
        host_abi_major: RAMFLUX_V2_ABI_MAJOR,
        host_abi_minor: RAMFLUX_V2_ABI_MINOR,
        flags: 0,
        data_root: text.as_ptr(),
        data_root_len: text.len(),
        suspend_deadline_ms: 0,
        request_deadline_ms: 0,
    }
}

fn request(method: &'static str, sdk_api: &'static str) -> RamfluxV2Request {
    RamfluxV2Request {
        struct_size: size_of_u32::<RamfluxV2Request>(),
        flags: 0,
        method: method.as_ptr(),
        method_len: method.len(),
        sdk_api: sdk_api.as_ptr(),
        sdk_api_len: sdk_api.len(),
        account_id: std::ptr::null(),
        account_id_len: 0,
        operation_id: std::ptr::null(),
        operation_id_len: 0,
        body_json: std::ptr::null(),
        body_json_len: 0,
        deadline_unix_ms: 0,
        cancel: std::ptr::null(),
    }
}

#[test]
fn header_declares_every_export() -> TestResult {
    let source = include_str!("exports.rs");
    let exported: std::collections::BTreeSet<&str> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub extern \"C\" fn "))
        .filter_map(|rest| rest.split('(').next())
        .collect();
    assert!(exported.len() >= 18, "export scan found {}", exported.len());
    for symbol in &exported {
        assert!(HEADER.contains(&format!("{symbol}(")), "header lacks {symbol}");
    }
    let declared: std::collections::BTreeSet<&str> = HEADER
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|word| word.starts_with("ramflux_v2_"))
        .collect();
    for symbol in declared {
        assert!(exported.contains(symbol), "header declares {symbol} which is not exported");
    }
    Ok(())
}

#[test]
fn version_reports_major_two_and_leaves_major_one_unchanged() {
    let mut version = RamfluxV2Version {
        struct_size: size_of_u32::<RamfluxV2Version>(),
        abi_major: 0,
        abi_minor: 0,
        protocol_version: 0,
        max_frame_bytes: 0,
        max_queue_events: 0,
        descriptor_fingerprint: [1; 32],
    };
    assert_eq!(ramflux_v2_abi_version(&raw mut version), 0);
    assert_eq!(version.abi_major, 2);
    assert_eq!(version.max_frame_bytes, 1 << 20);
    assert_eq!(crate::c_abi::ramflux_sdk_abi_version_major(), 1);
}

#[test]
fn struct_size_below_layout_is_invalid_and_above_is_unsupported() {
    let mut version = RamfluxV2Version {
        struct_size: 8,
        abi_major: 7,
        abi_minor: 0,
        protocol_version: 0,
        max_frame_bytes: 0,
        max_queue_events: 0,
        descriptor_fingerprint: [0; 32],
    };
    assert_eq!(
        ramflux_v2_abi_version(&raw mut version),
        RamfluxErrorCode::InvalidArgument as i32
    );
    assert_eq!(version.abi_major, 7, "a refused call must not write through the pointer");
    version.struct_size = size_of_u32::<RamfluxV2Version>() + 8;
    assert_eq!(
        ramflux_v2_abi_version(&raw mut version),
        RamfluxErrorCode::UnsupportedVersion as i32
    );
}

#[test]
fn newer_host_minor_and_other_major_are_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    for (major, minor) in [(1, 0), (3, 0), (2, RAMFLUX_V2_ABI_MINOR + 1)] {
        let mut config = config(root.path());
        config.host_abi_major = major;
        config.host_abi_minor = minor;
        let mut core = std::ptr::dangling_mut::<RamfluxV2Core>();
        let mut error = std::ptr::null_mut();
        let code = ramflux_v2_core_new(&raw const config, &raw mut core, &raw mut error);
        assert_eq!(code, RamfluxErrorCode::UnsupportedVersion as i32);
        assert!(core.is_null(), "a failed call must clear the out handle");
        assert_eq!(take_json(error)?["effect"], "none");
    }
    Ok(())
}

#[test]
fn null_and_oversize_inputs_are_refused_without_a_panic() -> TestResult {
    let mut error = std::ptr::null_mut();
    let mut response = std::ptr::null_mut();
    let request = request("account.list", "account");
    let code = ramflux_v2_execute(
        std::ptr::null_mut(),
        &raw const request,
        &raw mut response,
        &raw mut error,
    );
    assert_eq!(code, RamfluxErrorCode::InvalidArgument as i32);
    assert!(response.is_null());
    assert_eq!(take_json(error)?["code"], 1);
    assert_eq!(ramflux_v2_cancel(std::ptr::null_mut()), RamfluxErrorCode::InvalidArgument as i32);
    ramflux_v2_core_free(std::ptr::null_mut());
    ramflux_v2_subscription_free(std::ptr::null_mut());
    ramflux_v2_cancel_free(std::ptr::null_mut());
    ramflux_v2_buffer_wipe_free(std::ptr::null_mut());
    Ok(())
}

#[cfg(unix)]
#[test]
fn execute_runs_through_the_supervisor_and_suspend_releases_the_data_root() -> TestResult {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    let mut core = std::ptr::null_mut();
    let mut error = std::ptr::null_mut();
    assert_eq!(ramflux_v2_core_new(&raw const config, &raw mut core, &raw mut error), 0);

    // Stopped: nothing was opened, and a request has no effect.
    let list = request("account.list", "account");
    let mut response = std::ptr::null_mut();
    let code = ramflux_v2_execute(core, &raw const list, &raw mut response, &raw mut error);
    assert_ne!(code, 0);
    assert_eq!(take_json(error)?["effect"], "none");

    assert_eq!(ramflux_v2_core_start(core, &raw mut error), 0);
    let mut state = 9_u32;
    assert_eq!(ramflux_v2_core_state(core, &raw mut state), 0);
    assert_eq!(state, 1);
    assert_eq!(ramflux_v2_execute(core, &raw const list, &raw mut response, &raw mut error), 0);
    assert!(take_json(response)?.is_object());

    // A second supervisor on the same root is refused while the first runs.
    let mut second = std::ptr::null_mut();
    assert_eq!(ramflux_v2_core_new(&raw const config, &raw mut second, &raw mut error), 0);
    assert_eq!(
        ramflux_v2_core_start(second, &raw mut error),
        RamfluxErrorCode::AccountBusy as i32
    );
    ramflux_buffer_free(error);

    let mut report = std::ptr::null_mut();
    assert_eq!(ramflux_v2_core_suspend(core, &raw mut report, &raw mut error), 0);
    assert_eq!(take_json(report)?["data_root_lock_released"], true);
    // Suspended: the lock is free, so the second supervisor can take the root.
    assert_eq!(ramflux_v2_core_start(second, &raw mut error), 0);
    assert_eq!(ramflux_v2_core_close(second, &raw mut error), 0);
    ramflux_v2_core_free(second);

    assert_eq!(ramflux_v2_core_resume(core, &raw mut error), 0);
    assert_eq!(ramflux_v2_execute(core, &raw const list, &raw mut response, &raw mut error), 0);
    ramflux_buffer_free(response);

    // Close is idempotent, and a closed core admits nothing.
    assert_eq!(ramflux_v2_core_close(core, &raw mut error), 0);
    assert_eq!(ramflux_v2_core_close(core, &raw mut error), 0);
    let code = ramflux_v2_execute(core, &raw const list, &raw mut response, &raw mut error);
    assert_eq!(code, RamfluxErrorCode::TransportUnavailable as i32);
    assert_eq!(take_json(error)?["reason_code"], "closed");
    ramflux_v2_core_free(core);
    Ok(())
}

#[cfg(unix)]
#[test]
fn cancelled_before_admission_has_no_effect() -> TestResult {
    let root = tempfile::tempdir()?;
    let config = config(root.path());
    let mut core = std::ptr::null_mut();
    let mut error = std::ptr::null_mut();
    assert_eq!(ramflux_v2_core_new(&raw const config, &raw mut core, &raw mut error), 0);
    assert_eq!(ramflux_v2_core_start(core, &raw mut error), 0);
    let mut cancel = std::ptr::null_mut();
    assert_eq!(ramflux_v2_cancel_new(&raw mut cancel), 0);
    assert_eq!(ramflux_v2_cancel(cancel), 0);
    let mut list = request("account.list", "account");
    list.cancel = cancel.cast_const();
    let mut response = std::ptr::null_mut();
    let code = ramflux_v2_execute(core, &raw const list, &raw mut response, &raw mut error);
    assert_eq!(code, RamfluxErrorCode::Timeout as i32);
    let error = take_json(error)?;
    assert_eq!(error["reason_code"], "cancelled");
    assert_eq!(error["effect"], "none");
    ramflux_v2_cancel_free(cancel);
    ramflux_v2_core_free(core);
    Ok(())
}

#[test]
fn a_waiter_that_gives_up_after_the_claim_reports_unknown_effect() {
    // Before the driver claims the request, giving up means it is never sent.
    let stage = Stage::default();
    assert_eq!(stage.abandon(), Effect::None);
    assert_eq!(stage.abandon(), Effect::None, "abandon is stable");

    // After the claim the supervisor owns the request whatever the waiter does.
    let stage = Stage::default();
    let job = super::driver::tests_support::claim(&stage);
    assert!(job);
    assert_eq!(stage.abandon(), Effect::Unknown);
    assert!(!super::driver::tests_support::claim(&stage), "a request is sent at most once");
}

#[test]
fn slow_poller_gets_terminal_lagged_with_the_last_delivered_sequence() -> TestResult {
    let queue = EventQueue::new(2);
    assert!(super::subscription::tests_support::push(&queue, 1));
    assert!(super::subscription::tests_support::push(&queue, 2));
    let first: serde_json::Value = serde_json::from_slice(&queue.poll(1, Duration::ZERO)?)?;
    assert_eq!(first["events"].as_array().map(Vec::len), Some(1));
    assert!(first["terminal"].is_null());
    assert!(super::subscription::tests_support::push(&queue, 3));
    // The fourth event does not fit: the subscription ends, nothing is dropped silently.
    assert!(!super::subscription::tests_support::push(&queue, 4));
    assert!(!super::subscription::tests_support::push(&queue, 5));
    let rest: serde_json::Value = serde_json::from_slice(&queue.poll(64, Duration::ZERO)?)?;
    assert_eq!(rest["events"].as_array().map(Vec::len), Some(2));
    assert_eq!(rest["terminal"]["kind"], "lagged");
    assert_eq!(rest["terminal"]["last_seq"], "3");
    Ok(())
}

#[test]
fn cancelled_subscription_wakes_a_blocked_poll() -> TestResult {
    let queue = EventQueue::new(4);
    let waiter = std::sync::Arc::clone(&queue);
    let blocked = std::thread::spawn(move || waiter.poll(1, Duration::from_secs(20)));
    std::thread::sleep(Duration::from_millis(50));
    queue.terminate(Terminal::Cancelled);
    let bytes = blocked.join().map_err(|_| "poll thread panicked")??;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(value["terminal"]["kind"], "cancelled");
    Ok(())
}

#[test]
fn refusal_codes_keep_the_major_one_numbers() {
    assert_eq!(refusal_code("SchemaResetRequired") as i32, 23);
    assert_eq!(refusal_code("CustodyForkFenced") as i32, 22);
    assert_eq!(refusal_code("DataRootInUse") as i32, 18);
    assert_eq!(refusal_code("ObjectErased") as i32, 19);
    assert_eq!(refusal_code("a_refusal_added_later") as i32, 16);
}
