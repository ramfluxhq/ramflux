// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise the exported unlock entrypoint, including its serialized error buffer.
use super::*;
use crate::storage_failure_fixture::{Fault, Fixture, TestResult};

fn check(fault: Fault, expected: RamfluxErrorCode) -> TestResult {
    let fixture = Fixture::new(fault)?;
    assert_eq!(map_sdk_error(&SdkError::Storage(fixture.error()?)).code, expected);
    let config = serde_json::to_vec(&json!({"account_root":fixture.root()}))?;
    let mut client = ptr::null_mut();
    let mut error = ptr::null_mut();
    assert_eq!(
        ramflux_client_new(config.as_ptr(), config.len(), &raw mut client, &raw mut error),
        0
    );
    let request = br#"{"local_account_id":"acct","account_secret":"account-secret"}"#;
    let mut account = ptr::null_mut();
    let code = ramflux_client_unlock_account(
        client,
        request.as_ptr(),
        request.len(),
        &raw mut account,
        &raw mut error,
    );
    assert_eq!(code, expected as i32);
    assert!(account.is_null());
    assert!(!error.is_null());
    // SAFETY: the entrypoint returned an allocated, live error buffer. It remains
    // valid until ramflux_buffer_free below; no other thread accesses it.
    let body: Value =
        unsafe { serde_json::from_slice(std::slice::from_raw_parts((*error).ptr, (*error).len))? };
    assert_eq!(body["code"], expected as i32);
    assert_eq!(body["name"], expected.name());
    assert_eq!(
        body["retry_after_ms"],
        if matches!(fault, Fault::Busy) { json!(1_000) } else { Value::Null }
    );
    ramflux_buffer_free(error);
    let mut close_error = ptr::null_mut();
    assert_eq!(ramflux_client_close(client, &raw mut close_error), 0);
    ramflux_client_free(client);
    Ok(())
}

#[test]
fn c_abi_storage_policy_reports_real_process_contention_as_account_busy() -> TestResult {
    assert_eq!(RAMFLUX_ERR_ACCOUNT_BUSY, 18);
    assert_eq!(RAMFLUX_ERR_ACCOUNT_BUSY, RamfluxErrorCode::AccountBusy as i32);
    check(Fault::Busy, RamfluxErrorCode::AccountBusy)
}
#[test]
fn c_abi_storage_policy_reports_real_lock_open_failure_as_storage_failed() -> TestResult {
    assert_eq!(RamfluxErrorCode::StorageFailed as i32, 8);
    check(Fault::Io, RamfluxErrorCode::StorageFailed)
}
#[test]
fn c_abi_storage_policy_preserves_storage_failed_for_corrupted_mac() -> TestResult {
    check(Fault::Integrity, RamfluxErrorCode::StorageFailed)
}
