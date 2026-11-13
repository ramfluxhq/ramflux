// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Tests use host callbacks through the public ABI and the real account dispatcher.
use super::custody::{HostVault, RamfluxV2CustodyOperation as Op, RamfluxV2CustodyProvider};
use super::tests::{deadline, wait_result};
use super::*;
use crate::custody::PrimaryVault;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct Host {
    retained: AtomicUsize,
    released: AtomicUsize,
    calls: AtomicUsize,
    status: AtomicUsize,
    entries: Mutex<std::collections::BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>>,
}
fn host(context: u64) -> &'static Host {
    // SAFETY: a retained Arc owns the context throughout every SDK callback.
    unsafe { &*(context as *const Host) }
}
extern "C" fn retain(context: u64) {
    // SAFETY: caller owns this Arc during provider acceptance; SDK acquires its own reference.
    unsafe {
        Arc::increment_strong_count(context as *const Host);
    }
    host(context).retained.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn release(context: u64) {
    host(context).released.fetch_add(1, Ordering::SeqCst);
    // SAFETY: paired exactly once with retain, after the final SDK callback.
    unsafe {
        Arc::decrement_strong_count(context as *const Host);
    }
}
extern "C" fn invoke(context: u64, request: *mut super::custody::RamfluxV2CustodyRequest) -> i32 {
    // SAFETY: SDK lends one writable request until this synchronous callback returns.
    let request = unsafe { &mut *request };
    let op = request.operation;
    let reference = request.reference;
    let reference_len = request.reference_len;
    let input = request.input;
    let input_len = request.input_len;
    let output = request.output;
    let capacity = request.output_capacity;
    host(context).calls.fetch_add(1, Ordering::SeqCst);
    request.output_len = 0;
    let status = i32::try_from(host(context).status.load(Ordering::SeqCst)).unwrap_or(6);
    if status != 0 || matches!(op, Op::Preflight) {
        return status;
    }
    if reference_len > 128 || input_len > 4096 {
        return 2;
    }
    // SAFETY: callback inputs are borrowed from the SDK for their checked byte lengths.
    let reference = unsafe { std::slice::from_raw_parts(reference, reference_len) };
    let Ok(reference) = std::str::from_utf8(reference) else {
        return 2;
    };
    let Ok(mut entries) = host(context).entries.lock() else {
        return 6;
    };
    match op {
        Op::Preflight => 0,
        Op::StorePrimary | Op::StoreBranch | Op::StoreProvisioning => {
            if entries.len() >= 16 || entries.contains_key(reference) {
                return 5;
            }
            // SAFETY: SDK store bytes are valid for input_len and copied before return.
            let bytes = unsafe { std::slice::from_raw_parts(input, input_len) };
            entries.insert(reference.into(), zeroize::Zeroizing::new(bytes.to_vec()));
            0
        }
        Op::LoadPrimary | Op::LoadBranch | Op::LoadProvisioning => {
            let Some(bytes) = entries.get(reference) else {
                return 1;
            };
            if bytes.len() > capacity {
                return 2;
            }
            // SAFETY: SDK lends capacity writable bytes and a valid length slot; bounds checked.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
                request.output_len = bytes.len();
            }
            0
        }
        Op::Delete => {
            entries.remove(reference);
            0
        }
    }
}
fn table(host: &Host) -> RamfluxV2CustodyProvider {
    RamfluxV2CustodyProvider {
        abi_version: 1,
        context: std::ptr::from_ref(host) as u64,
        retain: Some(retain),
        release: Some(release),
        invoke: Some(invoke),
    }
}

#[test]
fn host_custody_preflight_drives_real_creation_and_releases_after_close() {
    let host = Arc::new(Host::default());
    let root = tempfile::tempdir().expect("test: isolated account root");
    let config = serde_json::to_vec(&json!({"data_root":root.path()})).expect("test: config");
    let mut client = 0;
    let provider = table(&host);
    assert_eq!(
        ramflux_v2_client_open_with_custody(
            config.as_ptr(),
            config.len(),
            &raw const provider,
            &raw mut client
        ),
        0,
        "host provider must open real supervisor"
    );
    let request = serde_json::to_vec(&json!({"sdk_api":"account", "method":"account.create.begin",
        "body":{"display_name":"Host Human","principal_kind":"human"},"deadline_ms":deadline()}))
    .expect("test: creation request");
    let mut operation = 0;
    assert_eq!(
        ramflux_v2_execute(client, request.as_ptr(), request.len(), &raw mut operation),
        0,
        "creation must be admitted through the public ABI"
    );
    let result = wait_result(client, operation);
    assert_eq!(
        result["response"]["body"]["ceremony"], "pending",
        "real creation must use host preflight rather than unsupported native vault"
    );
    assert_eq!(
        host.calls.load(Ordering::SeqCst),
        1,
        "preflight must run once before phrase creation"
    );
    assert_eq!(host.released.load(Ordering::SeqCst), 0, "live supervisor must retain the context");
    assert_eq!(ramflux_v2_client_close(client), 0, "close must drain provider tasks");
    assert_eq!(host.retained.load(Ordering::SeqCst), 1, "provider ownership is acquired once");
    assert_eq!(host.released.load(Ordering::SeqCst), 1, "provider ownership is released once");
}

#[test]
fn provider_errors_and_invalid_seed_lengths_fail_closed() {
    let host = Arc::new(Host::default());
    let vault = HostVault::new(table(&host)).expect("test: valid provider");
    let reference = ramflux_protocol::encode_base64url([7; 32]);
    host.entries
        .lock()
        .expect("test: host storage")
        .insert(reference.clone(), zeroize::Zeroizing::new(Vec::new()));
    assert!(vault.load_primary(&reference).is_err(), "empty host seed cannot become authority");
    vault.delete(&reference).expect("test: remove corrupt fixture");
    let seed = zeroize::Zeroizing::new([9; 32]);
    let key = ramflux_crypto::custody::SelfSigningKey::from_vault_seed(&seed);
    vault.store_new(&reference, &key).expect("test: host stores primary");
    let loaded = vault.load_primary(&reference).expect("test: host loads primary");
    assert_eq!(*loaded.vault_seed(), *seed, "provider must preserve exact vault seed bytes");
    assert!(
        vault.store_new(&reference, &key).is_err(),
        "host storage must refuse replacement authority"
    );
    host.status.store(4, Ordering::SeqCst);
    assert!(
        matches!(
            vault.preflight(),
            Err(crate::SdkError::CustodyVault(crate::custody::CustodyVaultReason::Locked))
        ),
        "host lock failure must remain typed"
    );
    assert!(
        vault.home_authorization_preflight().is_err(),
        "storage access cannot grant independent migration user presence"
    );
    let shared = Arc::clone(&vault);
    drop(vault);
    assert_eq!(host.released.load(Ordering::SeqCst), 0, "a pending SDK task retains custody");
    drop(shared);
    assert_eq!(host.released.load(Ordering::SeqCst), 1, "final task releases custody context");
}
