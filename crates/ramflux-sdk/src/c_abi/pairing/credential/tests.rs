// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Callback buffer and shutdown boundaries with real provider ownership.
use super::*;
use crate::custody::pairing::{PersistedReservation, persist_reservation};
use std::sync::{Arc, mpsc};
use std::time::Duration;
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Host {
    mode: usize,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
extern "C" fn callback(
    _: *const u8,
    _: usize,
    pass: *mut u8,
    _: usize,
    pass_len: *mut usize,
    confirm: *mut u8,
    _: usize,
    confirm_len: *mut usize,
    data: *mut c_void,
) -> i32 {
    // SAFETY: each test keeps Host alive until all provider uses drain and join.
    let Some(host) = (unsafe { data.cast::<Host>().as_ref() }) else { return 1 };
    if host.mode == 4 {
        if host.entered.send(()).is_err() {
            return 1;
        }
        let Ok(release) = host.release.lock() else { return 1 };
        if release.recv_timeout(Duration::from_secs(5)).is_err() {
            return 1;
        }
    }
    if host.mode == 1 {
        return 1;
    }
    // SAFETY: the provider supplies both initialized 1024-byte buffers and lengths.
    // Deliberately oversized length mode writes only metadata, never out of bounds.
    unsafe {
        pass.write(b'a');
        confirm.write(if host.mode == 3 { b'b' } else { b'a' });
        pass_len.write(if host.mode == 2 { 1025 } else { 1 });
        confirm_len.write(usize::from(host.mode == 3 || host.mode == 5));
    }
    0
}
fn metadata(root: &std::path::Path, action: &str) -> Result<CredentialRequest, SdkError> {
    let request = CredentialRequest {
        local_account_id: "callback-b".into(),
        reservation_id: ramflux_protocol::encode_base64url([41; 32]),
        frontend_generation: 1,
        action: action.into(),
    };
    persist_reservation(
        root,
        &PersistedReservation {
            account_id: request.local_account_id.clone(),
            reservation_id: request.reservation_id.clone(),
            frontend_generation: 1,
        },
    )?;
    Ok(request)
}
fn host(mode: usize) -> (Box<Host>, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, waiting) = mpsc::sync_channel(1);
    (Box::new(Host { mode, entered, release: Mutex::new(waiting) }), observed, release)
}
#[test]
fn pairing_abi_callback_refuses_oversized_mismatched_and_unrequested_confirmation() -> TestResult {
    let root = tempfile::tempdir()?;
    for (mode, action, expected) in
        [(1, "unlock", false), (2, "unlock", true), (3, "setup", true), (5, "unlock", true)]
    {
        let (mut host, _, _) = host(mode);
        let provider = CallbackProvider::new(
            root.path().into(),
            callback,
            std::ptr::from_mut(host.as_mut()).cast(),
        );
        let result = provider.provide(&metadata(root.path(), action)?);
        if expected {
            assert!(
                result.is_err(),
                "test: callback accepted invalid buffer or confirmation mode {mode}"
            );
        } else {
            assert!(
                matches!(result?, CredentialOutcome::Refused),
                "test: host refusal became input"
            );
        }
        provider.stop_and_drain();
    }
    let (mut host, _, _) = host(5);
    let provider = CallbackProvider::new(
        root.path().into(),
        callback,
        std::ptr::from_mut(host.as_mut()).cast(),
    );
    assert!(
        matches!(
            provider.provide(&metadata(root.path(), "setup")?)?,
            CredentialOutcome::Provided { confirmation: Some(_), .. }
        ),
        "test: equal setup confirmation was refused"
    );
    provider.stop_and_drain();
    Ok(())
}
#[test]
fn pairing_abi_callback_shutdown_drains_host_use_and_discards_late_input() -> TestResult {
    let root = tempfile::tempdir()?;
    let request = metadata(root.path(), "unlock")?;
    let (mut host, entered, release) = host(4);
    let provider = Arc::new(CallbackProvider::new(
        root.path().into(),
        callback,
        std::ptr::from_mut(host.as_mut()).cast(),
    ));
    let worker = {
        let provider = provider.clone();
        std::thread::spawn(move || provider.provide(&request))
    };
    entered.recv_timeout(Duration::from_secs(5))?;
    provider.cancel();
    assert_eq!(
        *provider.active.lock().map_err(|_| "test: active lock")?,
        1,
        "test: active host callback lost its drain owner"
    );
    let drain = {
        let provider = provider.clone();
        std::thread::spawn(move || provider.stop_and_drain())
    };
    release.send(())?;
    let result = worker.join().map_err(|_| "test: callback worker panic")??;
    drain.join().map_err(|_| "test: drain panic")?;
    assert!(
        matches!(result, CredentialOutcome::Refused),
        "test: shutdown released late private input"
    );
    assert_eq!(
        *provider.active.lock().map_err(|_| "test: active lock")?,
        0,
        "test: shutdown returned with a host callback active"
    );
    assert!(
        provider.provide(&metadata(root.path(), "unlock")?).is_err(),
        "test: stopped provider called host again"
    );
    Ok(())
}
