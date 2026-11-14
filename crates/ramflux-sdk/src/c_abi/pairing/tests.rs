// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual ABI, attended socket, private call broker and shared closed DTO codecs.
use super::*;
use crate::c_abi::{
    ramflux_buffer_free, ramflux_client_close, ramflux_client_free, ramflux_client_new,
};
use crate::custody::pairing::{PersistedReservation, persist_reservation};
use crate::platform::listener::BusListener as _;
use ramflux_protocol::custody::pairing::full_transfer::U64;
use ramflux_protocol::custody::pairing::local_dto::{
    CredentialRequest, FullStatus, FullStatusStage, FullTailStatus, LocalEvent, StatusRequest,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
static CALLBACKS: AtomicUsize = AtomicUsize::new(0);
const CANARY: &[u8] = b"cold-resume-private-canary";
type TestResult = Result<(), Box<dyn std::error::Error>>;
extern "C" fn input(
    request: *const u8,
    request_len: usize,
    pass: *mut u8,
    pass_cap: usize,
    pass_len: *mut usize,
    confirm: *mut u8,
    confirm_cap: usize,
    confirm_len: *mut usize,
    _: *mut c_void,
) -> i32 {
    if request.is_null()
        || request_len > 1024
        || pass.is_null()
        || confirm.is_null()
        || pass_len.is_null()
        || confirm_len.is_null()
        || pass_cap != 1024
        || confirm_cap != 1024
    {
        return 1;
    }
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the SDK supplied these live buffers, and the capacities/nulls above
    // establish room for this fixed canary and the two writable length outputs.
    unsafe {
        std::ptr::copy_nonoverlapping(CANARY.as_ptr(), pass, CANARY.len());
        *pass_len = CANARY.len();
        *confirm_len = 0;
    }
    0
}
#[tokio::test]
async fn pairing_abi_private_callbacks_and_allocated_dto_results_round_trip() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(round_trip()).await
}
async fn round_trip() -> TestResult {
    CALLBACKS.store(0, Ordering::Relaxed);
    let root = Arc::new(tempfile::tempdir()?);
    let metadata = CredentialRequest {
        local_account_id: "cold-b".into(),
        reservation_id: ramflux_protocol::encode_base64url([31; 32]),
        frontend_generation: 2,
        action: "unlock".into(),
    };
    persist_reservation(
        root.path(),
        &PersistedReservation {
            account_id: "cold-b".into(),
            reservation_id: metadata.reservation_id.clone(),
            frontend_generation: 2,
        },
    )?;
    let socket = root.path().join("abi.sock");
    let listener = crate::platform::listener::bind(&socket)?;
    let config = ramflux_protocol::canonical_json_bytes(&serde_json::json!({
        "account_root":root.path().to_str().ok_or("test: root UTF8")?,
        "pairing_socket":socket.to_str().ok_or("test: socket UTF8")?,"pairing_account_id":"cold-b"}))?;
    let owned_root = root.clone();
    let host = tokio::task::spawn_blocking(move || {
        let _root = owned_root;
        ffi_case(&config)
    });
    let daemon = async {
        let mut stream = listener.accept().await?;
        let parent = crate::bus::io::read_local_bus_frame(&mut stream).await?;
        let result = LocalResult {
            schema: "ramflux.pairing.LocalResult.v2".into(),
            version: 2,
            outcome: Outcome::FullStatus {
                value: Box::new(FullStatus {
                    attachment_absent: U64(0),
                    bytes_durable: U64(12),
                    bytes_total: U64(12),
                    cut: U64(1),
                    generation: 4,
                    lease_expires_at: crate::custody::network_now()? + 604_800,
                    operation_id: ramflux_protocol::encode_base64url([32; 32]),
                    result: None,
                    role: "responder".into(),
                    stage: FullStatusStage::AwaitingPrepare,
                    tail_status: FullTailStatus::None,
                }),
            },
        };
        result.validate()?;
        crate::bus::credentials::resume_tests::serve(
            root.path(),
            &mut stream,
            parent,
            metadata,
            serde_json::to_value(result)?,
        )
        .await
    };
    let (host, daemon) = tokio::join!(host, daemon);
    daemon?;
    host?.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert_eq!(
        CALLBACKS.load(Ordering::Relaxed),
        1,
        "test: ABI invoked an extra private callback or bypassed it"
    );
    Ok(())
}
struct Client(*mut RamfluxClient);
impl Drop for Client {
    fn drop(&mut self) {
        ramflux_client_free(self.0);
    }
}
struct Buffer(*mut RamfluxBuffer);
impl Drop for Buffer {
    fn drop(&mut self) {
        ramflux_buffer_free(self.0);
    }
}
impl Buffer {
    fn bytes(&self) -> Result<Vec<u8>, String> {
        // SAFETY: each wrapper owns one SDK-returned buffer until its Drop frees it.
        let value = unsafe { self.0.as_ref() }.ok_or("test: missing ABI buffer")?;
        if value.len > LocalResult::LIMIT {
            return Err("test: ABI output exceeded DTO cap".into());
        }
        if value.len == 0 {
            return Ok(Vec::new());
        }
        if value.ptr.is_null() {
            return Err("test: nonempty ABI buffer lacked data".into());
        }
        // SAFETY: the SDK allocated exactly len initialized bytes for this live buffer.
        Ok(unsafe { std::slice::from_raw_parts(value.ptr, value.len) }.to_vec())
    }
}
fn ffi_case(config: &[u8]) -> Result<(), String> {
    let mut client = std::ptr::null_mut();
    let mut error = std::ptr::null_mut();
    assert_eq!(
        ramflux_client_new(config.as_ptr(), config.len(), &raw mut client, &raw mut error),
        0,
        "test: ABI rejected the configured pairing client"
    );
    let client = Client(client);
    let _error = Buffer(error);
    assert_eq!(
        ramflux_pairing_set_credential_provider(client.0, Some(input), std::ptr::null_mut()),
        0,
        "test: ABI failed to install the attended provider"
    );
    let request = StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: ramflux_protocol::encode_base64url([32; 32]),
        generation: 4,
    };
    let method =
        std::ffi::CString::new("device.transfer.status").map_err(|error| error.to_string())?;
    let body = request.to_wire_bytes().map_err(|error| error.to_string())?;
    let mut result = std::ptr::null_mut();
    assert_eq!(
        ramflux_pairing_call(client.0, method.as_ptr(), body.as_ptr(), body.len(), &raw mut result),
        0,
        "test: ABI failed its actual attended raw-reply exchange"
    );
    let result = Buffer(result);
    assert!(
        matches!(
            LocalResult::from_wire_bytes(&result.bytes()?)
                .map_err(|error| error.to_string())?
                .outcome,
            Outcome::FullStatus { .. }
        ),
        "test: ABI did not return the shared FullStatus DTO"
    );
    let stale = StatusRequest { generation: 5, ..request };
    let body = stale.to_wire_bytes().map_err(|error| error.to_string())?;
    let mut refused = std::ptr::null_mut();
    assert_eq!(
        ramflux_pairing_call(
            client.0,
            method.as_ptr(),
            body.as_ptr(),
            body.len(),
            &raw mut refused
        ),
        RamfluxErrorCode::PairingStale as i32,
        "test: ABI sent or accepted a known stale operation generation"
    );
    let refused = Buffer(refused);
    assert!(
        matches!(LocalResult::from_wire_bytes(&refused.bytes()?).map_err(|error|error.to_string())?.outcome,
        Outcome::Error { error } if error.code == "WrongContext"),
        "test: stale ABI result lost its closed error body"
    );
    let mut event = std::ptr::null_mut();
    assert_eq!(
        ramflux_pairing_event_poll(client.0, &raw mut event),
        0,
        "test: ABI event poll failed"
    );
    let event = Buffer(event);
    let bytes = event.bytes()?;
    assert!(LocalEvent::from_wire_bytes(&bytes).is_ok(), "test: ABI queued a foreign event schema");
    assert!(
        !bytes.windows(CANARY.len()).any(|part| part == CANARY),
        "test: ABI leaked private input into an event"
    );
    assert_eq!(
        ramflux_pairing_set_credential_provider(client.0, None, std::ptr::null_mut()),
        0,
        "test: ABI failed to unregister its callback"
    );
    assert_eq!(
        ramflux_client_close(client.0, std::ptr::null_mut()),
        0,
        "test: ABI failed to close"
    );
    Ok(())
}

/// Read an actual registered actor over the configured socket through the public ABI.
pub(super) fn registered_state(config: &[u8], body: &[u8]) -> Result<serde_json::Value, String> {
    let mut client = std::ptr::null_mut();
    let mut error = std::ptr::null_mut();
    let code = ramflux_client_new(config.as_ptr(), config.len(), &raw mut client, &raw mut error);
    let client = Client(client);
    let _error = Buffer(error);
    if code != 0 {
        return Err("test: registered-state ABI client setup refused".into());
    }
    let method =
        std::ffi::CString::new("device.transfer.status").map_err(|error| error.to_string())?;
    let mut output = std::ptr::null_mut();
    let code =
        ramflux_pairing_call(client.0, method.as_ptr(), body.as_ptr(), body.len(), &raw mut output);
    let output = Buffer(output);
    if code != 0 {
        return Err(format!("test: registered-state ABI status refused with code {code}"));
    }
    let result =
        LocalResult::from_wire_bytes(&output.bytes()?).map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}
