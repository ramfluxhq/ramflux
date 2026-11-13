// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use serde_json::Value;
use std::time::{Duration, Instant};

fn take_buffer(ptr: *mut RamfluxBuffer) -> Value {
    assert!(!ptr.is_null(), "successful bridge call must allocate its output");
    // SAFETY: the bridge returned a live uniquely owned buffer; read before releasing it.
    let buffer = unsafe { &*ptr };
    // SAFETY: bridge buffer contains exactly len readable bytes until released below.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    let value = serde_json::from_slice(bytes).expect("test: valid bridge JSON");
    ramflux_v2_buffer_free(ptr);
    value
}

struct Fixture {
    _root: tempfile::TempDir,
    handle: u64,
}
impl Fixture {
    fn open() -> Self {
        let root = tempfile::tempdir().expect("test: isolated data root");
        let config = serde_json::to_vec(&json!({"data_root":root.path()})).expect("test: config");
        let mut handle = 0;
        assert_eq!(
            ramflux_v2_client_open(config.as_ptr(), config.len(), &mut handle),
            0,
            "real in-process supervisor must start"
        );
        Self { _root: root, handle }
    }
    fn submit(&self, method: &str, deadline: u64) -> u64 {
        let request = serde_json::to_vec(&json!({
            "sdk_api":"account","method":method,"body":{},"deadline_ms":deadline
        }))
        .expect("test: request");
        let mut operation = 0;
        assert_eq!(
            ramflux_v2_execute(self.handle, request.as_ptr(), request.len(), &mut operation),
            0,
            "request admission should succeed"
        );
        operation
    }
    fn result(&self, operation: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut buffer = std::ptr::null_mut();
            let code = ramflux_v2_operation_poll(self.handle, operation, &mut buffer);
            if code == 0 {
                return take_buffer(buffer);
            }
            assert_eq!(code, RamfluxV2Status::Pending as i32, "poll must preserve its operation");
            assert!(Instant::now() < deadline, "real supervisor request exceeded test deadline");
            std::thread::yield_now();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        assert_eq!(
            ramflux_v2_client_close(self.handle),
            0,
            "supervisor must drain and release its writer"
        );
    }
}
fn deadline() -> u64 {
    u64::try_from(super::super::current_millis())
        .expect("test: epoch millis")
        .saturating_add(30_000)
}

#[test]
fn negotiation_preserves_v1_and_publishes_supervisor_inventory() {
    assert_eq!(super::super::ramflux_sdk_abi_version_major(), 1, "v1 consumers retain their ABI");
    let mut buffer = std::ptr::null_mut();
    assert_eq!(ramflux_v2_negotiate(2, 0, &mut buffer), 0, "ABI v2 negotiation");
    let metadata = take_buffer(buffer);
    let methods = metadata["methods"].as_array().expect("test: method inventory");
    for method in [
        "account.create.begin",
        "account.create.show_once",
        "account.list",
        "message.submit",
        "call.invite",
        "device.pair.begin",
        "group.role.set",
        "surface.action",
        "account.config.set",
    ] {
        assert!(methods.contains(&json!(method)), "missing shared supervisor method {method}");
    }
    assert_eq!(ramflux_v2_negotiate(3, 0, &mut buffer), 3, "major mismatch is typed");
    assert!(buffer.is_null(), "failure must clear output");
}

#[test]
fn executes_real_supervisor_and_releases_writer_on_close() {
    let fixture = Fixture::open();
    let id = fixture.submit("account.list", deadline());
    let result = fixture.result(id);
    assert_eq!(result["code"], 0, "account index read must use real supervisor");
    assert_eq!(result["response"]["method"], "account.list", "correlation must be retained");
    assert_eq!(ramflux_v2_operation_release(fixture.handle, id), 0, "terminal handle released");
    let config =
        serde_json::to_vec(&json!({"data_root":fixture._root.path()})).expect("test: config");
    let mut duplicate = 0;
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &mut duplicate),
        18,
        "second ABI client must not acquire the same data-root writer"
    );
    assert_eq!(ramflux_v2_client_close(fixture.handle), 0, "first writer closes");
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &mut duplicate),
        0,
        "close must release all database and root-lock owners"
    );
    assert_eq!(ramflux_v2_client_close(duplicate), 0, "replacement closes cleanly");
}

#[test]
fn expired_requests_use_real_dispatch_error_and_custody_is_reachable() {
    let fixture = Fixture::open();
    let expired = fixture.submit("account.list", 1);
    let result = fixture.result(expired);
    assert_ne!(result["code"], 0, "expired request cannot succeed");
    assert_eq!(result["response"]["kind"], "error", "dispatch produces a typed error frame");
    assert_eq!(ramflux_v2_operation_release(fixture.handle, expired), 0, "release expiry");
    let custody = fixture.submit("account.create.show_once", deadline());
    let result = fixture.result(custody);
    assert_ne!(result["code"], 0, "no ceremony cannot disclose a phrase");
    assert_eq!(
        result["response"]["method"], "account.create.show_once",
        "custody uses shared connection handling"
    );
}

#[test]
fn duplicate_json_and_oversized_inputs_are_rejected_before_admission() {
    let fixture = Fixture::open();
    let request = br#"{"sdk_api":"account","method":"account.list","body":{},"deadline_ms":1,"deadline_ms":2}"#;
    let mut id = 99;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &mut id),
        1,
        "duplicate I-JSON keys must fail"
    );
    assert_eq!(id, 0, "failure cannot publish an operation handle");
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), MAX_FRAME_BYTES + 1, &mut id),
        1,
        "oversized input must be rejected without dereferencing it"
    );
}

#[test]
fn event_overflow_is_explicit_and_cannot_consume_completion_credit() {
    let shared = state::Shared::default();
    shared.operations.lock().expect("test: operations").insert(1, Arc::new(Operation::default()));
    for _ in 0..=state::MAX_EVENTS {
        shared.push_event(b"{}".to_vec());
    }
    shared.complete(1, json!({"code":0}));
    let events = shared.events.lock().expect("test: events");
    assert!(events.resync, "overflow must require projection resync");
    assert!(events.queue.is_empty(), "stale events must not be presented as a continuous journal");
    let operations = shared.operations.lock().expect("test: operations");
    assert!(
        operations
            .get(&1)
            .expect("test: retained operation")
            .state
            .lock()
            .expect("test: operation")
            .result
            .is_some(),
        "event overflow cannot discard terminal completion"
    );
}

#[test]
fn preadmission_cancel_never_reaches_the_supervisor() {
    let root = tempfile::tempdir().expect("test: isolated root");
    let client =
        Client::start(LocalBusConfig::new("", root.path())).expect("test: start supervisor");
    let operation = Arc::new(Operation::default());
    operation.state.lock().expect("test: operation").cancelled = true;
    client.shared.operations.lock().expect("test: operation map").insert(1, Arc::clone(&operation));
    let frame = LocalBusFrame::request("1", None, "node", "node.remove", json!({"node_id":"test"}));
    let bytes = crate::bus::inprocess::encode_request(frame).expect("test: encoded mutation");
    client
        .commands
        .try_send(Command {
            id: 1,
            bytes: zeroize::Zeroizing::new(bytes),
            operation: Arc::clone(&operation),
        })
        .map_err(|_| "send failed")
        .expect("test: queue cancelled operation");
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let state = operation.state.lock().expect("test: operation");
        if let Some(result) = &state.result {
            let result: Value = serde_json::from_slice(result).expect("test: result");
            assert_eq!(result["code"], 25, "cancelled queued work must not dispatch");
            assert_eq!(result["effects"], "none", "no-effect guarantee applies before admission");
            assert!(!state.admitted, "cancel must win the admission transition");
            break;
        }
        drop(state);
        assert!(Instant::now() < until, "cancel terminal exceeded deadline");
        std::thread::yield_now();
    }
    client.close().expect("test: close supervisor");
}
