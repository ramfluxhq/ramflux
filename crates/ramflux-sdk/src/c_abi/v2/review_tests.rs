// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public C boundary regressions for review findings.
use super::tests::{Fixture, deadline, take_buffer};
use super::*;
use serde_json::json;

thread_local! { static PANIC_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
pub(super) fn maybe_panic() {
    assert!(!PANIC_NEXT.with(|value| value.replace(false)), "test: injected boundary unwind");
}

#[test]
fn public_exports_contain_unwinds_and_the_client_survives() {
    let fixture = Fixture::open();
    let mut buffer = std::ptr::null_mut();
    PANIC_NEXT.with(|value| value.set(true));
    assert_eq!(
        ramflux_v2_negotiate(2, 0, &raw mut buffer),
        17,
        "native caller receives typed panic status"
    );
    assert!(buffer.is_null(), "panic cannot invent a buffer");
    PANIC_NEXT.with(|value| value.set(true));
    ramflux_v2_buffer_free(std::ptr::null_mut());
    assert_eq!(
        fixture.result(fixture.submit("account.list", deadline()))["code"],
        0,
        "contained unwinds leave the supervisor reachable"
    );
}

#[test]
fn c_event_poll_fences_late_zero_and_already_queued_stale_generations() {
    let fixture = Fixture::open();
    let body = json!({"topics":["account.backup.job.changed"]});
    let first = fixture.result(fixture.submit_body("subscription.open", &body, deadline()));
    let old = first["subscription_generation"]
        .as_str()
        .expect("test: first generation")
        .parse::<u64>()
        .expect("test: u64");
    let shared = super::exports::test_shared(fixture.handle);
    shared.push_event(br#"{"old":true}"#.to_vec(), old);
    assert_eq!(
        fixture.result(fixture.submit("subscription.close", deadline()))["code"],
        0,
        "explicit close acknowledgement releases the subscription slot"
    );
    let reopened = fixture.result(fixture.submit_body("subscription.open", &body, deadline()));
    let current = reopened["subscription_generation"]
        .as_str()
        .expect("test: generation")
        .parse::<u64>()
        .expect("test: u64");
    assert!(current > old, "dispatcher assigns a fresh generation");
    shared.push_event(br#"{"late":true}"#.to_vec(), old);
    shared.push_event(br#"{"unassigned":true}"#.to_vec(), 0);
    // Exercise the independent poll fence, including bytes queued before a generation switch.
    {
        let mut events = shared.events.lock().expect("test: event queue");
        for generation in [old, 0] {
            let bytes = zeroize::Zeroizing::new(br#"{"stale":true}"#.to_vec());
            events.bytes += bytes.len();
            events.queue.push_back(super::state::Event { generation, bytes });
        }
    }
    let mut out = std::ptr::null_mut();
    assert_eq!(
        ramflux_v2_event_poll(fixture.handle, &raw mut out),
        24,
        "C layer never exports old or unassigned events"
    );
    assert!(out.is_null(), "discarded events allocate no buffer");
    shared.push_event(br#"{"current":true}"#.to_vec(), current);
    assert_eq!(ramflux_v2_event_poll(fixture.handle, &raw mut out), 0, "current event is exported");
    assert_eq!(take_buffer(out)["current"], true, "only current data crosses the C boundary");
}

#[test]
fn policy_refuses_unknown_sensitive_exports_and_oversized_operation_keys() {
    let fixture = Fixture::open();
    for (method, operation_id, expected) in [
        ("unknown.method", "bounded".to_owned(), 12),
        ("itest.bypass", "bounded".to_owned(), 1),
        ("account.export_agent_credentials", "bounded".to_owned(), 12),
        ("account.backup.export", "bounded".to_owned(), 12),
        ("account.list", "x".repeat(257), 1),
    ] {
        let request=serde_json::to_vec(&json!({"sdk_api":"account","method":method,"body":{},"operation_id":operation_id,"deadline_ms":deadline()})).expect("test: request");
        let mut operation = 99;
        assert_eq!(
            ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut operation),
            expected,
            "policy must refuse {method} before admission"
        );
        assert_eq!(operation, 0, "refusal cannot allocate credit");
    }
}

#[test]
fn failure_outputs_preserve_structured_codes_and_erase_diagnostics() {
    let shared = super::state::Shared::default();
    let op = std::sync::Arc::new(super::state::Operation::default());
    shared.operations.lock().expect("test: operations").insert(1, op.clone());
    shared.failed(1, &crate::SdkError::LocalBus("private/path and diagnostic".into()));
    let state = op.state.lock().expect("test: result");
    let bytes = state.result.as_ref().expect("test: terminal error");
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("test: typed JSON");
    assert!(value.get("message").is_none(), "SDK Display cannot cross the native boundary");
    drop(state);
    shared.complete(1,json!({"code":0,"response":{"error":{"code":"InvalidArgument","message":"private/path","retry_after_ms":null,"details":{"retryable":false}},"body":{"message":"User content","code":"user-field"},"event":{"error":{"code":"mcp_failure","message":"private/path"}},"receipt":{"object_id":"object","operation_id":"op","last_error":"private/path","state":"failed"}}}));
    let state = op.state.lock().expect("test: result");
    let value: serde_json::Value =
        serde_json::from_slice(state.result.as_ref().expect("test: completion"))
            .expect("test: JSON");
    assert!(
        value["response"]["error"].get("message").is_none(),
        "carrier diagnostics are stripped too"
    );
    assert_eq!(
        value["response"]["error"]["details"]["retryable"], false,
        "typed structured details survive"
    );
    assert!(
        value["response"]["event"]["error"].get("message").is_none(),
        "code/message-only event errors are sanitized"
    );
    assert!(
        value["response"]["receipt"]["last_error"].is_null(),
        "reconciliation diagnostics remain internal"
    );
    assert_eq!(
        value["response"]["receipt"]["last_error_code"], 16,
        "unknown diagnostic is not guessed into a retry class"
    );
    assert_eq!(
        value["response"]["body"]["message"], "User content",
        "business content is not an error string"
    );
}

#[test]
fn concurrent_opens_reserve_a_previously_missing_root() {
    let root = tempfile::tempdir().expect("test: root parent");
    let missing = root.path().join("new-root");
    let config = std::sync::Arc::new(
        serde_json::to_vec(&json!({"data_root":missing})).expect("test: config"),
    );
    let (finished, outcomes) = std::sync::mpsc::sync_channel(2);
    let mut workers = Vec::new();
    let mut starters = Vec::new();
    for _ in 0..2 {
        let (start, ready) = std::sync::mpsc::sync_channel(1);
        starters.push(start);
        let finished = finished.clone();
        let config = config.clone();
        workers.push(std::thread::spawn(move || {
            ready.recv_timeout(std::time::Duration::from_secs(5)).expect("test: concurrent start");
            let mut handle = 0;
            let code = ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut handle);
            let _ = finished.send((code, handle));
        }));
    }
    for start in starters {
        start.send(()).expect("test: start opens");
    }
    let mut codes = Vec::new();
    let mut handles = Vec::new();
    for _ in 0..2 {
        let (code, handle) = outcomes
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("test: bounded startup result");
        codes.push(code);
        // Keep the successful root reserved until BOTH open attempts have returned.
        if handle != 0 {
            handles.push(handle);
        }
    }
    for worker in workers {
        worker.join().expect("test: opener joined");
    }
    for handle in handles {
        assert_eq!(ramflux_v2_client_close(handle), 0, "winning opener closes");
    }
    assert_eq!(codes.iter().filter(|v| **v == 0).count(), 1, "exactly one root owner");
    assert_eq!(
        codes.iter().filter(|v| **v == 18).count(),
        1,
        "other opener gets typed AccountBusy"
    );
}

#[test]
fn closed_command_channel_returns_closed_before_atomic_shutdown_flags() {
    let root = tempfile::tempdir().expect("test: isolated supervisor");
    let mut client = super::runtime::Client::start(crate::LocalBusConfig::new("", root.path()))
        .expect("test: real supervisor");
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    drop(receiver);
    // Retain the original sender so the real supervisor remains live through the assertion.
    let original = std::mem::replace(
        &mut std::sync::Arc::get_mut(&mut client).expect("test: not registered yet").commands,
        sender,
    );
    let handle = super::exports::register_test_client(client.clone());
    assert!(
        !client.shared.closed.load(std::sync::atomic::Ordering::Acquire),
        "shutdown has not been reported"
    );
    let request = serde_json::to_vec(
        &json!({"sdk_api":"account","method":"account.list","body":{},"deadline_ms":deadline()}),
    )
    .expect("test: request");
    let mut operation = 99;
    assert_eq!(
        ramflux_v2_execute(handle, request.as_ptr(), request.len(), &raw mut operation),
        26,
        "a disconnected carrier is Closed even before shutdown flags change"
    );
    assert_eq!(operation, 0, "failed admission allocates no handle");
    assert!(
        client.shared.operations.lock().expect("test: credits").is_empty(),
        "failed send returns its operation credit"
    );
    assert_eq!(ramflux_v2_client_close(handle), 0, "real supervisor still shuts down normally");
    drop(original);
}
