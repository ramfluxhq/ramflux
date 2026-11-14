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
    let fixture = Fixture::configured_exports(false, false);
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
    let mut completion = json!({"code":1,"message":"private/path","response":{"kind":"error","method":"conversation.edit","error":{"code":"edit_conflict","message":"private/path","details":{"target":"target","expected":1,"received":2,"reason":"private/path"}},"body":{"code":7,"name":"edit_conflict","message":"private/path","details":{"target":"target","expected":1,"received":2}}}});
    super::native_error::completion(&mut completion);
    assert!(completion.get("message").is_none(), "completion diagnostics stay internal");
    assert!(
        completion["response"]["error"].get("message").is_none(),
        "error envelope diagnostics stay internal"
    );
    assert!(
        completion["response"]["error"]["details"].get("reason").is_none(),
        "adapter details cannot smuggle a diagnostic string"
    );
    assert_eq!(
        completion["response"]["error"]["details"]["expected"], 1,
        "typed conflict facts survive"
    );
    let mut business = json!({"code":0,"response":{"kind":"response","method":"account.config.get","body":{"code":7,"name":"custom","message":"User content","error":{"code":1,"message":"User error content"}}}});
    let expected = business.clone();
    super::native_error::completion(&mut business);
    assert_eq!(
        business, expected,
        "business payloads are never recursively scrubbed by field patterns"
    );
    for (method, body) in [
        ("object.transfer.status", json!({"transfer":{"last_error":"private/path","attempts":2}})),
        (
            "object.directory",
            json!({"objects":[{"last_error":"private/path","name":"User attachment"}]}),
        ),
    ] {
        let mut response = json!({"kind":"response","method":method,"body":body});
        super::native_error::frame(&mut response);
        assert!(
            !response.to_string().contains("private/path"),
            "typed transfer diagnostics stay internal"
        );
        if method == "object.directory" {
            assert_eq!(
                response["body"]["objects"][0]["name"], "User attachment",
                "user-authored attachment name survives"
            );
        }
    }
    let mut event = json!({"kind":"event","method":"mcp.tool.failed","body":{"error":{"code":"failed","message":"private/path"}}});
    super::native_error::frame(&mut event);
    assert!(
        event["body"]["error"].get("message").is_none(),
        "typed SDK event diagnostic is not peer data"
    );
}

#[test]
fn concurrent_opens_reserve_a_previously_missing_root() {
    let root = tempfile::tempdir().expect("test: root parent");
    let missing = root.path().join("new-root");
    let config = std::sync::Arc::new(
        serde_json::to_vec(&json!({"data_root":missing,"allow_secret_exports":true}))
            .expect("test: config"),
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
    client.shared.allow_secret_exports.store(true, std::sync::atomic::Ordering::Release);
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

#[test]
fn every_secret_output_policy_row_requires_explicit_host_capability() {
    let fixture = Fixture::configured_exports(false, false);
    for policy in super::method_policy::METHOD_POLICIES.iter().filter(|row| row.secret_output) {
        let request=serde_json::to_vec(&json!({"sdk_api":policy.capability,"method":policy.name,"body":{},"deadline_ms":deadline()})).expect("test: classified operation");
        let mut operation = 99;
        assert_eq!(
            ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut operation),
            12,
            "secret-output method {} must require explicit opt-in",
            policy.name
        );
        assert_eq!(operation, 0, "denied export allocates no operation");
    }
}

#[test]
fn rejected_complex_schema_and_cancelled_inputs_wipe_sdk_canary_allocations() {
    use crate::bus::secrets::canary;
    let fixture = Fixture::open();
    let inputs = [
        json!({"sdk_api":"account","method":"account.unlock","body":{"a_secret":canary::TEXT,"z_complex":vec![0;4096]},"deadline_ms":deadline()}),
        json!({"sdk_api":"account","method":7,"body":{"passphrase":canary::TEXT},"deadline_ms":deadline()}),
    ];
    for input in inputs {
        let bytes = serde_json::to_vec(&input).expect("test: rejected input");
        let mut operation = 99;
        canary::enable();
        assert_eq!(
            ramflux_v2_execute(fixture.handle, bytes.as_ptr(), bytes.len(), &raw mut operation),
            1,
            "invalid input is rejected before admission"
        );
        let (count, zeroed) = canary::finish();
        assert!(
            count > 0 && zeroed,
            "all observed SDK-owned canary buffers are zeroed while still allocated"
        );
        assert_eq!(operation, 0, "rejection has no operation handle");
    }
    let bytes=serde_json::to_vec(&json!({"sdk_api":"account","method":"account.unlock","body":{"passphrase":canary::TEXT},"deadline_ms":1})).expect("test: expiring input");
    let mut operation = 0;
    canary::enable();
    assert_eq!(
        ramflux_v2_execute(fixture.handle, bytes.as_ptr(), bytes.len(), &raw mut operation),
        0,
        "valid request reaches its bounded waiter"
    );
    assert_eq!(
        ramflux_v2_operation_cancel(fixture.handle, operation),
        0,
        "cancel shares the operation handle"
    );
    let result = fixture.result(operation);
    let (count, zeroed) = canary::finish();
    assert!(count > 0 && zeroed, "cancellation retains input/encoding wipe guarantees");
    assert!(
        matches!(result["code"].as_i64(), Some(10 | 25)),
        "expired/cancelled request cannot reach business execution"
    );
    assert_eq!(
        ramflux_v2_operation_release(fixture.handle, operation),
        0,
        "cancelled operation releases credit"
    );
}
