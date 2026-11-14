// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::runtime::{Client, Command};
use super::state::{self, MAX_FRAME_BYTES, MAX_OPERATIONS, Operation};
use super::*;
use crate::c_abi::RamfluxBuffer;
use crate::{LocalBusConfig, LocalBusFrame};
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) fn take_buffer(ptr: *mut RamfluxBuffer) -> Value {
    assert!(!ptr.is_null(), "successful bridge call must allocate its output");
    // SAFETY: the bridge returned a live uniquely owned buffer; read before releasing it.
    let buffer = unsafe { &*ptr };
    // SAFETY: bridge buffer contains exactly len readable bytes until released below.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    let value = serde_json::from_slice(bytes).expect("test: valid bridge JSON");
    ramflux_v2_buffer_free(ptr);
    value
}

pub(super) struct Fixture {
    root: tempfile::TempDir,
    pub(super) handle: u64,
}
impl Fixture {
    pub(super) fn open() -> Self {
        Self::configured(false)
    }
    pub(super) fn configured(with_node: bool) -> Self {
        Self::configured_exports(with_node, false)
    }
    pub(super) fn configured_exports(with_node: bool, allow: bool) -> Self {
        let root = tempfile::tempdir().expect("test: isolated data root");
        if with_node {
            seed_node(root.path());
        }
        let mut config = json!({"data_root":root.path()});
        if allow {
            config["allow_secret_exports"] = json!(true);
        }
        let config = serde_json::to_vec(&config).expect("test: config");
        let mut handle = 0;
        assert_eq!(
            ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut handle),
            0,
            "real in-process supervisor must start"
        );
        Self { root, handle }
    }
    pub(super) fn submit(&self, method: &str, deadline: u64) -> u64 {
        self.submit_body(method, &json!({}), deadline)
    }
    pub(super) fn submit_body(&self, method: &str, body: &Value, deadline: u64) -> u64 {
        let request = serde_json::to_vec(&json!({
            "sdk_api":"account","method":method,"body":body,"deadline_ms":deadline
        }))
        .expect("test: request");
        let mut operation = 0;
        assert_eq!(
            ramflux_v2_execute(self.handle, request.as_ptr(), request.len(), &raw mut operation),
            0,
            "request admission should succeed"
        );
        operation
    }
    pub(super) fn result(&self, operation: u64) -> Value {
        wait_result(self.handle, operation)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let outcome = ramflux_v2_client_close(self.handle);
        if !std::thread::panicking() {
            assert_eq!(outcome, 0, "supervisor must drain and release its writer");
        }
    }
}
pub(super) fn deadline() -> u64 {
    u64::try_from(super::super::current_millis())
        .expect("test: epoch millis")
        .saturating_add(30_000)
}

#[test]
fn negotiation_preserves_v1_and_publishes_supervisor_inventory() {
    assert_eq!(super::super::ramflux_sdk_abi_version_major(), 1, "v1 consumers retain their ABI");
    let mut buffer = std::ptr::null_mut();
    assert_eq!(ramflux_v2_negotiate(2, 0, &raw mut buffer), 0, "ABI v2 negotiation");
    let metadata = take_buffer(buffer);
    #[cfg(feature = "card-runtime")]
    assert_eq!(
        metadata["card_runtime"]["abi_major"],
        ramflux_card::HOST_ABI,
        "linked renderer must advertise its independent ABI"
    );
    #[cfg(not(feature = "card-runtime"))]
    assert!(metadata["card_runtime"].is_null(), "ordinary C ABI builds must omit the renderer");
    assert_eq!(
        metadata["message_schema_generation"],
        ramflux_protocol::schema_profile::ACTIVE_STORAGE_GENERATION
    );
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
        "conversation.edit",
        "conversation.react",
        "conversation.reply",
        "conversation.delete",
    ] {
        assert!(methods.contains(&json!(method)), "missing shared supervisor method {method}");
    }
    assert_eq!(ramflux_v2_negotiate(3, 0, &raw mut buffer), 3, "major mismatch is typed");
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
        serde_json::to_vec(&json!({"data_root":fixture.root.path()})).expect("test: config");
    let mut duplicate = 0;
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut duplicate),
        18,
        "second ABI client must not acquire the same data-root writer"
    );
    assert_eq!(ramflux_v2_client_close(fixture.handle), 0, "first writer closes");
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut duplicate),
        0,
        "close must release all database and root-lock owners"
    );
    assert_eq!(ramflux_v2_client_close(duplicate), 0, "replacement closes cleanly");
}

#[test]
fn expired_requests_have_no_effects_and_real_custody_is_reachable() {
    let fixture = Fixture::open();
    let expired = fixture.submit("account.list", 1);
    let result = fixture.result(expired);
    assert_eq!(result["code"], 10, "expired request must return typed Timeout");
    assert_eq!(result["effects"], "none", "pre-admission expiry cannot have effects");
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
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut id),
        1,
        "duplicate I-JSON keys must fail"
    );
    assert_eq!(id, 0, "failure cannot publish an operation handle");
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), MAX_FRAME_BYTES + 1, &raw mut id),
        1,
        "oversized input must be rejected without dereferencing it"
    );
}

#[test]
fn event_overflow_is_explicit_and_cannot_consume_completion_credit() {
    let shared = state::Shared::default();
    shared.operations.lock().expect("test: operations").insert(1, Arc::new(Operation::default()));
    shared.activate_generation(1, None);
    for _ in 0..=state::MAX_EVENTS {
        shared.push_event(b"{}".to_vec(), 1);
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
    seed_node(root.path());
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
            deadline_ms: None,
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
    assert_eq!(
        client.close().expect("test: close supervisor"),
        super::runtime::CloseResult::Done,
        "successful close must confirm real writer release"
    );
    assert!(
        crate::node::NodeStore::load(root.path(), &[])
            .expect("test: durable nodes")
            .profiles
            .contains_key("test"),
        "a cancelled pre-admission node removal must leave its durable node intact"
    );
}

#[test]
fn admitted_cancellation_preserves_the_supervisor_terminal_response() {
    let fixture = Fixture::configured(true);
    let id = fixture.submit_body("node.remove", &json!({"node_id":"test"}), deadline());
    let before = fixture.result(id);
    assert_eq!(before["code"], 0, "the admitted mutation must finish successfully");
    assert!(
        !crate::node::NodeStore::load(fixture.root.path(), &[])
            .expect("test: durable nodes")
            .profiles
            .contains_key("test"),
        "successful node removal must have real durable effects before cancellation"
    );
    assert_eq!(ramflux_v2_operation_cancel(fixture.handle, id), 0, "cancel an admitted waiter");
    let after = fixture.result(id);
    assert_eq!(
        before, after,
        "cancellation cannot turn an executed request into a no-effect result"
    );
    assert_eq!(ramflux_v2_operation_release(fixture.handle, id), 0, "release retained terminal");
}

#[test]
fn completed_operations_retain_credit_until_explicit_release() {
    let fixture = Fixture::open();
    let mut ids = Vec::new();
    for _ in 0..MAX_OPERATIONS {
        let id = fixture.submit("account.list", deadline());
        assert_eq!(fixture.result(id)["code"], 0, "real request completes while retaining credit");
        ids.push(id);
    }
    let request = serde_json::to_vec(&json!({"sdk_api":"account","method":"account.list",
        "body":{},"deadline_ms":deadline()}))
    .expect("test: request");
    let mut extra = 999;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut extra),
        15,
        "a full terminal map must reject admission with RateLimited"
    );
    assert_eq!(extra, 0, "rejection cannot publish a cancel handle");
    let first = ids.first().copied().expect("test: terminal handles");
    assert_eq!(
        ramflux_v2_operation_release(fixture.handle, first),
        0,
        "explicit release restores one credit"
    );
    let replacement = fixture.submit("account.list", deadline());
    assert_eq!(fixture.result(replacement)["code"], 0, "new request reuses released capacity");
}

#[test]
fn subscription_cancel_is_dispatched_and_allows_replacement() {
    let fixture = Fixture::open();
    let request = serde_json::to_vec(&json!({"sdk_api":"backup","method":"bus.subscribe",
        "body":{"topics":["account.backup.job.changed"]},"deadline_ms":deadline()}))
    .expect("test: backup subscription");
    let mut subscription = 0;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut subscription),
        0,
        "real daemon-scoped subscription must be admitted"
    );
    assert_eq!(
        fixture.result(subscription)["response"]["body"]["subscribed"],
        true,
        "the shared backup stream must acknowledge subscription"
    );
    assert_eq!(
        ramflux_v2_operation_cancel(fixture.handle, subscription),
        0,
        "subscription token must also be its cancellation handle"
    );
    let barrier = fixture.submit("subscription.close", deadline());
    assert_eq!(
        fixture.result(barrier)["response"]["body"]["subscribed"],
        false,
        "explicit close acknowledgement must follow the queued cancellation control"
    );
    assert_eq!(
        ramflux_v2_operation_release(fixture.handle, subscription),
        0,
        "subscription terminal is independently released"
    );
    let mut replacement = 0;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut replacement),
        0,
        "cancelled subscription cannot retain subscription credit"
    );
    assert_eq!(
        fixture.result(replacement)["code"],
        0,
        "replacement subscription uses the real stream"
    );
}

fn seed_node(root: &std::path::Path) {
    let profile: crate::NodeProfile = serde_json::from_value(json!({
        "node_id":"test","node_public_key":ramflux_crypto::public_key_base64url_from_seed([7;32]),
        "pin_source":"tofu","ca_cert_pem":"test-only CA",
        "gateway":{"quic_addr":"node.example.invalid:443","tcp_addr":"node.example.invalid:443","server_name":"node.example.invalid"},
        "relay":{"quic_addr":"node.example.invalid:443","server_name":"node.example.invalid"},
        "prekey_http_url":"https://node.example.invalid","discovered_at":1,"expires_at":2,
        "enabled":true,"builtin":false
    })).expect("test: bounded local node fixture");
    let mut store = crate::node::NodeStore::default();
    store.profiles.insert("test".to_owned(), profile);
    store.save(root).expect("test: seed isolated durable node store");
}

#[test]
fn compatibility_custody_envelopes_do_not_disconnect_the_bridge() {
    let fixture = Fixture::open();
    let id = fixture.submit("account.custody.cancel", deadline());
    let response = fixture.result(id);
    assert_eq!(response["code"], 0, "compatibility cancellation is a real SDK operation");
    assert_eq!(
        response["response"]["protocol"], "ramflux.local_bus.custody.v1",
        "compatibility response must preserve its original typed envelope"
    );
    let next = fixture.submit("account.list", deadline());
    assert_eq!(fixture.result(next)["code"], 0, "compatibility envelopes cannot close the carrier");
}

#[test]
fn shared_error_classes_keep_the_binding_numeric_contract() {
    for (error, expected) in [
        (crate::SdkError::DataRootInUse, 18),
        (crate::SdkError::NoNodeSelected, 9),
        (crate::SdkError::Transport(ramflux_transport::TransportError::NotAuthenticated), 5),
    ] {
        let name = crate::bus::io::local_bus_error_code(&error);
        assert_eq!(
            error_code(name),
            expected,
            "shared SDK classification {name} lost its binding code"
        );
    }
}

#[test]
fn every_operation_has_explicit_policy_and_generated_manifest_matches() {
    let policies = super::method_policy::METHOD_POLICIES;
    let classified =
        policies.iter().map(|policy| policy.name).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        classified.len(),
        policies.len(),
        "duplicate classifications cannot hide an operation"
    );
    let supported = crate::bus::inprocess::method_names()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        supported, classified,
        "every new SDK operation needs an explicit capability and secret policy"
    );
    for policy in policies {
        assert!(!policy.capability.is_empty(), "{} has no capability classification", policy.name);
        assert!(
            !policy.show_once || policy.secret_output,
            "{} cannot disclose a one-time value through an ordinary output",
            policy.name
        );
    }
    let checked: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/include/ramflux_sdk_methods.json"
    )))
    .expect("test: generated method policy JSON");
    assert_eq!(
        checked,
        super::method_policy::manifest(),
        "regenerate the checked method policy from SDK source"
    );
    for name in ["account.create.show_once", "account.custody.show_once"] {
        let policy = policies
            .iter()
            .find(|policy| policy.name == name)
            .expect("test: one-time disclosure policy");
        assert!(
            policy.show_once && policy.secret_output,
            "{name} must remain a one-time secret disclosure"
        );
    }
}

#[test]
fn close_timeout_retains_handle_until_real_supervisor_releases_writer() {
    struct ReleaseOnDrop(Arc<tokio::sync::Notify>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }
    let root = tempfile::tempdir().expect("test: isolated root");
    let (entered, entered_rx) = std::sync::mpsc::sync_channel(1);
    let release = ReleaseOnDrop(Arc::new(tokio::sync::Notify::new()));
    let client = Client::start_delayed(
        LocalBusConfig::new("", root.path()),
        super::runtime::ShutdownGate { entered, release: Arc::clone(&release.0) },
    )
    .expect("test: real supervisor with shutdown barrier");
    let handle = super::exports::register_test_client(Arc::clone(&client));
    let request = serde_json::to_vec(&json!({"sdk_api":"account","method":"account.list",
        "body":{},"deadline_ms":deadline()}))
    .expect("test: real indexed read");
    let mut operation = 0;
    assert_eq!(
        ramflux_v2_execute(handle, request.as_ptr(), request.len(), &raw mut operation),
        0,
        "real supervisor operation must be admitted before shutdown"
    );
    let completed = wait_result(handle, operation);
    assert_eq!(
        ramflux_v2_client_close(handle),
        10,
        "bounded initial wait must time out while the real supervisor holds its lease"
    );
    entered_rx.recv_timeout(Duration::from_secs(5)).expect("test: real shutdown reached barrier");
    assert_eq!(
        ramflux_v2_client_close(handle),
        24,
        "retry must remain pending rather than inventing successful close"
    );
    assert_eq!(
        wait_result(handle, operation),
        completed,
        "pending close must retain the operation's completed response"
    );
    assert_eq!(ramflux_v2_client_release(handle), 24, "a pending shutdown cannot be discarded");
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let (result, waiter) = client.test_holding_close_lock(|| {
        let waiter = std::thread::spawn(move || {
            let result = (ramflux_v2_client_close(handle), ramflux_v2_client_release(handle));
            let _ = sent.send(result);
        });
        (received.recv_timeout(Duration::from_secs(5)), waiter)
    });
    waiter.join().expect("test: poll worker");
    assert_eq!(
        result.expect("test: polling must not wait for the held mutex"),
        (24, 24),
        "both retry and release are nonblocking while another close owns completion state"
    );

    let config =
        serde_json::to_vec(&json!({"data_root":root.path()})).expect("test: replacement config");
    let mut replacement = 0;
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut replacement),
        18,
        "the actual data-root lock must refuse replacement while shutdown is pending"
    );
    assert!(
        matches!(
            crate::bus::data_root_lock::DataRootLock::acquire(root.path()),
            Err(crate::SdkError::DataRootInUse)
        ),
        "the real supervisor must still own its OS data-root lease at the shutdown barrier"
    );
    release.0.notify_one();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match ramflux_v2_client_close(handle) {
            0 => break,
            24 => assert!(
                Instant::now() < until,
                "supervisor failed to confirm release before test deadline"
            ),
            code => panic!("unexpected shutdown outcome {code}"),
        }
        std::thread::yield_now();
    }
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut replacement),
        0,
        "only confirmed shutdown permits replacement writer ownership"
    );
    assert_eq!(ramflux_v2_client_close(replacement), 0, "replacement must close normally");
}

pub(super) fn wait_result(handle: u64, operation: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut buffer = std::ptr::null_mut();
        let code = ramflux_v2_operation_poll(handle, operation, &raw mut buffer);
        if code == 0 {
            return take_buffer(buffer);
        }
        assert_eq!(code, RamfluxV2Status::Pending as i32, "poll must preserve its operation");
        assert!(Instant::now() < deadline, "real supervisor request exceeded test deadline");
        std::thread::yield_now();
    }
}

#[test]
fn daemon_stop_is_refused_before_supervisor_admission() {
    let fixture = Fixture::open();
    let request = serde_json::to_vec(
        &json!({"sdk_api":"daemon","method":"daemon.stop","body":{},"deadline_ms":deadline()}),
    )
    .expect("test: stop request");
    let mut id = 9;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut id),
        12,
        "native hosts close the supervisor with client_close"
    );
    assert_eq!(id, 0, "denied method allocates no operation");
    assert_eq!(
        fixture.result(fixture.submit("account.list", deadline()))["code"],
        0,
        "denied stop leaves the supervisor running"
    );
}

#[test]
fn stale_event_reset_cannot_clear_a_replacement_subscription() {
    let fixture = Fixture::open();
    let body = json!({"topics":["account.backup.job.changed"]});
    let first = fixture.submit_body("subscription.open", &body, deadline());
    let first_reply = fixture.result(first);
    let first_generation = first_reply["subscription_generation"]
        .as_str()
        .expect("test: exact generation")
        .parse::<u64>()
        .expect("test: generation integer");
    assert_eq!(ramflux_v2_operation_cancel(fixture.handle, first), 0, "cancel old stream");
    let barrier = fixture.submit("subscription.close", deadline());
    assert_eq!(fixture.result(barrier)["code"], 0, "real close barrier");
    assert_eq!(
        ramflux_v2_event_reset(fixture.handle, first_generation),
        0,
        "matching closed-generation reset"
    );
    let second = fixture.submit_body("subscription.open", &body, deadline());
    let second_reply = fixture.result(second);
    let second_generation = second_reply["subscription_generation"]
        .as_str()
        .expect("test: replacement generation")
        .parse::<u64>()
        .expect("test: generation integer");
    assert!(
        second_generation > first_generation,
        "real dispatcher must advance the account generation"
    );
    assert_eq!(
        ramflux_v2_event_reset(fixture.handle, first_generation),
        1,
        "stale reset cannot mutate the replacement queue"
    );
    assert_eq!(
        ramflux_v2_event_reset(fixture.handle, second_generation),
        0,
        "current-generation reset remains valid"
    );
}

#[test]
fn shared_directory_projection_preserves_order_visibility_and_totals() {
    let input = json!({"visible":true,"limit":"1","rows":[
        {"id":"b","title":"Recent","latest_ms":"10","unread":2,"attention":1},
        {"id":"p","title":"Pinned","pinned":true,"unread":3,"attention":0}
    ]});
    let encoded = serde_json::to_vec(&input).expect("test: authoritative row facts");
    let mut buffer = std::ptr::null_mut();
    assert_eq!(
        ramflux_v2_conversation_project(encoded.as_ptr(), encoded.len(), &raw mut buffer),
        0,
        "shared projection must run without a client or I/O"
    );
    let projected = take_buffer(buffer);
    assert_eq!(projected["rows"][0]["id"], "p", "the shared model orders pins before activity");
    assert_eq!(projected["next_offset"], 1, "shared pagination retains the snapshot offset");
    assert_eq!(
        projected["totals"]["unread"], "5",
        "navigation totals cover the entire visible snapshot"
    );
    let hidden = serde_json::to_vec(
        &json!({"visible":false,"rows":[{"id":"secret","title":"Secret","unread":4}]}),
    )
    .expect("test: locked snapshot");
    assert_eq!(
        ramflux_v2_conversation_project(hidden.as_ptr(), hidden.len(), &raw mut buffer),
        0,
        "locked projection is a successful empty presentation"
    );
    let projected = take_buffer(buffer);
    assert_eq!(projected["rows"], json!([]), "locked snapshots cannot expose cached rows");
    assert_eq!(projected["totals"]["unread"], "0", "locked snapshots cannot expose cached counts");
}

#[test]
fn shared_receipt_projection_never_invents_delivery_or_retry_permission() {
    let input = serde_json::to_vec(
        &json!({"outgoing":true,"receipt":{"state":"sent"},"now_ms":u64::MAX.to_string()}),
    )
    .expect("test: accepted receipt");
    let mut buffer = std::ptr::null_mut();
    assert_eq!(
        ramflux_v2_receipt_present(input.as_ptr(), input.len(), &raw mut buffer),
        0,
        "full-range clocks must cross the exact integer binding"
    );
    let projected = take_buffer(buffer);
    assert_eq!(
        projected["receipt"]["state"], "sent",
        "elapsed time cannot upgrade acceptance into delivery"
    );
    assert_eq!(
        projected["manual_retry"], false,
        "accepted operations cannot be manually duplicated"
    );
    let input =
        serde_json::to_vec(&json!({"outgoing":false,"receipt":{"state":"read"},"now_ms":"0"}))
            .expect("test: incoming receipt");
    assert_eq!(
        ramflux_v2_receipt_present(input.as_ptr(), input.len(), &raw mut buffer),
        0,
        "incoming receipt projection succeeds"
    );
    assert_eq!(
        take_buffer(buffer),
        Value::Null,
        "incoming messages have no outgoing receipt presentation"
    );
}

#[test]
fn native_clients_cannot_submit_raw_routing_without_explicit_capability() {
    let fixture = Fixture::open();
    let request = serde_json::to_vec(&json!({"sdk_api":"message","method":"message.submit",
        "body":{},"deadline_ms":deadline()}))
    .expect("test: raw request");
    let mut operation = 99;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, request.as_ptr(), request.len(), &raw mut operation),
        12,
        "raw message routing must be refused before carrier admission"
    );
    assert_eq!(operation, 0, "refused raw routing cannot allocate an operation");
}

#[cfg(feature = "card-runtime")]
#[test]
fn bundled_card_trust_verifies_and_renders_all_components() -> Result<(), Box<dyn std::error::Error>>
{
    let mut buffer = std::ptr::null_mut();
    assert_eq!(ramflux_v2_card_trust_package(&raw mut buffer), 0);
    let index = take_buffer(buffer);
    assert_eq!(index["card_abi_major"], 4);
    assert_eq!(index["release"]["app_id"], "ramflux.native");
    let decode = |name: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(ramflux_protocol::decode_base64url(
            index.get(name).and_then(Value::as_str).ok_or("binary field")?,
        )?)
    };
    let bytecode = decode("bytecode_base64url")?;
    let signature: [u8; 64] =
        decode("signature_base64url")?.try_into().map_err(|_| "signature length")?;
    let key: [u8; 32] = decode("trusted_key_base64url")?.try_into().map_err(|_| "key length")?;
    let descriptor = index["descriptor"].as_str().ok_or("descriptor")?.as_bytes();
    let policy: ramflux_card::AcceptancePolicy = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/include/card/policy.json"
    )))?;
    assert_eq!(policy.app_id, "ramflux.native");
    assert_eq!(policy.package_id, "ramflux.card.library");
    let package =
        ramflux_card::SignedPackage::verify(&bytecode, descriptor, &signature, &key, &policy)?;
    let fixtures: &[&[u8]] = &[
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ramflux-card/fixtures/complete_form.json"
        )),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../ramflux-card/fixtures/task.json")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../ramflux-card/fixtures/chart.json")),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ramflux-card/fixtures/approval.json"
        )),
    ];
    for input in fixtures {
        assert!(input.len() <= 8192, "bounded card fixture");
        let spec = ramflux_card::CardSpec::parse(input)?;
        let (_session, batch) = ramflux_card::CardSession::open(spec, package.clone())?;
        batch.mutations.first().ok_or("signed SDK library produced no semantic mutations")?;
    }
    for presentation in index["presentations"].as_object().ok_or("presentations")?.values() {
        ramflux_card::Presentation::parse(&serde_json::to_vec(presentation)?)?;
    }
    for (epoch, version) in
        [(policy.minimum_epoch + 1, 1), (policy.minimum_epoch, policy.minimum_version + 1)]
    {
        let stricter = ramflux_card::AcceptancePolicy {
            minimum_epoch: epoch,
            minimum_version: version,
            ..policy.clone()
        };
        assert!(
            ramflux_card::SignedPackage::verify(&bytecode, descriptor, &signature, &key, &stricter)
                .is_err(),
            "authentic lower epoch/version must fail the host release floor"
        );
    }
    let wrong_digest = ramflux_card::AcceptancePolicy {
        exact_descriptor_sha256: Some("00".repeat(32)),
        ..policy.clone()
    };
    assert!(
        ramflux_card::SignedPackage::verify(&bytecode, descriptor, &signature, &key, &wrong_digest)
            .is_err(),
        "authentic package must match the exact pinned descriptor"
    );
    let mut tampered = bytecode;
    let first = tampered.first_mut().ok_or("bytecode")?;
    *first ^= 1;
    assert!(
        ramflux_card::SignedPackage::verify(&tampered, descriptor, &signature, &key, &policy)
            .is_err()
    );
    assert!(
        ramflux_card::SignedPackage::verify(
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/include/card/library.qjb")),
            descriptor,
            &signature,
            &[0; 32],
            &policy
        )
        .is_err()
    );
    Ok(())
}
