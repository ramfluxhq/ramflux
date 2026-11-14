// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compare-and-record discovery refuses unknown contracts before any verify write.
use super::RamfluxV2Status;
use super::method_policy::{
    CONTACT_VERIFY_CAS_DESCRIPTOR, contact_verify_cas_inventory_admits,
    loaded_cas_descriptor_matches,
};
use super::runtime::Client;
use super::state;
use super::tests::{deadline, take_buffer};
use super::*;
use crate::LocalBusConfig;
use crate::c_abi::RamfluxErrorCode;
use serde_json::{Value, json};
use std::sync::Arc;

fn negotiate() -> Value {
    let mut buffer = std::ptr::null_mut();
    assert_eq!(ramflux_v2_negotiate(2, 0, &raw mut buffer), 0, "loaded library negotiation");
    take_buffer(buffer)
}

fn verify_row(inventory: &Value) -> Value {
    inventory["method_policy"]["methods"]
        .as_array()
        .expect("test: methods")
        .iter()
        .find(|row| row["name"] == "contact.verify")
        .expect("test: contact.verify row")
        .clone()
}

fn without_cas(inventory: &Value) -> Value {
    let mut legacy = inventory.clone();
    let methods = legacy["method_policy"]["methods"].as_array_mut().expect("test: methods");
    for row in methods.iter_mut().filter(|row| row["name"] == "contact.verify") {
        let object = row.as_object_mut().expect("test: row");
        object.insert("capability".to_owned(), json!("contact"));
        object.remove("cas_capability");
        object.remove("contract");
        object.remove("request_type");
        object.remove("response_type");
        object.remove("message_descriptor_blake3");
        object.remove("product_pin");
    }
    legacy
}

#[test]
fn verify_cas_v2_preserves_typed_refusal_and_reconciliation() {
    let inventory = negotiate();
    let methods = inventory["methods"].as_array().expect("test: method names");
    assert!(methods.iter().any(|method| method == "contact.verify"), "verify stays advertised");
    assert!(contact_verify_cas_inventory_admits(&inventory), "production inventory admits CAS");
    assert!(
        !contact_verify_cas_inventory_admits(&without_cas(&inventory)),
        "legacy inventory writes nothing"
    );
    let mut missing = inventory.clone();
    missing["method_policy"]["methods"]
        .as_array_mut()
        .expect("test: methods")
        .retain(|row| row["name"] != "contact.verify");
    assert!(!contact_verify_cas_inventory_admits(&missing), "missing verify is unavailable");
    let mut unknown = inventory.clone();
    unknown["method_policy"]["methods"]
        .as_array_mut()
        .expect("test: methods")
        .iter_mut()
        .filter(|row| row["name"] == "contact.verify")
        .for_each(|row| row["message_descriptor_blake3"] = json!("00"));
    assert!(!contact_verify_cas_inventory_admits(&unknown), "unknown digest is unavailable");
    let mut duplicate = inventory.clone();
    let row = verify_row(&inventory);
    duplicate["method_policy"]["methods"].as_array_mut().expect("test: methods").push(row);
    assert!(!contact_verify_cas_inventory_admits(&duplicate), "duplicate metadata is unavailable");
    assert!(loaded_cas_descriptor_matches(CONTACT_VERIFY_CAS_DESCRIPTOR));
    assert!(!loaded_cas_descriptor_matches("00"), "execute uses this predicate before submit");
    refuse_execute_and_reconcile();
    poll_resync_and_free();
}

fn refuse_real_account() {
    let created = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test: runtime")
        .block_on(crate::client::native_test_support::Fixture::new("cas-abi-refuse"))
        .expect("test: account");
    let root = created.root.0.clone();
    drop(created);
    let root_text = root.to_path_buf().display().to_string();
    let config = serde_json::to_vec(&json!({"data_root": root_text})).expect("test: config");
    let mut handle = 0;
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut handle),
        0,
        "supervisor opens the real account root"
    );
    let submit = |method: &str, body: Value| {
        let request = serde_json::to_vec(&json!({
            "account_id":"cas-abi-refuse",
            "sdk_api":"contact",
            "method":method,
            "body":body,
            "deadline_ms":deadline(),
        }))
        .expect("test: request");
        let mut operation = 0;
        assert_eq!(
            ramflux_v2_execute(handle, request.as_ptr(), request.len(), &raw mut operation),
            0,
            "admission does not write"
        );
        super::tests::wait_result(handle, operation)
    };
    let unlock = serde_json::to_vec(&json!({
        "account_id":"cas-abi-refuse",
        "sdk_api":"account",
        "method":"account.unlock",
        "body":{"passphrase":"native fixture data passphrase"},
        "deadline_ms":deadline(),
    }))
    .expect("test: unlock");
    let mut operation = 0;
    assert_eq!(ramflux_v2_execute(handle, unlock.as_ptr(), unlock.len(), &raw mut operation), 0);
    let unlocked = super::tests::wait_result(handle, operation);
    assert_eq!(unlocked["code"], 0, "real account unlock: {unlocked}");
    let missing = submit("contact.verify", json!({}));
    assert!(
        missing.to_string().contains("expected_safety_required"),
        "a real account keeps the typed refusal: {missing}"
    );
    let peer = ramflux_protocol::encode_base64url([9; 32]);
    let mismatch = submit(
        "contact.verify",
        json!({"expected":{
            "algorithm_version":2,
            "self_identity_commitment":peer,
            "contact_identity_commitment":peer,
            "safety_number_hash":"hash",
            "contact_device_set_hash":"devices",
            "contact_lineage_head":"lineage",
            "self_authority_head":"self-head",
            "contact_authority_head":"contact-head",
            "principal_id":"principal",
            "link_id":"missing-link"
        }}),
    );
    assert_ne!(mismatch["code"], 0, "mismatched material is not recorded: {mismatch}");
    assert_eq!(ramflux_v2_client_close(handle), 0, "real account supervisor releases its writer");
    let mut reader = crate::RamfluxClient::new();
    reader.open_account_index(&root).expect("test: index");
    reader.unlock_account("cas-abi-refuse", b"native fixture data passphrase").expect("test: read");
    let keys = reader
        .account_db()
        .expect("test: database")
        .actor_state_keys("identity/contact_safety_")
        .expect("test: keys");
    assert!(keys.is_empty(), "refusal writes no confirmation: {keys:?}");
}

fn refuse_execute_and_reconcile() {
    let fixture = super::tests::Fixture::open();
    let expired = serde_json::to_vec(&json!({
        "sdk_api":"contact","method":"contact.verify","body":{"expected":{}},"deadline_ms":1
    }))
    .expect("test: request");
    let mut operation = 7;
    assert_eq!(
        ramflux_v2_execute(fixture.handle, expired.as_ptr(), expired.len(), &raw mut operation),
        0,
        "an expired verify is admitted only as a no-effect waiter"
    );
    let expired_result = fixture.result(operation);
    assert_eq!(expired_result["code"], RamfluxErrorCode::Timeout as i32);
    assert_eq!(expired_result["effects"], "none");
    let refused = fixture.submit_body("contact.verify", &json!({"expected":{}}), deadline());
    let refused_result = fixture.result(refused);
    assert_ne!(refused_result["code"], 0, "an empty supervisor cannot record verification");
    refuse_real_account();
    assert_eq!(ramflux_v2_operation_cancel(fixture.handle, refused), 0, "cancel the waiter");
    assert_eq!(fixture.result(refused), refused_result, "cancel keeps the terminal refusal");
    assert_eq!(ramflux_v2_operation_release(fixture.handle, refused), 0);
    let mut missing = 4;
    assert_eq!(
        ramflux_v2_execute(0, expired.as_ptr(), expired.len(), &raw mut missing),
        RamfluxErrorCode::InvalidArgument as i32,
        "a changed handle never submits"
    );
    assert_eq!(missing, 0);
    reconcile_conflict();
}

fn committed_account()
-> (crate::custody::tests::Root, ramflux_protocol::message::ExpectedContactSafety) {
    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("test: runtime");
    runtime.block_on(async {
        let local = crate::client::native_test_support::Fixture::new("cas-abi-commit")
            .await
            .expect("test: account");
        let peer = crate::client::native_test_support::Fixture::new("cas-abi-peer")
            .await
            .expect("test: peer");
        local
            .client
            .persist_fetched_identity_directory(&peer.manifest)
            .expect("test: peer directory");
        let own = local.client.own_account_anchor().expect("test: anchor");
        let peer_root = peer.manifest.principal_commitment.clone();
        local.client.establish_friend_link("cas-abi-link", &own, &peer_root).expect("test: link");
        let expected = crate::client::contact_verification_cas::current_contact_safety_expectation(
            &local.client,
            &peer_root,
        )
        .expect("test: expectation");
        (local.root, expected)
    })
}

fn reconcile_conflict() {
    let (root, expected) = committed_account();
    let root_text = root.0.to_path_buf().display().to_string();
    let config = serde_json::to_vec(&json!({"data_root": root_text})).expect("test: config");
    let mut handle = 0;
    assert_eq!(
        ramflux_v2_client_open(config.as_ptr(), config.len(), &raw mut handle),
        0,
        "supervisor opens the committed account"
    );
    let unlock = serde_json::to_vec(&json!({
        "account_id":"cas-abi-commit",
        "sdk_api":"account",
        "method":"account.unlock",
        "body":{"passphrase":"native fixture data passphrase"},
        "deadline_ms":deadline(),
    }))
    .expect("test: unlock");
    let mut operation = 0;
    assert_eq!(ramflux_v2_execute(handle, unlock.as_ptr(), unlock.len(), &raw mut operation), 0);
    assert_eq!(super::tests::wait_result(handle, operation)["code"], 0, "unlock");
    let body = serde_json::to_value(ramflux_protocol::message::ContactSafetyVerifyRequest {
        expected: Some(expected.clone()),
    })
    .expect("test: verify body");
    let submit = |request_body: &Value| {
        let request = serde_json::to_vec(&json!({
            "account_id":"cas-abi-commit",
            "sdk_api":"contact",
            "method":"contact.verify",
            "body":request_body,
            "operation_id":"cas-op",
            "deadline_ms":deadline(),
        }))
        .expect("test: request");
        let mut operation = 0;
        assert_eq!(
            ramflux_v2_execute(handle, request.as_ptr(), request.len(), &raw mut operation),
            0
        );
        (operation, super::tests::wait_result(handle, operation))
    };
    let (committed_op, committed) = submit(&body);
    assert_eq!(committed["code"], 0, "compare-and-record commits: {committed}");
    assert!(
        committed.to_string().contains("verified"),
        "the committed result is verified: {committed}"
    );
    let (reconciled_op, reconciled) = submit(&body);
    assert_eq!(reconciled["code"], 0, "the same operation reconciles: {reconciled}");
    assert_eq!(
        reconciled["response"]["body"], committed["response"]["body"],
        "reconciliation returns the committed result"
    );
    let mut changed = expected;
    changed.safety_number_hash.push('x');
    let changed_body =
        serde_json::to_value(ramflux_protocol::message::ContactSafetyVerifyRequest {
            expected: Some(changed),
        })
        .expect("test: changed body");
    let (conflict_op, conflict) = submit(&changed_body);
    assert_eq!(
        conflict["code"],
        RamfluxErrorCode::InvalidArgument as i32,
        "a changed expectation under the same operation conflicts: {conflict}"
    );
    assert_eq!(
        conflict["response"]["error"]["code"], "ValidationFailed",
        "the bus publishes the operation mismatch as ValidationFailed"
    );
    let (replay_op, replay) = submit(&body);
    assert_eq!(replay["code"], 0, "the original body still reconciles: {replay}");
    assert_eq!(replay["response"]["body"], committed["response"]["body"]);
    assert_eq!(ramflux_v2_operation_cancel(handle, committed_op), 0, "cancel keeps the waiter");
    assert_eq!(
        super::tests::wait_result(handle, committed_op),
        committed,
        "cancel of a committed result does not rewrite it"
    );
    assert_eq!(ramflux_v2_operation_release(handle, committed_op), 0);
    assert_eq!(ramflux_v2_operation_release(handle, reconciled_op), 0);
    assert_eq!(ramflux_v2_operation_release(handle, conflict_op), 0);
    assert_eq!(ramflux_v2_operation_release(handle, replay_op), 0);
    assert_eq!(ramflux_v2_client_close(handle), 0);
}

fn poll_resync_and_free() {
    let root = tempfile::tempdir().expect("test: event root");
    let client = Client::start(LocalBusConfig::new("", root.path())).expect("test: supervisor");
    let handle = super::exports::register_test_client(Arc::clone(&client));
    client.shared.activate_generation(7, Some("cas".into()));
    for _ in 0..=state::MAX_EVENTS {
        client.shared.push_event(b"{}".to_vec(), 7);
    }
    let mut buffer = std::ptr::null_mut();
    assert_eq!(
        ramflux_v2_event_poll(handle, &raw mut buffer),
        RamfluxV2Status::ResyncRequired as i32,
        "event overflow requires a snapshot"
    );
    ramflux_v2_buffer_free(buffer);
    assert_eq!(ramflux_v2_client_close(handle), 0, "event client releases its writer");
}
