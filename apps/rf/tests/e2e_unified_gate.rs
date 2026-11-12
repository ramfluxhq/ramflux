// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Whole-module gate for unified messages: real router, gateway and node services, two daemons
//! with separate stores, and only `rf` JSON as the observer. The rows need message schema v1 as
//! the active storage generation; on a dormant tree each row reports that and returns.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    Account, Daemon, boot_stack, configure_node, crash_daemon, create_account, dm_send, dump_logs,
    exchange_contacts, rf_json, start_daemon, start_daemon_at, unique, unlock_account_with_timeout,
    wait_json,
};
use serde_json::Value;
use std::time::Duration;

const SCHEMA: &str = "ramflux.message.read_model.v1";

fn dormant(row: &str) -> bool {
    let dormant = !ramflux_protocol::schema_profile::schema_v1_live();
    if dormant {
        eprintln!("unified gate row `{row}` not exercised: message schema v1 is dormant");
    }
    dormant
}

fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value.get(key).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn texts(value: &Value, key: &str) -> Vec<String> {
    rows(value, key)
        .iter()
        .filter_map(|row| row.get("text").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn row_with_text<'a>(value: &'a Value, key: &str, text: &str) -> Option<&'a Value> {
    rows(value, key).iter().find(|row| row.get("text").and_then(Value::as_str) == Some(text))
}

fn changes(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    after: u64,
) -> e2e::Result<Value> {
    rf_json(
        &daemon.socket,
        &[
            "dm",
            "list",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--after-seq",
            &after.to_string(),
        ],
    )
}

fn detail(daemon: &Daemon, account: &Account, conversation: &str, id: &str) -> e2e::Result<Value> {
    rf_json(
        &daemon.socket,
        &["dm", "list", "--account", &account.id, "--conversation", conversation, "--message", id],
    )
}

/// Sync through the real gateway until the durable change stream carries every expected text.
fn wait_synced(
    daemon: &Daemon,
    account: &Account,
    conversation: &str,
    expected: &[String],
) -> e2e::Result<Value> {
    wait_json(
        daemon,
        &[
            "dm",
            "read",
            "--account",
            &account.id,
            "--conversation",
            conversation,
            "--after-seq",
            "0",
        ],
        |value| {
            let got = texts(value, "changes");
            expected.iter().all(|text| got.contains(text))
        },
    )
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn unified_messages_survive_a_crash_and_a_backlog_beyond_the_delivery_page() -> e2e::Result<()> {
    if dormant("durable reader") {
        return Ok(());
    }
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("unified-dm");
    // More than the 64-entry in-memory delivery page of the generation-zero reader.
    let bodies = (0..70).map(|index| format!("unified body {index}")).collect::<Vec<_>>();
    for body in &bodies {
        dm_send(&alice_d, &alice, &bob, &conversation, &unique("msg"), body)?;
    }
    wait_synced(&bob_d, &bob, &conversation, &bodies)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;

    // Abrupt process death after commit: nothing may depend on memory of the old process.
    let (socket, root) = crash_daemon(bob_d)?;
    let bob_d = start_daemon_at(socket, root)?;
    unlock_account_with_timeout(&bob_d, &bob, Duration::from_secs(10))
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;

    // `dm list` performs no sync: every row below comes from the durable store alone.
    let mut cursor = 0;
    let mut served = Vec::new();
    for _ in 0..8 {
        let batch = changes(&bob_d, &bob, &conversation, cursor)?;
        assert_eq!(batch["schema"], SCHEMA);
        served.extend(texts(&batch, "changes"));
        let next = batch["next_after"].as_u64().ok_or("next_after missing")?;
        assert!(next >= cursor, "change cursor moved backwards: {batch}");
        cursor = next;
        if batch["more"] != true {
            break;
        }
    }
    for body in &bodies {
        assert_eq!(
            served.iter().filter(|text| *text == body).count(),
            1,
            "`{body}` must be served exactly once after the crash"
        );
    }
    let page = rf_json(
        &bob_d.socket,
        &["dm", "list", "--account", &bob.id, "--conversation", &conversation, "--limit", "100"],
    )?;
    assert_eq!(page["schema"], SCHEMA);
    assert_eq!(rows(&page, "messages").len(), bodies.len());
    assert!(page.get("gateway_entries").is_none() && page.get("decrypted_messages").is_none());
    let newest = rows(&page, "messages").first().ok_or("page empty")?;
    assert_eq!(newest["text"], bodies[bodies.len() - 1].as_str());
    assert_eq!(
        (newest["state"].as_str(), newest["kind"].as_str()),
        (Some("content"), Some("message"))
    );
    let id = newest["id"].as_str().ok_or("id missing")?;
    let single = detail(&bob_d, &bob, &conversation, id)?;
    assert_eq!(single["message"]["text"], newest["text"]);
    assert_eq!(single["message"]["revision"], 0);
    Ok(())
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn unified_receipt_and_delete_reach_the_peer_read_model() -> e2e::Result<()> {
    if dormant("receipt and erasure") {
        return Ok(());
    }
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("unified-dm");
    let body = "unified body to acknowledge and erase".to_owned();
    dm_send(&alice_d, &alice, &bob, &conversation, &unique("msg"), &body)?;
    let received = wait_synced(&bob_d, &bob, &conversation, std::slice::from_ref(&body))
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    let row = row_with_text(&received, "changes", &body).ok_or("received row missing")?;
    let id = row["id"].as_str().ok_or("id missing")?.to_owned();
    assert_eq!(row["is_own"], false);
    let cursor = received["next_after"].as_u64().ok_or("next_after missing")?;

    rf_json(
        &bob_d.socket,
        &[
            "dm",
            "receipt",
            "delivered",
            "--account",
            &bob.id,
            "--conversation",
            &conversation,
            "--message",
            &id,
            "--receiver-device",
            &bob.device_id,
        ],
    )?;
    wait_json(
        &alice_d,
        &["dm", "read", "--account", &alice.id, "--conversation", &conversation, "--message", &id],
        |value| {
            value["message"]["is_own"] == true
                && rows(&value["message"], "receipts")
                    .iter()
                    .any(|receipt| receipt["delivered_at"].is_i64())
        },
    )
    .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;

    rf_json(
        &alice_d.socket,
        &[
            "dm",
            "delete",
            "--account",
            &alice.id,
            "--conversation",
            &conversation,
            "--message",
            &id,
            "--scope",
            "everyone",
        ],
    )?;
    let after = cursor.to_string();
    let erased = wait_json(
        &bob_d,
        &[
            "dm",
            "read",
            "--account",
            &bob.id,
            "--conversation",
            &conversation,
            "--after-seq",
            &after,
        ],
        |value| rows(value, "changes").iter().any(|row| row["id"] == id.as_str()),
    )
    .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    let tombstone =
        rows(&erased, "changes").iter().find(|row| row["id"] == id.as_str()).ok_or("tombstone")?;
    assert_eq!(tombstone["state"], "tombstone");
    assert_eq!(tombstone["erasure"]["scope"], "everyone");
    assert!(tombstone["text"].is_null() && tombstone["content"].is_null());
    assert_eq!(rows(tombstone, "reactions").len() + rows(tombstone, "receipts").len(), 0);
    assert!(!erased.to_string().contains(&body), "erased body is still served: {erased}");
    let single = detail(&bob_d, &bob, &conversation, &id)?;
    assert_eq!(single["message"]["state"], "tombstone");
    assert!(!single.to_string().contains(&body));
    Ok(())
}

/// Real services and daemon restart surround a test-only mutation at the receiving
/// daemon's wire handoff. This is deliberately distinct from a router WAL mutation.
#[cfg(feature = "itest-rfd-fault")]
#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn unified_tampered_commitment_never_reaches_the_reader_after_restart() -> e2e::Result<()> {
    if dormant("tampered binding") { return Ok(()); }
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("unified-binding");
    let calibration = "untouched binding calibration".to_owned();
    dm_send(&alice_d, &alice, &bob, &conversation, &unique("good"), &calibration)?;
    wait_synced(&bob_d, &bob, &conversation, std::slice::from_ref(&calibration))?;
    let (socket, root) = crash_daemon(bob_d)?;
    let envelope = unique("tampered-binding");
    let secret = "tampered binding must never appear";
    dm_send(&alice_d, &alice, &bob, &conversation, &envelope, secret)?;
    let marker = stack.root.join("binding-injection.marker");
    let marker_text = marker.to_str().ok_or("marker path")?;
    let env = [
        ("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE", "dm-recv-tamper-binding"),
        ("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER", marker_text),
        ("RAMFLUX_SDK_ITEST_BINDING_ENVELOPE", envelope.as_str()),
    ];
    let bob_d = e2e::spawn_daemon_with_env(socket, root, &env)?;
    unlock_account_with_timeout(&bob_d, &bob, Duration::from_secs(10))?;
    e2e::wait_json(&bob_d, &["account", "status", "--account", &bob.id], |_| marker.exists())?;
    assert_tampered_absent(&bob_d, &bob, &conversation, &calibration, secret)?;
    let (socket, root) = crash_daemon(bob_d)?;
    std::fs::remove_file(&marker)?;
    let bob_d = e2e::spawn_daemon_with_env(socket, root, &env)?;
    unlock_account_with_timeout(&bob_d, &bob, Duration::from_secs(10))?;
    // The bad entry must be retried from durable state, never converted into a visible row.
    e2e::wait_json(&bob_d, &["account", "status", "--account", &bob.id], |_| marker.exists())?;
    assert_tampered_absent(&bob_d, &bob, &conversation, &calibration, secret)?;
    Ok(())
}

#[cfg(feature = "itest-rfd-fault")]
fn assert_tampered_absent(daemon: &Daemon, account: &Account, conversation: &str, calibration: &str, secret: &str) -> e2e::Result<()> {
    let page = rf_json(&daemon.socket, &["dm", "list", "--account", &account.id, "--conversation", conversation, "--limit", "100"])?;
    assert_eq!(page["schema"], SCHEMA);
    assert_eq!(texts(&page, "messages"), vec![calibration.to_owned()]);
    assert!(!page.to_string().contains(secret));
    let stream = changes(daemon, account, conversation, 0)?;
    assert_eq!(texts(&stream, "changes"), vec![calibration.to_owned()]);
    assert!(!stream.to_string().contains(secret));
    Ok(())
}
