// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! MEDIA-LAYER-DECL-01: two real accounts befriend each other, each primary publishes its own
//! layer-4 declaration at activation, and a DM carrying an r4 media reference is accepted by
//! the sender and visible to the receiver. No seeded rows and no fallback representation.
#![cfg(all(any(unix, windows), feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    boot_stack, configure_node, create_account, dm_conversation, dump_logs, exchange_contacts,
    start_daemon, unique, wait_dm_texts, wait_json,
};
use serde_json::Value;

const MEDIA_REF: &str = include_str!("fixtures/media-dm/media-ref.json");
const OBJECT_ID: &str = "demo-b-b4-object";

fn media_row_present(value: &Value, body: &str) -> bool {
    value.to_string().contains(body) && value.to_string().contains(OBJECT_ID)
}

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn media_dm_between_two_current_accounts_needs_no_seeded_rows() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    // A contact card pins the exact authority head. Publishing the layer declaration advances
    // that head, so cards are taken only after both declarations are installed.
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob)] {
        wait_json(daemon, &["account", "status", "--account", account.id.as_str()], |value| {
            value["layer_declaration"]["state"] == "fresh"
        })?;
    }
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = dm_conversation(&alice, &bob)?;

    let media_dir = alice_d.data_root.join("media-dm-e2e");
    std::fs::create_dir_all(&media_dir)?;
    let media_path = media_dir.join("media-ref.json");
    assert!(MEDIA_REF.len() < 16 * 1024, "fixture must stay small and bounded");
    std::fs::write(&media_path, MEDIA_REF)?;
    let media_arg = media_path.to_str().ok_or("media path is not UTF-8")?;

    let message = unique("media");
    let body = "attachment over the real wire";
    let args = [
        "dm",
        "send",
        "--account",
        alice.id.as_str(),
        "--conversation",
        conversation.as_str(),
        "--message",
        message.as_str(),
        "--envelope",
        message.as_str(),
        "--source-principal",
        alice.principal_id.as_str(),
        "--sender",
        alice.device_id.as_str(),
        "--recipient-device",
        bob.device_id.as_str(),
        "--recipient-principal-commitment",
        bob.principal_commitment.as_str(),
        "--target",
        bob.target_delivery_id.as_str(),
        "--body",
        body,
        "--media-ref",
        media_arg,
    ];
    // wait_json retries a PeerUpgradeRequired refusal until its 90 s deadline, so a refusal
    // that never clears (no declaration ever published) fails this test with the daemon logs.
    let sent = wait_json(&alice_d, &args, |_| true).map_err(|error| {
        format!("media DM was refused: {error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d]))
    })?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &[body])?;
    if !media_row_present(&received, body) {
        return Err(format!("receiver lacks the media row: {received}; sent={sent}").into());
    }
    // Both primaries publish their own declaration through the real node.
    for (daemon, account) in [(&alice_d, &alice), (&bob_d, &bob)] {
        let status =
            wait_json(daemon, &["account", "status", "--account", account.id.as_str()], |value| {
                value["layer_declaration"]["state"] == "fresh"
            })?;
        assert_eq!(
            status["layer_declaration"]["max_layer"], 4,
            "the published declaration must be layer 4: {status}"
        );
    }
    Ok(())
}
