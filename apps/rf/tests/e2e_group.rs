// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F3: three real accounts receive one generated group Message and its exact retryable Delete.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dump_logs,
    exchange_contacts, group_create, group_send, rf_json, start_daemon, unique, wait_group_texts,
    wait_json,
};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn f3_group_of_three_one_message_both_members_receive() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    let carol_d = start_daemon(&stack, "carol")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    configure_node(&carol_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    let carol = create_account(&carol_d, "Carol")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    exchange_contacts(&alice_d, &alice, &carol_d, &carol)?;
    exchange_contacts(&bob_d, &bob, &carol_d, &carol)?;
    let group = unique("e2e-group");
    group_create(&alice_d, &alice, &group, &[&bob, &carol])?;
    let body = "group hello on the real wire";
    group_send(&alice_d, &alice, &group, &group, "g-msg-1", body)?;
    let bob_view = wait_group_texts(&bob_d, &bob, &group, &group, &[body]).map_err(|error| {
        format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
    })?;
    let carol_view =
        wait_group_texts(&carol_d, &carol, &group, &group, &[body]).map_err(|error| {
            format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
        })?;
    assert_texts_once_in_order(&bob_view, &[body])?;
    assert_texts_once_in_order(&carol_view, &[body])?;
    let id = bob_view["messages"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|row| row["text"] == body).and_then(|row| row["id"].as_str())
        })
        .ok_or("test: generated group message id missing")?;
    let operation = unique("group-delete");
    let arguments = [
        "group",
        "message",
        "delete",
        "--account",
        &alice.id,
        "--group",
        &group,
        "--message",
        id,
        "--operation-id",
        &operation,
    ];
    let deletion = rf_json(&alice_d.socket, &arguments)?;
    for (daemon, account) in [(&bob_d, &bob), (&carol_d, &carol)] {
        let erased = wait_json(
            daemon,
            &[
                "group",
                "read",
                "--account",
                &account.id,
                "--group",
                &group,
                "--conversation",
                &group,
            ],
            |value| {
                value["messages"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| row["id"] == id && row["state"] == "tombstone")
                })
            },
        )
        .map_err(|error| {
            format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d, &carol_d]))
        })?;
        let row = erased["messages"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == id))
            .ok_or("test: group tombstone missing")?;
        assert_eq!(row["erasure"]["scope"], "everyone", "both members must receive peer erasure");
        assert_eq!(row["erasure"]["tombstone_id"], deletion["tombstone_id"]);
        assert!(row["text"].is_null() && row["content"].is_null(), "erasure must be content-free");
        assert!(!erased.to_string().contains(body), "group history cannot serve the erased body");
    }
    let retry = rf_json(&alice_d.socket, &arguments)?;
    assert_eq!(
        retry["delete_event_id"], deletion["delete_event_id"],
        "group retry retains one event"
    );
    assert_eq!(
        retry["tombstone_id"], deletion["tombstone_id"],
        "group retry retains one tombstone"
    );
    Ok(())
}
