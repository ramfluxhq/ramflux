// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F3: group of three accounts; one message; both members receive the body.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dump_logs,
    exchange_contacts, group_create, group_send, start_daemon, unique, wait_group_texts,
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
    assert_texts_once_in_order(&carol_view, &[body])
}
