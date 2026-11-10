// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F2: three DMs while B is down; after restart, all three arrive once, in order.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dm_send,
    exchange_contacts, shutdown_daemon, start_daemon, start_daemon_at, unique, unlock_account,
    wait_dm_texts,
};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn f2_restart_catchup_three_dms_once_in_order() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("e2e-resume");
    let (bob_socket, bob_root) = shutdown_daemon(bob_d)?;
    let bodies = ["resume-one", "resume-two", "resume-three"];
    for (index, body) in bodies.iter().enumerate() {
        dm_send(&alice_d, &alice, &bob, &conversation, &format!("msg-{index}"), body)?;
    }
    let bob_d = start_daemon_at(bob_socket, bob_root)?;
    unlock_account(&bob_d, &bob)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &bodies)?;
    assert_texts_once_in_order(&received, &bodies)
}
