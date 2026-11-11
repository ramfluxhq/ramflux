// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live push, abrupt process death, offline sends, and durable resume with exact node ACKs.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, crash_daemon, create_account, dm_send,
    dump_logs, exchange_contacts, start_daemon, start_daemon_at, unique, unlock_account,
    wait_dm_texts, wait_node_observed_ack,
};

#[ignore = "real-process CLI e2e: run explicitly on QA and in the CLI e2e CI job"]
#[test]
fn e2e_push_restart() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = unique("push-restart");
    let bodies = ["push-one", "push-two", "push-three", "resume-one", "resume-two", "resume-three"];
    let ids: Vec<String> =
        (0..bodies.len()).map(|i| unique(&format!("push-restart-{i}"))).collect();
    // Observe push while the recipient process is alive, then kill it mid-conversation.
    for (id, body) in ids.iter().zip(&bodies).take(3) {
        dm_send(&alice_d, &alice, &bob, &conversation, id, body)?;
    }
    // Node ACKs precede any read request, so read-triggered catch-up cannot mask missing push.
    for id in ids.iter().take(3) {
        wait_node_observed_ack(&stack, &bob, id)?;
    }
    let live = wait_dm_texts(&bob_d, &bob, &conversation, &bodies[..3])?;
    assert_texts_once_in_order(&live, &bodies[..3])?;
    let (socket, root) = crash_daemon(bob_d)?;
    for (id, body) in ids.iter().zip(&bodies).skip(3) {
        dm_send(&alice_d, &alice, &bob, &conversation, id, body)?;
    }
    let bob_d = start_daemon_at(socket, root)?;
    unlock_account(&bob_d, &bob)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &bodies)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    assert_texts_once_in_order(&received, &bodies)?;
    for id in &ids {
        wait_node_observed_ack(&stack, &bob, id).map_err(|error| {
            format!(
                "missing ACK for {id}: {error}; logs={}",
                dump_logs(&stack, &[&alice_d, &bob_d])
            )
        })?;
    }
    Ok(())
}
