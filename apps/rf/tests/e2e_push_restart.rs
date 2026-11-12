// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live push, abrupt process death, offline sends, and durable resume with exact node ACKs.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    boot_stack, configure_node, crash_daemon, create_account, dm_send, dump_logs,
    exchange_contacts, mesh_cursor, message_texts, rf_json, start_daemon, start_daemon_at, unique,
    unlock_account_with_timeout, wait_dm_texts, wait_dm_texts_with_timeout, wait_node_observed_ack,
    wait_node_pending,
};

use std::time::Duration;

#[ignore = "real-process CLI e2e: run explicitly on QA and in the CLI e2e CI job"]
#[test]
fn e2e_push_restart() -> e2e::Result<()> {
    eprintln!("push/restart: boot stack");
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    eprintln!("push/restart: exchange contacts");
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
    eprintln!("push/restart: await live node ACKs");
    for id in ids.iter().take(3) {
        wait_node_observed_ack(&stack, &bob, id)?;
    }
    let status = rf_json(&bob_d.socket, &["account", "status", "--account", &bob.id])?;
    assert_eq!(
        status["session_delivery_mode"], "push",
        "recipient must negotiate push before process death: {status}"
    );
    let live = wait_dm_texts(&bob_d, &bob, &conversation, &bodies[..3])?;
    assert_eq!(message_texts(&live), bodies[..3], "live push must contain exactly the sent set");
    eprintln!("push/restart: live push verified; crash recipient");
    let (socket, root) = crash_daemon(bob_d)?;
    for (id, body) in ids.iter().zip(&bodies).skip(3) {
        dm_send(&alice_d, &alice, &bob, &conversation, id, body)?;
    }
    eprintln!("push/restart: await offline node pending");
    wait_node_pending(&stack, &bob, &ids[3..])?;
    eprintln!("push/restart: restart and unlock recipient");
    let bob_d = start_daemon_at(socket, root)?;
    eprintln!("push/restart: recipient daemon ready; unlock and await networking");
    unlock_account_with_timeout(&bob_d, &bob, Duration::from_secs(10))
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    eprintln!("push/restart: recipient networking live; await resumed messages");
    let received =
        wait_dm_texts_with_timeout(&bob_d, &bob, &conversation, &bodies, Duration::from_secs(15))
            .map_err(|error| {
            format!(
                "{error}; node_cursor={:?}; recipient_status={:?}; logs={}",
                mesh_cursor(&stack, &bob.target_delivery_id),
                rf_json(&bob_d.socket, &["account", "status", "--account", &bob.id]),
                dump_logs(&stack, &[&alice_d, &bob_d])
            )
        })?;
    assert_eq!(message_texts(&received), bodies, "restart must contain exactly the full sent set");
    eprintln!("push/restart: full received set verified; await all ACKs");
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
