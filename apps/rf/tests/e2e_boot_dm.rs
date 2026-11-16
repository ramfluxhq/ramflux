// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F1: two born-v3 accounts, contact cards, DM A→B, exact text, ACK visible to A.
#![cfg(all(any(unix, windows), feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dm_ack,
    dm_receipt_delivered, dm_send, dump_logs, envelope_id_from_read, exchange_contacts,
    inbox_seq_from_read, start_daemon, unique, wait_dm_receipt, wait_dm_texts,
    wait_node_observed_ack,
};

#[ignore = "cli e2e: CI job cli-e2e only; not a local lane gate"]
#[test]
fn f1_two_accounts_contact_dm_receive_ack() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = e2e::dm_conversation(&alice, &bob)?;
    let message = unique("msg");
    let body = "hello from Alice over the real wire";
    let sent = dm_send(&alice_d, &alice, &bob, &conversation, &message, body)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &[body])?;
    assert_texts_once_in_order(&received, &[body])?;
    let envelope = envelope_id_from_read(&sent).ok_or_else(|| {
        format!("receive JSON missing wire envelope_id; sent={sent} received={received}")
    })?;
    wait_node_observed_ack(&stack, &bob, &envelope).map_err(|error| {
        format!(
            "node ACK for envelope {envelope} missing after receive: {error}; logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
    })?;
    let inbox_seq = inbox_seq_from_read(&sent, &envelope).ok_or_else(|| {
        format!("receive JSON missing inbox_seq for {envelope}; received={received}")
    })?;
    // Default-on Push installs the receive ledger, so public `message.ack` /
    // `rf dm ack` is refused with receive_ledger_managed_ack (P25). The node
    // ACK is the engine ack_batch from live intake (wait_node_observed_ack).
    match dm_ack(&bob_d, &bob, &conversation, &envelope, Some(inbox_seq)) {
        Ok(_) => {}
        Err(error) if error.to_string().contains("receive_ledger_managed_ack") => {}
        Err(error) => {
            return Err(format!(
                "dm_ack envelope={envelope} message={message} received={received} error={error} logs={}",
                dump_logs(&stack, &[&alice_d, &bob_d])
            )
            .into());
        }
    }
    let logical = sent["message_id"].as_str().ok_or("sender canonical message identity missing")?;
    let receipt = dm_receipt_delivered(&bob_d, &bob, &conversation, logical).map_err(|error| {
        format!(
            "receipt delivered failed: {error}; logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
    })?;
    if receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
        return Err(format!("B receipt delivered was refused: {receipt}").into());
    }
    wait_dm_receipt(&alice_d, &alice, &conversation, logical, &bob)
        .map_err(|error| format!("{error}; logs={}", dump_logs(&stack, &[&alice_d, &bob_d])))?;
    // Reopen the receiving store and read the same body back. Linux already covers this
    // through the restart jobs; the Windows acceptance requires it in this test.
    #[cfg(windows)]
    {
        let (socket, data_root) = e2e::shutdown_daemon(bob_d)?;
        let bob_again = e2e::start_daemon_at(socket, data_root)?;
        e2e::unlock_account_without_wait(&bob_again, &bob)?;
        let persisted = wait_dm_texts(&bob_again, &bob, &conversation, &[body])?;
        assert_texts_once_in_order(&persisted, &[body])?;
    }
    Ok(())
}

#[ignore = "real-process Demo B B1 single-node: CLI e2e CI job"]
#[test]
fn b1_same_node_bidirectional_dm_uses_deliver_without_resume() -> e2e::Result<()> {
    let stack = boot_stack()?;
    let alice_d = start_daemon(&stack, "alice")?;
    let bob_d = start_daemon(&stack, "bob")?;
    configure_node(&alice_d, &stack.discovery_url)?;
    configure_node(&bob_d, &stack.discovery_url)?;
    let alice = create_account(&alice_d, "Alice")?;
    let bob = create_account(&bob_d, "Bob")?;
    exchange_contacts(&alice_d, &alice, &bob_d, &bob)?;
    let conversation = e2e::dm_conversation(&alice, &bob)?;
    for (sender_d, sender, recipient_d, recipient, body) in [
        (&alice_d, &alice, &bob_d, &bob, "B1 Alice to Bob"),
        (&bob_d, &bob, &alice_d, &alice, "B1 Bob to Alice"),
    ] {
        let before = e2e::wait_receive_settled(recipient_d, recipient)?;
        let ids = [unique("b1-first"), unique("b1-second")];
        let sent = ids
            .iter()
            .map(|id| dm_send(sender_d, sender, recipient, &conversation, id, body))
            .collect::<e2e::Result<Vec<_>>>()?;
        let logical = sent
            .iter()
            .map(|entry| entry["message_id"].as_str().ok_or("canonical sender identity missing"))
            .collect::<Result<Vec<_>, _>>()?;
        for id in &ids {
            wait_node_observed_ack(&stack, recipient, id)?;
        }
        let after = e2e::wait_receive_settled(recipient_d, recipient)?;
        assert!(
            e2e::receive_counter(&after, "deliver_frames")?
                > e2e::receive_counter(&before, "deliver_frames")?,
            "B1 must receive Deliver frames: before={before} after={after}"
        );
        for counter in ["resume_requests", "page_fetches", "catch_up_passes"] {
            assert_eq!(after[counter], before[counter], "B1 {counter}: {before} -> {after}");
        }
        wait_dm_texts(recipient_d, recipient, &conversation, &[body, body])?;
        for owner in [(sender_d, sender), (recipient_d, recipient)] {
            let view = e2e::rf_json(
                &owner.0.socket,
                &["dm", "read", "--account", &owner.1.id, "--conversation", &conversation],
            )?;
            for id in &logical {
                let rows =
                    view["messages"].as_array().ok_or("canonical message projection missing")?;
                let count = rows
                    .iter()
                    .filter(|row| {
                        row["message_id"].as_str().or_else(|| row["id"].as_str()) == Some(*id)
                    })
                    .count();
                assert_eq!(
                    count, 1,
                    "logical message id {id} must occur once in account {} canonical projection",
                    owner.1.id
                );
            }
        }
        let [first_sent, second_sent] = sent.as_slice() else {
            return Err("two sender transport entries required".into());
        };
        let [first_id, second_id] = ids.as_slice() else {
            return Err("two envelope IDs required".into());
        };
        let first = inbox_seq_from_read(first_sent, first_id)
            .ok_or("first node-assigned inbox sequence missing from submit result")?;
        let second = inbox_seq_from_read(second_sent, second_id)
            .ok_or("second node-assigned inbox sequence missing from submit result")?;
        // Background contact-control envelopes may legitimately interleave between two sends
        // (each new send authorization now waits for a fresh authority fetch); the two message
        // deliveries must still arrive in order, with no resume or page fetch (asserted above).
        assert!(second > first, "B1 Deliver sequences must increase: {first} -> {second}");
        assert!(
            e2e::receive_counter(&after, "last_acked_seq")?
                <= e2e::receive_counter(&after, "committed_cursor")?,
            "{after}"
        );
        eprintln!("B1 recipient={} before={before} after={after}", recipient.id);
    }
    Ok(())
}

#[ignore = "two-node harness calibration for the controller's post-demo federation module; CLI e2e CI job"]
#[test]
fn two_nodes_have_separate_identities_cas_and_stores() -> e2e::Result<()> {
    let a = e2e::boot_node("node-a", true)?;
    let b = e2e::boot_node("node-b", false)?;
    assert_ne!(a.node_id, b.node_id);
    assert_ne!(a.root, b.root);
    assert_ne!(a.admin_url, b.admin_url);
    for path in ["secrets/node-signing.key", "certs/ca.pem"] {
        assert_ne!(std::fs::read(a.root.join(path))?, std::fs::read(b.root.join(path))?);
    }
    for node in [&a, &b] {
        for service in ["ramflux-router", "ramflux-gateway"] {
            assert!(node.root.join("state").join(format!("{service}.redb")).is_file());
        }
    }
    Ok(())
}
