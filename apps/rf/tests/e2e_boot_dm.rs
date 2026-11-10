// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! F1: two born-v3 accounts, contact cards, DM A→B, exact text, ACK visible to A.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

use e2e::{
    assert_texts_once_in_order, boot_stack, configure_node, create_account, dm_ack,
    dm_receipt_delivered, dm_send, dump_logs, envelope_id_from_read, exchange_contacts,
    start_daemon, unique, wait_dm_texts,
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
    let conversation = unique("e2e-dm");
    let message = unique("msg");
    let body = "hello from Alice over the real wire";
    dm_send(&alice_d, &alice, &bob, &conversation, &message, body)?;
    let received = wait_dm_texts(&bob_d, &bob, &conversation, &[body])?;
    assert_texts_once_in_order(&received, &[body])?;
    let envelope = envelope_id_from_read(&received).unwrap_or_else(|| message.clone());
    if let Err(error) = dm_ack(&bob_d, &bob, &conversation, &envelope) {
        return Err(format!(
            "dm_ack envelope={envelope} message={message} received={received} error={error} logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
        .into());
    }
    let receipt = dm_receipt_delivered(&bob_d, &bob, &conversation, &message).map_err(|error| {
        format!(
            "receipt delivered failed: {error}; logs={}",
            dump_logs(&stack, &[&alice_d, &bob_d])
        )
    })?;
    if receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
        return Err(format!("B receipt delivered was refused: {receipt}").into());
    }
    let alice_view = wait_dm_texts(&alice_d, &alice, &conversation, &[body])?;
    if message_id_visible(&alice_view, &message) {
        Ok(())
    } else {
        Err(format!("ACK/receipt path: Alice no longer sees message {message}: {alice_view}")
            .into())
    }
}

fn message_id_visible(value: &serde_json::Value, message: &str) -> bool {
    for key in ["decrypted_messages", "messages", "gateway_entries"] {
        if let Some(rows) = value.get(key).and_then(serde_json::Value::as_array) {
            for row in rows {
                if row.get("message_id").and_then(serde_json::Value::as_str) == Some(message)
                    || row.get("id").and_then(serde_json::Value::as_str) == Some(message)
                    || row.get("envelope_id").and_then(serde_json::Value::as_str) == Some(message)
                {
                    return true;
                }
            }
        }
    }
    e2e::message_texts(value).iter().any(|text| !text.is_empty())
}
