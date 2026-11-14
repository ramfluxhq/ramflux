// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Logical conversation fan-out preserves storage collision fences and the first ciphertext.
use super::*;
use std::sync::{Arc, atomic::AtomicBool};

#[test]
fn fanout_preserves_one_row_and_refuses_changed_content_or_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let source = crate::bus::runtime_tests::account(
        root.path(),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let client = &source.client;
    let mut message = GatewayDirectMessage {
        conversation_id: "thread".into(),
        message_id: "logical".into(),
        envelope_id: "device-one".into(),
        source_principal_id: "sender".into(),
        sender_id: "device-sender".into(),
        recipient_device_id: Some("peer-one".into()),
        recipient_principal_commitment: None,
        target_delivery_id: "peer-one".into(),
        encrypted_body: b"cipher-one".to_vec(),
        created_at: 1,
        ttl: 300,
    };
    client.project_conversation_fanout(&message, b"same text", true)?;
    client.account_db()?.store_message_content("thread", "logical", b"same text")?;
    message.encrypted_body = b"cipher-two".to_vec();
    message.recipient_device_id = Some("peer-two".into());
    assert!(
        client.project_conversation_fanout(&message, b"same text", false).is_err(),
        "raw send must retain its ciphertext collision fence"
    );
    client.project_conversation_fanout(&message, b"same text", true)?;
    let row = client.direct_message_by_id("logical")?.ok_or("local logical row absent")?;
    assert_eq!(
        row.encrypted_body, b"cipher-one",
        "fan-out must preserve the first physical ciphertext"
    );
    assert_eq!(
        client.direct_messages("thread")?.len(),
        1,
        "device fan-out must not duplicate timeline rows"
    );
    assert!(
        client.project_conversation_fanout(&message, b"changed", true).is_err(),
        "a logical id cannot claim different plaintext"
    );
    message.conversation_id = "another-thread".into();
    assert!(
        client.project_conversation_fanout(&message, b"same text", true).is_err(),
        "a logical id cannot cross conversation scope"
    );
    message.conversation_id = "thread".into();
    message.sender_id = "another-sender".into();
    assert!(
        client.project_conversation_fanout(&message, b"same text", true).is_err(),
        "a logical id cannot cross authenticated sender scope"
    );
    Ok(())
}
