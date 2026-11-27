// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Invalid receipt targets preserve delivery integrity.
use super::{
    fixture::{self, Spec, TestResult},
    *,
};
#[test]
fn unknown_or_inbound_targets_cannot_poison_a_later_valid_delivery_receipt() -> TestResult {
    let root = runtime_tests::root("receipt-unknown-target");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    fixture::seed_pair(&a, &b)?;
    let source = a.client(None)?;
    source.send_direct_message("thread", "outgoing", &a.device, b"sent")?;
    source.send_direct_message("thread", "incoming", &b.device, b"received")?;
    for target in ["missing", "incoming", "outgoing"] {
        let event = SdkReceiptEventEnvelope {
            schema: "ramflux.sdk.receipt_event.v1".into(),
            version: 1,
            receipt_id: target.into(),
            event_seq: 1,
            nonce: target.into(),
            reader_device_id: b.device.clone(),
            event: SdkReceiptEventBody::Delivered {
                conversation_id: "thread".into(),
                message_id: target.into(),
                delivered_at: now_unix_timestamp(),
                receiver_device_id: b.device.clone(),
                scope: "e2ee_private".into(),
                ttl_seconds: 300,
            },
        };
        let result = source.apply_receipt_event_plaintext(
            &serde_json::to_vec(&event)?,
            &b.identity()?,
            "thread",
        );
        if target == "outgoing" {
            assert!(result?.is_some());
        } else {
            assert!(matches!(result, Err(SdkError::InboundRejected(_))));
            assert!(source.account_db()?.delivery_receipt("thread", &b.identity()?)?.is_none());
        }
    }
    let row = source.direct_message_by_id("outgoing")?.ok_or("outgoing")?;
    assert_eq!(row.receipts.len(), 1);
    assert_eq!(row.receipts[0].state, "delivered");
    drop(source);
    Ok(())
}

#[test]
fn equal_device_names_and_wire_ids_under_different_roots_have_independent_receipt_bindings()
-> TestResult {
    let root = runtime_tests::root("receipt-root-collision");
    let a = Spec::new(&root, "alice", 51);
    let b = Spec::new(&root, "bob", 61);
    let mut foreign = Spec::new(&root, "mallory", 71);
    foreign.device.clone_from(&b.device);
    let source = a.client(None)?;
    a.trust(&source, &b)?;
    a.trust(&source, &foreign)?;
    for (peer, conversation, logical) in
        [(&b, "thread-b", "logical-b"), (&foreign, "thread-m", "logical-m")]
    {
        source.send_direct_message(conversation, logical, &a.device, b"ciphertext")?;
        let mut message = a.message(peer, logical);
        message.envelope_id = "shared-wire".into();
        message.conversation_id = conversation.into();
        source.bind_outgoing_delivery(
            &a.identity()?,
            &message,
            &crate::client::routed::Kind::Direct,
        )?;
        assert_eq!(
            source.resolve_delivery_receipt_message(
                &peer.identity()?,
                conversation,
                "shared-wire"
            )?,
            logical
        );
    }
    assert!(
        source
            .resolve_delivery_receipt_message(&foreign.identity()?, "thread-b", "shared-wire")
            .is_err()
    );
    assert_eq!(
        source.resolve_delivery_receipt_message(&b.identity()?, "thread-b", "shared-wire")?,
        "logical-b"
    );
    drop(source);
    Ok(())
}
