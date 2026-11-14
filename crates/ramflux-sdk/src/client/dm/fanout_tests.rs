// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated fan-out preserves its first ciphertext and refuses changed content or scope.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult, watchdog};
use prost::Message as _;
use ramflux_protocol::message as g;

#[tokio::test(flavor = "current_thread")]
async fn fanout_preserves_one_row_and_refuses_changed_content_or_scope() -> TestResult {
    watchdog::within(async {
        let source = Fixture::new("fanout-sender").await?;
        let peer = Fixture::new("fanout-peer").await?;
        source.accept_peer(&peer)?;
        let scope = g::dm_scope::derive(
            &source.client.own_account_anchor()?,
            &peer.client.own_account_anchor()?,
        )?;
        let mut message = GatewayDirectMessage {
            conversation_id: scope.clone(),
            message_id: "logical-operation".into(),
            envelope_id: "device-one".into(),
            source_principal_id: source.config.principal_id.clone(),
            sender_id: source.config.device_id.clone(),
            recipient_device_id: Some(peer.config.device_id.clone()),
            recipient_principal_commitment: Some(peer.client.own_account_anchor()?),
            target_delivery_id: peer.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: 1,
            ttl: 300,
        };
        let prepared = source.client.prepare_authored_message(
            &mut message,
            None,
            &g::Message { text: "same text".into(), ..Default::default() },
        )?;
        source.client.project_authored_message(&message, &prepared.exact, b"cipher-one")?;
        source.client.project_authored_message(&message, &prepared.exact, b"cipher-two")?;
        let row = source.client.direct_message_by_id(&message.message_id)?.ok_or("logical row")?;
        assert_eq!(row.encrypted_body, b"cipher-one", "fan-out must keep its first ciphertext");
        assert_eq!(source.client.direct_messages(&scope)?.len(), 1);
        let mut changed = g::Inner::decode(prepared.exact.as_slice())?;
        let mut body = g::Message::decode(changed.body.as_slice())?;
        body.text = "changed".into();
        changed.body = body.encode_to_vec();
        assert!(matches!(
            source.client.project_authored_message(&message, &changed.encode_to_vec(), b"changed"),
            Err(SdkError::ReplayMismatch)
        ));
        message.conversation_id = "another-thread".into();
        assert!(
            source.client.project_authored_message(&message, &prepared.exact, b"changed").is_err()
        );
        message.conversation_id = scope.clone();
        message.sender_id = "another-sender".into();
        assert!(
            source.client.project_authored_message(&message, &prepared.exact, b"changed").is_err()
        );
        assert_eq!(
            source.client.account_db()?.message_content(&message.message_id)?,
            Some(prepared.exact.clone())
        );
        assert_eq!(source.client.direct_messages(&scope)?.len(), 1);
        Ok(())
    })
    .await?
}
