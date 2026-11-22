// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native participant and receipt admission uses authenticated roots despite copied device labels.
use crate::client::native_test_support::{Fixture, TestResult, sibling_erasure, watchdog};
use crate::client::routed::{Route, SealPair, SendMaterial};
use crate::{GatewayDirectMessage, GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::message as g;

#[tokio::test]
async fn a_friend_named_like_another_principal_cannot_write_or_ack_their_thread() -> TestResult {
    watchdog::within(exercise(false)).await?
}

#[tokio::test]
async fn a_qualified_device_address_is_not_a_principal_participant_alias() -> TestResult {
    watchdog::within(exercise(true)).await?
}

fn receipt(
    source: &Fixture,
    target: &g::MessageRef,
    state: g::ReceiptState,
) -> TestResult<g::Content> {
    let identity = source.client.owned_device_identity()?;
    Ok(g::Content {
        value: Some(g::content::Value::Receipt(g::Receipt {
            targets: vec![target.clone()],
            state: state.into(),
            at: u64::try_from(crate::time::now_unix_timestamp())?,
            receiver: Some(g::QualifiedDevice {
                account_anchor: identity.root_commitment().into(),
                device_id: identity.device_id().into(),
                device_epoch: source
                    .client
                    .device_branch
                    .as_ref()
                    .ok_or("test: native branch")?
                    .device_epoch,
            }),
        })),
    })
}

/// Construct a structurally valid sender-authenticated event for a claimed scope. The sender
/// controls this claim; only the receiver's immutable participant roots can authorize it.
fn claimed_scope(
    source: &Fixture,
    target: &Fixture,
    conversation: &str,
    content: &g::Content,
    operation: &str,
) -> TestResult<GatewayInboxEntry> {
    let identity = source.client.allocate_generated_identity(
        conversation,
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    let id = ramflux_protocol::encode_base64url(&identity.id);
    let exact = RamfluxClient::encode_generated_inner(identity, content)?;
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: id,
        envelope_id: operation.into(),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(target.client.own_account_anchor()?),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: source.client.content_ttl()?,
    };
    let material: SendMaterial = source.material_for(target)?;
    let route = if matches!(content.value, Some(g::content::Value::Receipt(_))) {
        Route::receipt()
    } else {
        Route::direct()
    };
    // The ordinary producer correctly refuses this claimed foreign scope. An
    // adversary can still seal and sign it with its own real pair credentials.
    let sealed = source.client.account_db()?.write_transaction(|| {
        let (mut session, header, bundle) = source.client.prepared_send_pair(
            &source.config,
            &message,
            material,
            crate::client::target_selection::kind_id_for_route(&route.kind),
        )?;
        source.client.seal_routed_with_route(
            &message,
            &exact,
            route,
            SealPair {
                local: &source.config.device_id,
                remote: target.client.owned_device_identity()?.storage_key(),
                session: &mut session,
                header,
                bundle,
            },
        )
    })?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(
        &crate::bus::connection_manager::SessionMetadata::sealing_config_for(&source.config)?,
        &mut message,
        sealed,
    )?;
    ramflux_node_core::check_entry_bound(&envelope)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
        envelope,
    })
}

fn assert_participant_refusal(error: Box<dyn std::error::Error>) -> TestResult {
    match error.downcast::<SdkError>().map_err(|error| error.to_string())?.as_ref() {
        SdkError::InboundRejected(reason) => assert!(
            reason.contains("participant") || reason.contains("root") || reason.contains("scope"),
            "test: outsider failed outside participant admission: {reason}"
        ),
        SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Authority, .. } => {}
        other => {
            return Err(
                format!("test: outsider failed outside participant admission: {other}").into()
            );
        }
    }
    Ok(())
}

async fn exercise(qualified_alias: bool) -> TestResult {
    let mut alice = Fixture::with_principal("participants-alice", "alice", "alice").await?;
    let mallory = Fixture::with_principal("participants-mallory", "bob", "mallory").await?;
    let principal = if qualified_alias {
        mallory.client.owned_device_identity()?.storage_key().to_owned()
    } else {
        "bob".into()
    };
    let mut bob = Fixture::with_principal("participants-bob", "bob", &principal).await?;
    for peer in [&bob, &mallory] {
        alice.accept_peer(peer)?;
        peer.accept_peer(&alice)?;
    }
    let conversation = g::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let unrelated = g::dm_scope::derive(
        &alice.client.own_account_anchor()?,
        &mallory.client.own_account_anchor()?,
    )?;
    sibling_erasure::authored(&mallory, &mut alice, &unrelated, "mallory-introduction").await?;
    sibling_erasure::authored(&bob, &mut alice, &conversation, "honest-incoming").await?;
    let (_, outgoing) =
        sibling_erasure::authored(&alice, &mut bob, &conversation, "honest-outgoing").await?;
    let reference = g::MessageRef {
        id: ramflux_protocol::decode_base64url(&outgoing.message_id)?,
        conversation_id: conversation.clone(),
        author_anchor: alice.client.own_account_anchor()?,
    };
    let before = serde_json::to_value(
        alice.client.generated_message_view_page(&conversation, None, 10)?.messages,
    )?;
    let attacks = [
        g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "forgery".into(),
                erasure_nonce: ramflux_crypto::random_32()?.to_vec(),
                ..Default::default()
            })),
        },
        receipt(&mallory, &reference, g::ReceiptState::ReceiptDelivered)?,
        receipt(&mallory, &reference, g::ReceiptState::ReceiptRead)?,
    ];
    for (index, content) in attacks.into_iter().enumerate() {
        let entry =
            claimed_scope(&mallory, &alice, &conversation, &content, &format!("outsider-{index}"))?;
        let error = alice
            .receive(entry.envelope, 10 + u64::try_from(index)?)
            .await
            .err()
            .ok_or("test: outsider wrote the victim conversation")?;
        assert_participant_refusal(error)?;
        assert_eq!(
            serde_json::to_value(
                alice.client.generated_message_view_page(&conversation, None, 10)?.messages
            )?,
            before,
            "outsider message/receipt must preserve the victim's complete durable view"
        );
    }
    let bob_identity = bob.client.owned_device_identity()?;
    let foreign = mallory.client.owned_device_identity()?;
    for (index, state) in
        [g::ReceiptState::ReceiptDelivered, g::ReceiptState::ReceiptRead].into_iter().enumerate()
    {
        let content = receipt(&bob, &reference, state)?;
        let entry = claimed_scope(
            &bob,
            &alice,
            &conversation,
            &content,
            &format!("honest-receipt-{index}"),
        )?;
        alice.receive(entry.envelope, 20 + u64::try_from(index)?).await?;
    }
    assert_receipts(&alice.client, &bob_identity, &foreign, &conversation, &outgoing.message_id)?;
    Ok(())
}

fn assert_receipts(
    client: &RamfluxClient,
    bob_identity: &ramflux_crypto::RootQualifiedDeviceRef,
    foreign: &ramflux_crypto::RootQualifiedDeviceRef,
    conversation: &str,
    message: &str,
) -> TestResult {
    let db = client.account_db()?;
    assert!(
        db.delivery_receipt(conversation, bob_identity)?.is_some(),
        "the genuine participant's delivered receipt must calibrate the path"
    );
    assert!(
        db.delivery_receipt(conversation, foreign)?.is_none(),
        "a copied device label cannot inherit another root's receipt"
    );
    assert_eq!(
        db.conversation_projection(conversation, Some(bob_identity))?
            .read_through_message_id
            .as_deref(),
        Some(message)
    );
    for identity in [None, Some(foreign)] {
        assert!(
            db.conversation_projection(conversation, identity)?.read_through_message_id.is_none(),
            "a private read receipt must remain scoped to the authenticated participant root"
        );
    }
    Ok(())
}
