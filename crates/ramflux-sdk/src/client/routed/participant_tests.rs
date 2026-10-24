// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Principal participant gates and root-scoped receipt attribution resist literal device-name copies.
use super::review::{pool, trust};
use super::*;

fn outgoing(sender: &Fixture, receiver: &Fixture, id: &str) -> GatewayDirectMessage {
    let mut message = super::r5::outgoing(sender, receiver, id);
    message.conversation_id = "alice-bob".into();
    message
}
fn receipt(device: &str, id: &str) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(
        &serde_json::json!({"schema":"ramflux.sdk.receipt_event.v1","version":1,"receipt_id":id,"event_seq":1,"nonce":"nonce","reader_device_id":device,"event":{"type":"ReceiptDelivered","conversation_id":"alice-bob","message_id":"outgoing","delivered_at":1,"receiver_device_id":device,"scope":"device","ttl_seconds":3600}}),
    )?)
}
#[tokio::test]
async fn a_friend_named_like_another_principal_cannot_write_or_ack_their_thread()
-> Result<(), SdkError> {
    let mut alice = Fixture::new("alice", 11)?;
    let bob = Fixture::new("bob", 31)?;
    let mallory = Fixture::owned("bob", "mallory", 51, 52)?;
    trust(&alice, &bob)?;
    trust(&alice, &mallory)?;
    alice.client.establish_friend_link("bob-link", "alice", "bob")?;
    alice.client.establish_friend_link("mallory-link", "alice", "mallory")?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let mut introduction = outgoing(&mallory, &alice, "mallory-introduction");
    introduction.conversation_id = "alice-mallory".into();
    let introduction = seal(&mallory, &alice, introduction, b"legitimate friend thread")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &introduction, false).await?;
    let honest = seal(&bob, &alice, outgoing(&bob, &alice, "honest"), b"hello")?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &honest, false).await?;
    alice.client.send_direct_message("alice-bob", "outgoing", "alice", b"outgoing")?;
    let before = alice.client.direct_messages("alice-bob")?.len();
    let attack = seal(&mallory, &alice, outgoing(&mallory, &alice, "attack"), b"forgery")?;
    let error = alice
        .client
        .apply_routed_entry(&mut engine, &pool()?, &attack, false)
        .await
        .err()
        .ok_or_else(|| invalid("attack accepted"))?;
    assert!(error.to_string().contains("not a direct conversation participant"), "{error}");
    assert!(
        !alice.client.account_db()?.actor_state_exists(&super::super::committed_key(&attack)?)?
    );
    let ack = seal_as(
        &mallory,
        &alice,
        outgoing(&mallory, &alice, "attack-receipt"),
        &receipt("bob", "forged")?,
        Route::receipt(),
    )?;
    let error = alice
        .client
        .apply_routed_entry(&mut engine, &pool()?, &ack, false)
        .await
        .err()
        .ok_or_else(|| invalid("receipt accepted"))?;
    assert!(error.to_string().contains("not a conversation participant"), "{error}");
    assert!(!alice.client.account_db()?.actor_state_exists(&super::super::committed_key(&ack)?)?);
    assert_eq!(alice.client.direct_messages("alice-bob")?.len(), before);
    assert_eq!(alice.client.account_db()?.delivery_receipt("alice-bob", "bob")?, None);
    assert_eq!(
        alice.client.account_db()?.delivery_receipt("alice-bob", &mallory.reference()?)?,
        None
    );
    let read = serde_json::to_vec(
        &serde_json::json!({"schema":"ramflux.sdk.receipt_event.v1","version":1,"receipt_id":"forged-read","event_seq":1,"nonce":"nonce","reader_device_id":"bob","event":{"type":"ReceiptReadPrivate","conversation_id":"alice-bob","message_id":"outgoing","reader_identity":"bob","read_at":1,"own_device_scope":"device"}}),
    )?;
    let forged_read = seal_as(
        &mallory,
        &alice,
        outgoing(&mallory, &alice, "forged-read"),
        &read,
        Route::receipt(),
    )?;
    assert!(
        alice.client.apply_routed_entry(&mut engine, &pool()?, &forged_read, false).await.is_err()
    );
    for device in ["bob".to_owned(), bob.reference()?, mallory.reference()?] {
        assert_eq!(
            alice
                .client
                .account_db()?
                .conversation_projection("alice-bob", &device)?
                .read_through_message_id,
            None
        );
    }
    // Accepted receipts retain the authenticated root address, never the name shared by both roots.
    let honest_ack = seal_as(
        &bob,
        &alice,
        outgoing(&bob, &alice, "honest-receipt"),
        &receipt("bob", "honest")?,
        Route::receipt(),
    )?;
    alice.client.apply_routed_entry(&mut engine, &pool()?, &honest_ack, false).await?;
    assert!(alice.client.account_db()?.delivery_receipt("alice-bob", &bob.reference()?)?.is_some());
    assert_eq!(
        alice.client.account_db()?.delivery_receipt("alice-bob", &mallory.reference()?)?,
        None
    );
    assert_eq!(alice.client.account_db()?.delivery_receipt("alice-bob", "bob")?, None);
    assert_honest_read_is_root_scoped(&mut alice, &bob, &mallory, &mut engine, &read).await?;
    Ok(())
}

async fn assert_honest_read_is_root_scoped(
    alice: &mut Fixture,
    bob: &Fixture,
    mallory: &Fixture,
    engine: &mut GatewaySessionEngine,
    read: &[u8],
) -> Result<(), SdkError> {
    let honest_read =
        seal_as(bob, alice, outgoing(bob, alice, "honest-read"), read, Route::receipt())?;
    alice.client.apply_routed_entry(engine, &pool()?, &honest_read, false).await?;
    assert_eq!(
        alice
            .client
            .account_db()?
            .conversation_projection("alice-bob", &bob.reference()?)?
            .read_through_message_id
            .as_deref(),
        Some("outgoing")
    );
    for device in ["bob".to_owned(), mallory.reference()?] {
        assert_eq!(
            alice
                .client
                .account_db()?
                .conversation_projection("alice-bob", &device)?
                .read_through_message_id,
            None
        );
    }
    Ok(())
}
