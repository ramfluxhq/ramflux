// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy bus recipient names resolve only within accepted, root-authenticated contacts.
use super::*;
#[test]
fn unqualified_recipient_resolves_a_known_contact_and_rejects_ambiguous_accepted_roots()
-> Result<(), SdkError> {
    let alice = Fixture::new("alice", 11)?;
    let bob = Fixture::owned("shared", "bob", 21, 22)?;
    let mallory = Fixture::owned("shared", "mallory", 31, 32)?;
    review::trust(&alice, &bob)?;
    review::trust(&alice, &mallory)?;
    let bob_root = bob.client.owned_device_identity()?.root_commitment().to_owned();
    let mallory_root = mallory.client.owned_device_identity()?.root_commitment().to_owned();
    assert!(alice.client.trusted_recipient_root("shared").is_err());
    alice.client.establish_friend_link("bob-contact", "alice", &bob_root)?;
    assert_eq!(alice.client.trusted_recipient_root("shared")?, bob_root);
    alice.client.establish_friend_link("mallory-contact", "alice", &mallory_root)?;
    assert!(alice.client.trusted_recipient_root("shared").is_err());
    Ok(())
}

#[tokio::test]
async fn a_second_account_device_accepts_the_peer_only_after_an_authenticated_contact_copy()
-> Result<(), SdkError> {
    let alice = Fixture::owned("alice-device", "alice", 41, 42)?;
    let primary = Fixture::owned("bob-primary", "bob", 51, 52)?;
    let staging = Fixture::owned("bob-sibling", "bob", 51, 53)?;
    let receiver = Fixture::owned("bob-sibling", "bob", 51, 53)?;
    let mut outgoing = message("first-peer-after-activation", "peer-thread");
    outgoing.sender_id = alice.id.clone();
    outgoing.recipient_device_id = Some(receiver.id.clone());
    outgoing.target_delivery_id = receiver.id.clone();
    let entry = seal(&alice, &staging, outgoing, b"hello both devices")?;
    assert!(receiver.client.ensure_inbound_device(&receiver.config()?, &entry).await.is_err());
    assert!(receiver.client.account_db()?.client_record("identity", "alice")?.is_none());
    let manifest = crate::client::identity_authority::test_support::manifest(&alice.client)?;
    primary.client.establish_friend_link(
        "accepted-on-primary",
        primary.client.owned_device_identity()?.root_commitment(),
        &manifest.principal_commitment,
    )?;
    let link = primary.client.account_db()?.friend_link("accepted-on-primary")?;
    let mut body = b"ramflux.own_contact.v1\n".to_vec();
    body.extend(serde_json::to_vec(&serde_json::json!({"manifest":manifest,"link":link}))?);
    // This dispatch follows the active sibling signature/owned-root checks in receive_own_device_message.
    assert!(receiver.client.receive_own_contact(&body)?);
    receiver.client.ensure_inbound_device(&receiver.config()?, &entry).await?;
    assert_eq!(&*receiver.client.open_routed(&entry, &receiver.id)?.body, b"hello both devices");
    Ok(())
}

#[test]
fn a_peer_cannot_preclaim_a_future_own_copy_row_id() -> Result<(), SdkError> {
    let primary = Fixture::owned("alice-primary", "alice", 51, 52)?;
    let reference = Fixture::owned("alice-sibling", "alice", 51, 53)?;
    let receiver = Fixture::owned("alice-sibling", "alice", 51, 53)?;
    let peer = Fixture::new("mallory", 61)?;
    let source = primary.client.owned_device_identity()?;
    let mut bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&serde_json::json!({
        "envelope_id":"own-envelope","message_id":"own-authored","sender_id":"alice-primary",
        "context":{"conversation_id":"own-thread","participants":["alice","mallory"],"group":null,"friend":null},
        "body_base64":ramflux_protocol::encode_base64url(b"genuine outgoing text")
    }))?);
    let apply = |client: &RamfluxClient| {
        client.receive_own_sent_message(
            &source,
            crate::client::own_device_copy::OwnMessageInput {
                id: "own-envelope",
                conversation: "own-thread",
                group: None,
                created_at: 1,
                body: &bytes,
            },
        )
    };
    assert!(apply(&reference.client)?);
    let expected = reference.client.direct_messages("own-thread")?[0].message_id.clone();
    // The peer knows the exact future id before the own-device packet reaches this receiver.
    let mut outgoing = message(&expected, "peer-thread");
    outgoing.source_principal_id = "mallory".into();
    outgoing.sender_id = peer.id.clone();
    outgoing.recipient_device_id = Some(receiver.id.clone());
    outgoing.target_delivery_id = receiver.id.clone();
    let entry = seal(&peer, &receiver, outgoing, b"peer preclaim")?;
    let peer_id = receiver.client.projection_id(&entry)?;
    assert_ne!(peer_id, expected, "a peer must not reserve a future own-copy identifier");
    receiver.client.send_direct_message("peer-thread", &peer_id, &peer.reference()?, &[])?;
    receiver.client.account_db()?.store_message_content(
        "peer-thread",
        &peer_id,
        b"peer preclaim",
    )?;
    assert!(apply(&receiver.client)?);
    assert_eq!(receiver.client.direct_messages("own-thread")?.len(), 1);
    assert_eq!(
        receiver.client.account_db()?.message_content(&expected)?.as_deref(),
        Some(b"genuine outgoing text".as_slice())
    );
    assert_eq!(
        receiver.client.account_db()?.message_content(&peer_id)?.as_deref(),
        Some(b"peer preclaim".as_slice())
    );
    Ok(())
}
