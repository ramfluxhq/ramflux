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
    copy_fixture_private_prekeys(&staging, &receiver)?;
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
