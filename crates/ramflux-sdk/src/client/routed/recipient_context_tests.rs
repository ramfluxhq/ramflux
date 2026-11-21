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
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{Fixture as Native, sibling_erasure, watchdog};
    use ramflux_protocol::message as g;
    watchdog::within(async {
        let alice = Native::new("recipient-copy-peer").await?;
        let mut primary = Native::new("recipient-copy-primary").await?;
        alice.accept_peer(&primary)?;
        primary.accept_peer(&alice)?;
        let mut receiver = primary.enroll_sibling("recipient-copy-target", "sibling").await?;
        alice.client.persist_observed_identity_directory_now(&primary.manifest)?;
        let directory = crate::client::native_test_support::directory::Directory::new(vec![
            primary.manifest.clone(),
            alice.manifest.clone(),
        ])
        .await?;
        directory.configure(&mut receiver);
        let conversation = g::dm_scope::derive(
            &alice.client.own_account_anchor()?,
            &primary.client.own_account_anchor()?,
        )?;
        let mut message = GatewayDirectMessage {
            conversation_id: conversation.clone(),
            message_id: "first-peer-operation".into(),
            envelope_id: "first-peer-envelope".into(),
            source_principal_id: alice.config.principal_id.clone(),
            sender_id: alice.config.device_id.clone(),
            recipient_device_id: Some(receiver.config.device_id.clone()),
            recipient_principal_commitment: Some(receiver.client.own_account_anchor()?),
            target_delivery_id: receiver.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: alice.client.content_ttl()?,
        };
        let prepared = alice.client.prepare_authored_message(
            &mut message,
            None,
            &g::Message { text: "hello both devices".into(), ..Default::default() },
        )?;
        let envelope =
            alice.seal_inner_to_with_id(&receiver, &prepared.wire, &message.envelope_id)?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 2,
            target_delivery_id: receiver.config.target_delivery_id.clone(),
            envelope: envelope.clone(),
        };
        assert!(
            matches!(
                receiver.client.authenticated_envelope_sender(
                    crate::client::identity_authority::HeadUse::NewAuthorization,
                    &entry
                ),
                Err(SdkError::InboundPending(_)
                    | SdkError::SenderManifestRequired { .. }
                    | SdkError::FreshHeadRequired { .. })
            ),
            "an uncached peer must wait for root authority rather than using a device label"
        );
        assert!(
            receiver
                .client
                .account_db()?
                .client_record("identity", &alice.manifest.principal_id)?
                .is_none()
        );
        assert!(receiver.client.direct_message_by_id(&message.message_id)?.is_none());
        sibling_erasure::contact(&primary, &alice, &mut receiver, &conversation).await?;
        receiver.receive(envelope, 2).await?;
        let view =
            receiver.client.generated_message_detail(&conversation, &message.message_id)?.message;
        assert_eq!(view.text.as_deref(), Some("hello both devices"));
        assert!(!view.is_own, "the peer cannot become an owned-device author");
        assert_eq!(
            view.author.ok_or("test: native peer author")?.account_anchor,
            alice.client.own_account_anchor()?
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test]
async fn a_peer_cannot_preclaim_a_future_own_copy_row_id()
-> crate::client::native_test_support::TestResult {
    use crate::client::native_test_support::{Fixture as Native, sibling_erasure, watchdog};
    use ramflux_protocol::message as g;
    watchdog::within(async {
        let mut primary = Native::new("own-preclaim-primary").await?;
        let mut peer = Native::new("own-preclaim-peer").await?;
        primary.accept_peer(&peer)?;
        peer.accept_peer(&primary)?;
        let conversation = g::dm_scope::derive(
            &primary.client.own_account_anchor()?, &peer.client.own_account_anchor()?
        )?;
        let (sent, original) = sibling_erasure::authored(
            &primary, &mut peer, &conversation, "original-owned-operation"
        ).await?;
        let mut receiver = primary.enroll_sibling("own-preclaim-target", "sibling").await?;
        peer.client.persist_observed_identity_directory_now(&primary.manifest)?;
        let directory = crate::client::native_test_support::directory::Directory::new(vec![primary.manifest.clone(), peer.manifest.clone()]).await?;
        directory.configure(&mut receiver);
        sibling_erasure::contact(&primary, &peer, &mut receiver, &conversation).await?;
        let mut preclaim = original.clone();
        preclaim.envelope_id = "peer-preclaim-envelope".into();
        preclaim.source_principal_id = peer.config.principal_id.clone();
        preclaim.sender_id = peer.config.device_id.clone();
        preclaim.recipient_device_id = Some(receiver.config.device_id.clone());
        preclaim.recipient_principal_commitment = Some(receiver.client.own_account_anchor()?);
        preclaim.target_delivery_id = receiver.config.target_delivery_id.clone();
        preclaim.encrypted_body.clear();
        let prepared = peer.client.prepare_authored_message(
            &mut preclaim, None, &g::Message { text: "peer preclaim attempt".into(), ..Default::default() }
        )?;
        assert_ne!(preclaim.message_id, original.message_id,
            "reusing another author's id as an operation token must allocate a different qualified event");
        receiver.receive(peer.seal_inner_to_with_id(
            &receiver, &prepared.wire, &preclaim.envelope_id
        )?, 2).await?;
        sibling_erasure::deliver(&primary, &mut receiver, sent.clone()).await?;
        sibling_erasure::deliver(&primary, &mut receiver, sent).await?;
        let own = receiver.client.generated_message_detail(&conversation, &original.message_id)?.message;
        let foreign = receiver.client.generated_message_detail(&conversation, &preclaim.message_id)?.message;
        assert!(own.is_own, "the original own copy must retain owned attribution");
        assert_eq!(own.author.ok_or("test: owned author")?.account_anchor, primary.client.own_account_anchor()?);
        assert_eq!(own.text.as_deref(), Some("SIBLING_DELETION_BODY_CANARY"));
        assert!(!foreign.is_own, "the peer cannot become an owned author");
        assert_eq!(foreign.text.as_deref(), Some("peer preclaim attempt"));
        assert_eq!(receiver.client.generated_message_view_page(&conversation, None, 10)?.messages.len(), 2,
            "peer operation labels and own-copy retries must retain two independent canonical rows");
        Ok::<_, Box<dyn std::error::Error>>(())
    }).await?
}
