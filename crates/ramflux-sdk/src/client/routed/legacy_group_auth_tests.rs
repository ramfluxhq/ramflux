// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy group transport must preserve the same device identity and member pins as routed v2.
use super::review::trust;
use super::*;
fn setup() -> Result<(Fixture, Fixture), SdkError> {
    let alice = Fixture::new("alice", 101)?;
    let bob = Fixture::new("bob", 111)?;
    trust(&bob, &alice)?;
    trust(&alice, &bob)?;
    fixture_group(&alice.client, "g", &alice)?;
    fixture_member(&alice.client, "g", &bob)?;
    bob.client.create_group("g", "bob")?;
    fixture_member(&bob.client, "g", &alice)?;
    bob.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &serde_json::json!({"kind":"group","group_id":"g"}),
    )?;
    bob.client.import_group_sender_key_distribution(
        &alice.client.export_group_sender_key_distribution("g", "alice")?,
    )?;
    Ok((alice, bob))
}
fn packet(sender: &Fixture, body: Vec<u8>, id: &str) -> Result<GatewayInboxEntry, SdkError> {
    let mut message = message(id, "thread");
    message.source_principal_id = sender.id.clone();
    message.sender_id = sender.id.clone();
    message.encrypted_body = body;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "bob".into(),
        envelope: gateway_direct_message_envelope(&sender.config()?, &message, None)?,
    })
}
#[test]
fn legacy_group_nonmembers_cannot_speak_as_a_pinned_member() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let mallory = Fixture::new("mallory", 121)?;
    trust(&bob, &mallory)?;
    let entry =
        packet(&mallory, alice.client.encrypt_group_message("g", "alice", b"forged")?, "forged")?;
    assert!(bob.client.legacy_group_binding("thread", "g", &entry)?);
    assert!(bob.client.authenticated_envelope_sender(&entry).is_ok());
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient("thread", "g", "forged", &entry, "bob")
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}
#[test]
fn legacy_group_current_members_cannot_claim_another_members_sender_id() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let carol = Fixture::new("carol", 131)?;
    trust(&bob, &carol)?;
    fixture_member(&bob.client, "g", &carol)?;
    let entry =
        packet(&carol, alice.client.encrypt_group_message("g", "alice", b"forged")?, "forged")?;
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient("thread", "g", "forged", &entry, "bob")
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}
#[test]
fn legacy_group_removed_members_cannot_reuse_old_epoch_keys() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let entry =
        packet(&alice, alice.client.encrypt_group_message("g", "alice", b"removed")?, "removed")?;
    bob.client.remove_group_member("g", "bob", "alice")?;
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient("thread", "g", "removed", &entry, "bob")
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}
#[test]
fn legacy_group_messages_require_an_authentic_outer_signature() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let mut entry =
        packet(&alice, alice.client.encrypt_group_message("g", "alice", b"forged")?, "forged")?;
    entry.envelope.signed.signature = ramflux_protocol::encode_base64url([0; 64]);
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient("thread", "g", "forged", &entry, "bob")
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}
#[test]
fn legacy_group_distribution_sender_is_bound_to_the_authenticated_device() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let mallory = Fixture::new("mallory", 141)?;
    trust(&bob, &mallory)?;
    let distribution = alice.client.export_group_sender_key_distribution("g", "alice")?;
    let body = serde_json::to_vec(&SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".into(),
        version: 1,
        distribution_base64: ramflux_protocol::encode_base64url(distribution),
        membership_event_base64: None,
        actor_manifest_url: None,
    })?;
    let conversation = group_sender_key_distribution_conversation_id("g", "mallory", "bob");
    let mut message = message("forged-distribution", &conversation);
    message.source_principal_id = "mallory".into();
    message.sender_id = "mallory".into();
    let bundle =
        bob.client.load_x3dh_private_state(&bob.client.local_device_identity("bob")?)?.bundle;
    let (mut session, x3dh) =
        mallory.client.create_send_dm_session_from_bundle(&message, "bob", bundle, "mallory")?;
    let encrypted = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        source_principal_commitment: None,
        x3dh,
        ciphertext: session.encrypt(&body, dm_associated_data(&conversation))?,
    })?;
    let entry = packet(&mallory, encrypted, "forged-distribution")?;
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient(
                "thread",
                "g",
                "forged-distribution",
                &entry,
                "bob"
            )
            .is_err()
    );
    Ok(())
}
#[test]
fn legacy_group_matching_pinned_member_remains_readable() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let entry = packet(
        &alice,
        alice.client.encrypt_group_message("g", "alice", b"legitimate")?,
        "legitimate",
    )?;
    let result = bob.client.append_group_gateway_delivery_for_recipient(
        "thread",
        "g",
        "legitimate",
        &entry,
        "bob",
    )?;
    assert!(matches!(result,GroupGatewayDeliveryResult::Message(bytes) if bytes==b"legitimate"));
    Ok(())
}

#[tokio::test]
async fn gateway_legacy_group_nonmembers_cannot_speak_as_a_pinned_member() -> Result<(), SdkError> {
    let (alice, bob) = setup()?;
    let mallory = Fixture::new("mallory", 151)?;
    trust(&bob, &mallory)?;
    let entry =
        packet(&mallory, alice.client.encrypt_group_message("g", "alice", b"forged")?, "forged")?;
    assert!(
        bob.client
            .append_group_gateway_delivery_for_recipient_with_gateway(
                &bob.config()?,
                "thread",
                "g",
                "forged",
                &entry,
                "bob"
            )
            .await
            .is_err()
    );
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}

#[test]
fn previously_parked_group_messages_cannot_claim_another_members_sender_id() -> Result<(), SdkError>
{
    let (alice, bob) = setup()?;
    let carol = Fixture::new("carol", 161)?;
    trust(&bob, &carol)?;
    fixture_member(&bob.client, "g", &carol)?;
    let body = alice.client.encrypt_group_message("g", "alice", b"forged pending")?;
    let group: SdkGroupEncryptedEnvelope = serde_json::from_slice(&body)?;
    let entry = packet(&carol, body, "pending-forged")?;
    bob.client.account_db()?.upsert_group_pending_undecrypted(&GroupPendingUndecryptedRecord {
        group_id: "g".into(),
        conversation_id: "thread".into(),
        group_key_epoch: group.group_key_epoch,
        message_id: "pending-forged".into(),
        sender_id: "alice".into(),
        inbox_seq: 1,
        envelope_json: serde_json::to_vec(&entry)?,
        created_at: now_unix_timestamp(),
    })?;
    assert_eq!(bob.client.retry_pending_group_messages("g", group.group_key_epoch)?.len(), 0);
    assert_eq!(bob.client.direct_messages("thread")?.len(), 0);
    Ok(())
}

#[path = "legacy_bootstrap_retry_tests.rs"]
mod bootstrap_retry;
