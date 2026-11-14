// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group data-plane key ownership and automatic restore/upgrade recovery regressions.
use super::r5::{fresh, outgoing};
use super::review::{pool, trust};
use super::session_record::{Wire, active, last};
use super::*;
use serde_json::json;
pub(super) fn manifest(f: &Fixture) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    f.manifest()
}
fn forged_group_traffic(sender: &Fixture) -> Result<(Vec<u8>, Vec<u8>), SdkError> {
    let group = "pinned";
    let epoch = sender.client.group_state(group)?.group_epoch;
    let seed = [0x91; 32];
    let mut session = ramflux_crypto::DmSession::initiator(
        seed,
        crate::group::group_sender_device_hash(group, "alice", "local"),
        crate::group::group_sender_device_hash(group, "alice", "remote"),
        crate::group::group_sender_transcript_hash(group, "alice", epoch),
    )?;
    let ciphertext = session.encrypt(
        b"forged group content",
        &crate::group::group_associated_data(group, "alice", epoch),
    )?;
    let distribution = crate::group::SdkGroupSenderKeyDistribution {
        schema: "ramflux.sdk.group_sender_key.distribution.v2".into(),
        version: 2,
        group_id: group.into(),
        sender_id: "alice".into(),
        group_key_epoch: epoch,
        group_state_hash: None,
        sender_key_seed: seed,
        sender_key_signature: None,
        sender_device_signing_public_key: Some(
            manifest(sender)?.devices[0].branch_public_key.clone(),
        ),
    };
    let body = crate::group::SdkGroupEncryptedEnvelope {
        schema: "ramflux.sdk.group_sender_key.message.v1".into(),
        version: 1,
        group_id: group.into(),
        sender_id: "alice".into(),
        group_key_epoch: epoch,
        group_state_hash: None,
        ciphertext,
    };
    Ok((serde_json::to_vec(&distribution)?, serde_json::to_vec(&body)?))
}
async fn replaced_key_traffic(cross_principal: bool) -> Result<(), SdkError> {
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    bob.client.create_group("pinned", "bob")?;
    fixture_member(&bob.client, "pinned", &alice)?;
    let original = manifest(&alice)?;
    bob.client.account_db()?.persist_group_member_device_key(
        "pinned",
        &crate::client::identity_authority::test_support::group_device(
            &bob.client,
            "pinned",
            "alice",
        )?,
        &original.devices[0].branch_public_key,
    )?;
    bob.client.account_db()?.bind_group_member_key_identity(
        "pinned",
        &crate::client::identity_authority::test_support::group_device(
            &bob.client,
            "pinned",
            "alice",
        )?,
        "alice",
        &original.principal_commitment,
        &original.devices[0].branch_public_key,
    )?;
    let principal = if cross_principal { "mallory" } else { "alice" };
    let impostor = Fixture::owned("alice", principal, if cross_principal { 71 } else { 41 }, 72)?;
    let advertised = manifest(&impostor)?;
    if cross_principal {
        // Reproduce a poisoned directory left by the reviewed version before the new guard.
        bob.client.account_db()?.persist_client_record("device","alice",&json!({"principal_id":"mallory","principal_commitment":advertised.principal_commitment,"signing_public_key":advertised.devices[0].branch_public_key,"x25519_identity_public":advertised.devices[0].prekey_bundle.identity_key}))?;
    } else {
        RamfluxClient::verify_device_manifest_json(
            serde_json::to_value(&advertised)?,
            &advertised.principal_commitment,
        )?;
        assert!(bob.client.persist_identity_directory(&advertised).is_err());
    }
    trust(&impostor, &bob)?;
    fixture_group(&impostor.client, "pinned", &alice)?;
    fixture_member(&impostor.client, "pinned", &bob)?;
    // A malicious sender bypasses the SDK's new local root/pin guard and constructs wire data.
    let (distribution, forged_body) = forged_group_traffic(&impostor)?;
    let mut keyless: serde_json::Value = serde_json::from_slice(&distribution)?;
    keyless
        .as_object_mut()
        .ok_or_else(|| invalid("distribution"))?
        .remove("sender_device_signing_public_key");
    let body = serde_json::to_vec(&SdkGroupSenderKeyDistributionEnvelope {
        schema: "ramflux.sdk.group_sender_key.distribution_envelope.v1".into(),
        version: 1,
        membership_event_base64: None,
        actor_manifest_url: None,
        distribution_base64: ramflux_protocol::encode_base64url(serde_json::to_vec(&keyless)?),
    })?;
    let mut msg = outgoing(&impostor, &bob, "forged-keyless");
    msg.source_principal_id = principal.into();
    msg.sender_id = principal.into();
    msg.conversation_id = "group-thread".into();
    let entry = seal_as(&impostor, &bob, msg, &body, Route::group_control("pinned"))?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    let keyless_rejected =
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err();
    let body = forged_body;
    let mut msg = outgoing(&impostor, &bob, "forged-group-data");
    msg.source_principal_id = principal.into();
    msg.sender_id = principal.into();
    msg.conversation_id = "group-thread".into();
    let entry = seal_as(&impostor, &bob, msg, &body, Route::group_message("pinned"))?;
    let message_rejected =
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await.is_err();
    assert!(
        keyless_rejected && message_rejected,
        "keyless rejected={keyless_rejected}, message rejected={message_rejected}"
    );
    assert_eq!(bob.client.direct_messages("group-thread")?, Vec::new());
    assert_eq!(
        bob.client.account_db()?.group_member_device_key(
            "pinned",
            &crate::client::identity_authority::test_support::group_device(
                &bob.client,
                "pinned",
                "alice"
            )?
        )?,
        Some(original.devices[0].branch_public_key.clone())
    );
    Ok(())
}
#[tokio::test]
async fn same_principal_changed_key_cannot_send_group_data_or_a_keyless_distribution()
-> Result<(), SdkError> {
    Box::pin(replaced_key_traffic(false)).await
}
#[tokio::test]
async fn cross_principal_cached_alias_cannot_send_group_data_or_a_keyless_distribution()
-> Result<(), SdkError> {
    Box::pin(replaced_key_traffic(true)).await
}
#[tokio::test]
async fn restored_device_with_empty_allocator_bootstraps_without_manual_recovery()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let mut engine = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    for n in 0..6 {
        let entry = fresh(&alice, &bob, &format!("before-restore-{n}"))?;
        bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    }
    let key = super::super::bootstrap_sequence::bootstrap_sequence_key(
        &alice.client.owned_device_identity()?,
    );
    alice.client.account_db()?.remove_actor_state(&key)?;
    alice.reopen_native().await?;
    let entry = fresh(&alice, &bob, "first-after-restore")?;
    bob.client.apply_routed_entry(&mut engine, &pool()?, &entry, false).await?;
    assert_eq!(active(&bob, "alice")?, decode(&entry.envelope)?.ciphertext.session_id);
    Ok(())
}
#[tokio::test]
async fn a_clock_behind_restore_recovers_through_an_authenticated_rate_limited_reset()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let now = u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| invalid("time"))?.as_millis(),
    )
    .map_err(|_| invalid("time"))?;
    alice.client.account_db()?.persist_actor_state(
        &super::super::bootstrap_sequence::bootstrap_sequence_key(
            &alice.client.owned_device_identity()?,
        ),
        &(now + 300_000),
    )?;
    let entry = fresh(&alice, &bob, "old-future-clock")?;
    let (mut be, _) = Wire::engine(&bob, &alice)?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false).await?;
    alice.client.account_db()?.remove_actor_state(
        &super::super::bootstrap_sequence::bootstrap_sequence_key(
            &alice.client.owned_device_identity()?,
        ),
    )?;
    alice.reopen_native().await?;
    let mut restored = alice;
    restored.client.establish_friend_link(
        "friend",
        &restored.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    let entry = fresh(&restored, &bob, "clock-behind-restore")?;
    let (mut be, bsent) = Wire::engine(&bob, &restored)?;
    assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false).await.is_err());
    let reset = last(&bsent)?;
    let (mut ae, asent) = Wire::engine(&restored, &bob)?;
    restored.client.apply_routed_entry(&mut ae, &pool()?, &reset, false).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &last(&asent)?, false).await?;
    assert_eq!(active(&restored, "bob")?, active(&bob, "alice")?);
    let good = super::r5::seal(
        &restored,
        &bob,
        super::r5::native_outgoing(&restored, &bob, "recovered")?,
        b"recovered",
    )?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &good, false).await?;
    let count = bsent.lock().map_err(|_| invalid("mutex"))?.len();
    for _ in 0..5 {
        assert!(bob.client.apply_routed_entry(&mut be, &pool()?, &entry, false).await.is_err());
    }
    assert_eq!(bsent.lock().map_err(|_| invalid("mutex"))?.len(), count);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn replay_watermarks_cannot_be_poisoned_by_another_principal_reusing_a_device_id()
-> Result<(), SdkError> {
    let alice = Fixture::native("alice", 41).await?;
    let bob = Fixture::native("bob", 61).await?;
    let entry = fresh(&alice, &bob, "scoped-watermark")?;
    let pair = RamfluxClient::pair_key(
        &bob.client.owned_device_identity()?,
        &alice.client.owned_device_identity()?,
    )?;
    bob.client
        .account_db()?
        .persist_actor_state(&format!("{pair}/bootstrap-high-water"), &9_007_199_254_740_991_u64)?;
    let opened = bob.client.open_routed(&entry, "bob")?;
    assert_eq!(
        RamfluxClient::decode_generated_inner(&opened.body)?.0.conversation_id,
        super::r5::native_outgoing(&alice, &bob, "scope")?.conversation_id
    );
    Ok(())
}
