// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated native group envelopes must retain their signed conversation binding.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

fn carrier(
    owner: &Fixture,
    peer: &Fixture,
    conversation: &str,
    id: &str,
) -> TestResult<GatewayInboxEntry> {
    let logical = owner.client.qualify_outgoing_group_message("group", id)?.0;
    let bytes = owner.client.encrypt_group_message(
        "group",
        &owner.config.device_id,
        b"native group reply",
    )?;
    let mut message = GatewayDirectMessage {
        conversation_id: conversation.into(),
        message_id: logical,
        envelope_id: id.into(),
        source_principal_id: owner.manifest.principal_id.clone(),
        sender_id: owner.config.device_id.clone(),
        recipient_device_id: Some(peer.config.device_id.clone()),
        recipient_principal_commitment: Some(peer.manifest.principal_commitment.clone()),
        target_delivery_id: peer.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let local = owner.client.owned_device_identity()?;
    let remote = peer.client.owned_device_identity()?;
    let (mut session, header, bundle) = owner.client.new_send_pair(
        &local,
        &message,
        peer.client.load_x3dh_private_state(&remote)?.bundle,
    )?;
    let packet = owner.client.seal_routed_with_route(
        &message,
        &bytes,
        Route::group_message("group"),
        SealPair {
            local: &owner.config.device_id,
            remote: remote.storage_key(),
            session: &mut session,
            header,
            bundle,
        },
    )?;
    message.encrypted_body = serde_json::to_vec(&packet)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 42,
        target_delivery_id: message.target_delivery_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&owner.config, &message, None)?,
    })
}

#[tokio::test]
async fn native_group_envelope_rejects_divergent_conversation_and_accepts_resolved_selector()
-> TestResult {
    let owner = Fixture::with_device("route-owner", "owner-device").await?;
    let mut peer = Fixture::with_device("route-peer", "peer-device").await?;
    owner.client.persist_fetched_identity_directory(&peer.manifest)?;
    peer.client.persist_fetched_identity_directory(&owner.manifest)?;
    peer.client.establish_friend_link(
        "consent",
        &owner.manifest.principal_commitment,
        &peer.manifest.principal_commitment,
    )?;
    let primary = owner
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native")?
        .group_primary(owner.vault.as_ref())?;
    owner.client.shared_group_create_with_primary(
        "group",
        "signed-thread",
        None,
        &owner.config.target_delivery_id,
        Some(&primary),
    )?;
    let state = owner.client.shared_group_change_with_primary(
        "group",
        &owner.config.target_delivery_id,
        ramflux_protocol::GroupStateChange::Add {
            member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    peer.client.accept_shared_group_state(&state, &peer.config.target_delivery_id)?;
    peer.client.import_group_sender_key_distribution(
        &owner.client.export_group_sender_key_distribution("group", &owner.config.device_id)?,
    )?;
    let mut engine =
        GatewaySessionEngine::with_test_transport(peer.config.clone(), Box::new(super::NoNetwork));
    let pool = super::review::pool()?;
    let wrong = carrier(&owner, &peer, "operator-thread", "wrong-thread")?;
    let error = peer
        .client
        .apply_routed_entry(&mut engine, &pool, &wrong, false)
        .await
        .err()
        .ok_or("wrong thread accepted")?;
    assert!(
        matches!(&error, SdkError::InboundRejected(reason) if reason == "authenticated group conversation conflicts with local binding"),
        "{error:?}"
    );
    assert!(peer.client.committed_routing(&wrong)?.is_none());
    // This is the same resolver used before sealing CLI sends and before read-model capture.
    let resolved =
        crate::bus::group_conversation::resolve(&owner.client, "group", "operator-thread")?;
    let correct = carrier(&owner, &peer, &resolved, "resolved-thread")?;
    let delivered = peer.client.apply_routed_entry(&mut engine, &pool, &correct, false).await?;
    assert_eq!(delivered.routing.ok_or("routing")?.conversation_id, "signed-thread");
    assert!(delivered.plaintext.is_some());
    assert!(peer.client.committed_routing(&correct)?.is_some());
    assert_eq!(peer.client.direct_messages("operator-thread")?.len(), 0);
    Ok(())
}
