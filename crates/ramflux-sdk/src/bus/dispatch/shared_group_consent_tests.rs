// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact-forwarded stranger snapshots and messages cannot create joined projections.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, atomic::AtomicBool};
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[tokio::test]
async fn r5_encrypted_contact_forward_and_message_preserve_consent_and_decline() -> TestResult {
    let root = runtime_tests::root("group-consent-wire");
    let mut user = runtime_tests::account(
        &root.join("user"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, directory, .. } =
        super::dm_tests::peer_fixture(&root, &mut user).await?;
    let contact = peers.remove(0);
    let stranger = runtime_tests::account(
        &root.join("stranger"),
        "stranger",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    stranger.client.shared_group_create("stranger-group", "stranger-thread", None, "stranger")?;
    stranger.client.shared_group_change(
        "stranger-group",
        "stranger",
        ramflux_protocol::GroupStateChange::Add {
            member: contact.client.owned_group_actor("device-peer-one")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let state = stranger.client.shared_group_change(
        "stranger-group",
        "stranger",
        ramflux_protocol::GroupStateChange::Add {
            member: user.client.owned_group_actor("sender")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    contact.client.accept_shared_group_state(&state, "device-peer-one")?;
    let actor = contact.client.owned_group_actor("device-peer-one")?;
    let forwarded = ramflux_crypto::resign_group_state_snapshot(
        contact.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &actor,
        &state,
    )?;
    let snapshot = contact.client.shared_group_packet(&forwarded, true)?;
    let message = contact.client.encrypt_group_message(
        "stranger-group",
        "device-peer-one",
        b"unsolicited",
    )?;
    let mut send_config = config.clone();
    send_config.principal_id = "peer".into();
    send_config.device_id = "device-peer-one".into();
    send_config.target_delivery_id = "device-peer-one".into();
    let mut sender = GatewaySessionEngine::with_test_transport(
        send_config.with_account_identity(&contact.client)?,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let mut receiver = GatewaySessionEngine::with_test_transport(
        config.with_account_identity(&user.client)?,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    for declined in [false, true] {
        if declined {
            user.client.decide_group_invitation("stranger-group", false, "sender")?;
        }
        for (index, (body, route)) in [
            (&snapshot, crate::client::routed::Route::group_control("stranger-group")),
            (&message, crate::client::routed::Route::group_message("stranger-group")),
        ]
        .into_iter()
        .enumerate()
        {
            let entry = seal(&contact.client, &mut sender, &user.client, body, route).await?;
            let result = user.client.apply_routed_entry(&mut receiver, &pool, &entry, false).await;
            if declined {
                assert!(
                    matches!(result, Err(SdkError::InboundRejected(reason)) if reason == "group invitation was declined")
                );
            } else if index == 1 {
                assert!(
                    matches!(result, Err(SdkError::InboundPending(reason)) if reason == "group consent or membership is pending")
                );
            } else {
                result?;
            }
            assert!(user.client.account_db()?.shared_group_state("stranger-group")?.is_none());
            assert!(
                user.client
                    .account_db()?
                    .client_record("conversation", "stranger-thread")?
                    .is_none()
            );
            assert!(
                user.client.account_db()?.message_content(&entry.envelope.envelope_id)?.is_none()
            );
        }
    }
    directory.abort();
    drop((user, contact, peers, stranger));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn seal(
    contact: &RamfluxClient,
    engine: &mut GatewaySessionEngine,
    user: &RamfluxClient,
    body: &[u8],
    route: crate::client::routed::Route,
) -> TestResult<GatewayInboxEntry> {
    let mut message = GatewayDirectMessage {
        conversation_id: "stranger-thread".into(),
        message_id: crate::new_surface_message_id()?,
        envelope_id: crate::new_surface_message_id()?,
        source_principal_id: "peer".into(),
        sender_id: "device-peer-one".into(),
        recipient_device_id: Some("device-sender".into()),
        recipient_principal_commitment: Some(
            user.owned_device_identity()?.root_commitment().into(),
        ),
        target_delivery_id: "sender".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    message.encrypted_body =
        serde_json::to_vec(&contact.seal_routed_as(engine, &message, body, route).await?)?;
    let envelope = crate::dm::gateway_direct_message_envelope(&engine.config, &message, None)?;
    Ok(GatewayInboxEntry {
        inbox_seq: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        target_delivery_id: "sender".into(),
        envelope,
    })
}
