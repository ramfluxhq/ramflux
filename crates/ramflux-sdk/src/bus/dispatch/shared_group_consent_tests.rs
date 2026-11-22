// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contact-forwarded stranger snapshots and messages cannot create joined projections.
use super::*;
use crate::bus::runtime_tests;
use prost::Message as _;
use ramflux_protocol::message as g;
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
    let stranger = native_stranger().await?;
    let (snapshot, message) =
        prepare_stranger_controls(&stranger.client, &contact.client, &user.client)?;
    let send_config =
        crate::client::native_test_support::bus::config_for(&contact.client, &config)?;
    let mut sender = GatewaySessionEngine::with_test_transport(
        send_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let receiver_config =
        crate::client::native_test_support::bus::config_for(&user.client, &config)?;
    let mut receiver = GatewaySessionEngine::with_test_transport(
        receiver_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    for declined in [false, true] {
        if declined {
            user.client.decide_group_invitation(
                "stranger-group",
                false,
                user.client.owned_device_identity()?.storage_key(),
            )?;
        }
        for (index, (body, route)) in [
            (&snapshot, crate::client::routed::Route::group_control("stranger-group")),
            (&message, crate::client::routed::Route::group_message("stranger-group")),
        ]
        .into_iter()
        .enumerate()
        {
            let entry = seal(&contact.client, &mut sender, &user.client, body, route).await?;
            let result = user.client.apply_routed_entry(&mut receiver, &pool, &entry).await;
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
            assert_not_joined(&user.client, &entry)?;
        }
    }
    directory.abort();
    drop((user, contact, peers, stranger));
    Ok(())
}
fn prepare_stranger_controls(
    stranger: &RamfluxClient,
    contact: &RamfluxClient,
    user: &RamfluxClient,
) -> TestResult<(Vec<u8>, Vec<u8>)> {
    stranger
        .fixture_group_create("stranger-group", "stranger-thread", None, "stranger")
        .map_err(|error| format!("stranger create: {error}"))?;
    stranger
        .fixture_group_change(
            "stranger-group",
            "stranger",
            ramflux_protocol::GroupStateChange::Add {
                member: contact.fixture_group_actor("device-peer-one")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )
        .map_err(|error| format!("stranger member admission: {error}"))?;
    let state = stranger
        .fixture_group_change(
            "stranger-group",
            "stranger",
            ramflux_protocol::GroupStateChange::Add {
                member: user.fixture_group_actor("sender")?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )
        .map_err(|error| format!("stranger member admission: {error}"))?;
    contact
        .fixture_accept_group_state(&state, "device-peer-one")
        .map_err(|error| format!("contact accept: {error}"))?;
    let actor = contact
        .fixture_group_actor("device-peer-one")
        .map_err(|error| format!("forward actor: {error}"))?;
    let forwarded = ramflux_crypto::resign_group_state_snapshot(
        contact.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &actor,
        &state,
    )
    .map_err(|error| format!("resign forwarding snapshot: {error}"))?;
    let snapshot = contact.shared_group_packet(&forwarded, true)?;
    let identity = contact.allocate_generated_identity(
        "stranger-thread",
        u64::try_from(now_unix_timestamp())?.saturating_mul(1_000),
        false,
    )?;
    let message = contact.encrypt_generated_group_inner(
        "stranger-group",
        "device-peer-one",
        identity,
        &g::Message { text: "unsolicited".into(), ..Default::default() },
    )?;
    Ok((snapshot, message))
}

async fn native_stranger() -> TestResult<LocalBusAccountState> {
    let mut stranger = Box::pin(crate::client::native_test_support::Fixture::with_principal(
        "stranger",
        "device-stranger",
        "stranger",
    ))
    .await?;
    Box::pin(crate::client::native_test_support::activation_send::tests::publish_layer_four(
        &mut stranger,
    ))
    .await?;
    Ok(stranger.into_bus())
}

async fn seal(
    contact: &RamfluxClient,
    engine: &mut impl crate::GatewaySessionAccess,
    user: &RamfluxClient,
    body: &[u8],
    route: crate::client::routed::Route,
) -> TestResult<GatewayInboxEntry> {
    let inner = g::Inner::decode(body)?;
    let id = inner.identity.ok_or("generated group identity")?;
    let target = user.owned_device_identity()?;
    let own = contact.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: id.conversation_id.clone(),
        message_id: ramflux_protocol::encode_base64url(&id.id),
        envelope_id: crate::new_surface_message_id()?,
        source_principal_id: engine.config().principal_id.clone(),
        sender_id: own.device_id().into(),
        recipient_device_id: Some(target.device_id().into()),
        recipient_principal_commitment: Some(target.root_commitment().into()),
        target_delivery_id: target.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let sealed = contact.seal_routed_as(engine, &message, body, route).await?;
    let envelope = crate::dm::gateway_generated_envelope_from_sealed(
        &engine.sealing_config()?,
        &mut message,
        sealed,
    )?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    })
}

fn assert_not_joined(user: &RamfluxClient, entry: &GatewayInboxEntry) -> TestResult {
    assert!(user.account_db()?.shared_group_state("stranger-group")?.is_none());
    assert!(!user.local_is_group_member("stranger-group")?);
    assert!(user.account_db()?.client_record("conversation", "stranger-thread")?.is_none());
    assert!(user.account_db()?.message_content(&entry.envelope.envelope_id)?.is_none());
    Ok(())
}
