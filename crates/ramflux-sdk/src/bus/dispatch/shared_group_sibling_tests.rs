// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An implicit sibling's public group send reaches its owner before any explicit join.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn configure(
    account: &mut LocalBusAccountState,
    base: &GatewaySessionConfig,
    device: &str,
) -> Result<GatewaySessionConfig, SdkError> {
    let mut config = base.clone();
    config.principal_id = "peer".into();
    config.device_id = device.into();
    config.target_delivery_id = device.into();
    config = config.with_account_identity(&account.client)?;
    account.gateway_config = config.clone();
    account.target_delivery_id = device.into();
    account.principal_commitment = account.client.owned_device_identity()?.root_commitment().into();
    Ok(config)
}
#[tokio::test]
async fn shared_group_implicit_sibling_first_public_send_reaches_owner_without_join() -> TestResult
{
    Box::pin(check_first_send("implicit-sibling-first", false)).await
}
#[tokio::test]
async fn shared_group_logical_message_collision_preserves_the_existing_row() -> TestResult {
    Box::pin(check_first_send("implicit-sibling-first", true)).await
}
#[tokio::test]
async fn shared_group_logical_message_cannot_preclaim_reserved_projection_ids() -> TestResult {
    Box::pin(check_first_send("routed:chosen", false)).await
}
fn prepare_group(
    owner: &LocalBusAccountState,
    sibling: &LocalBusAccountState,
    peer: &LocalBusAccountState,
) -> TestResult {
    let sender = sibling.client.owned_device_identity()?;
    let recipient = owner.client.owned_device_identity()?;
    sibling.client.persist_pair(
        &sender,
        &recipient,
        &[4; 32],
        &ramflux_crypto::DmSession::initiator(
            [71; 32],
            dm_device_id_hash(sender.device_id()),
            dm_device_id_hash(recipient.device_id()),
            [3; 32],
        )?,
    )?;
    owner.client.persist_pair(
        &recipient,
        &sender,
        &[4; 32],
        &ramflux_crypto::DmSession::recipient(
            [71; 32],
            dm_device_id_hash(recipient.device_id()),
            dm_device_id_hash(sender.device_id()),
            [3; 32],
        )?,
    )?;
    owner.client.shared_group_create(
        "group",
        "group-thread",
        Some("Sibling group".into()),
        "device-owner",
    )?;
    let state = owner.client.shared_group_change(
        "group",
        "device-owner",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: peer.client.owned_group_actor("sender")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    sibling.client.accept_shared_group_state(&state, "device-sibling")?;
    peer.client.accept_shared_group_state(&state, "sender")?;
    assert_eq!(state.view().members.len(), 2, "the sibling has not explicitly joined");
    Ok(())
}
async fn check_first_send(logical: &str, collision: bool) -> TestResult {
    let root = runtime_tests::root("group-implicit-sibling");
    let mut peer = runtime_tests::account(
        &root.join("peer"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, address: _, directory } =
        super::dm_tests::peer_fixture_devices(
            &root,
            &mut peer,
            &["device-owner", "device-sibling"],
        )
        .await?;
    let mut sibling = peers.pop().ok_or("sibling")?;
    let mut owner = peers.pop().ok_or("owner")?;
    let owner_config = configure(&mut owner, &config, "device-owner")?;
    let sibling_config = configure(&mut sibling, &config, "device-sibling")?;
    prepare_group(&owner, &sibling, &peer)?;
    if collision {
        seed_existing_message(&owner.client, logical)?;
    }
    let captured = Arc::new(Mutex::new(Vec::new()));
    sibling.put_engine(GatewaySessionEngine::with_test_transport(
        sibling_config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    let request = LocalBusFrame::request(
        "sibling-first",
        Some("peer".into()),
        "ramflux.sdk.v1",
        "group.send",
        json!({"group_id":"group","conversation_id":"group-thread","message_id":logical,"sender_id":"device-sibling","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url("first from implicit sibling")}),
    );
    Box::pin(super::super::group::dispatch_group_send_request(&request, &mut sibling)).await?;
    let entries = captured.lock().map_err(|_| "capture")?.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(
        owner_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut count = 0;
    for (index, envelope) in entries
        .into_iter()
        .filter(|envelope| envelope.target_delivery_id == "device-owner")
        .enumerate()
    {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(index + 1)?,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        owner.client.apply_routed_entry(&mut engine, &pool, &entry, false).await?;
        count += 1;
    }
    assert_eq!(count, 2, "owner must receive both key distribution and application payload");
    let rows = owner.client.direct_messages("group-thread")?;
    assert_eq!(rows.len(), 1, "first group message must be present exactly once");
    let row = &rows[0];
    let sender = sibling.client.owned_device_identity()?;
    assert_eq!(
        row.message_id,
        ramflux_protocol::group_message_id(
            "group",
            sender.root_commitment(),
            sender.device_id(),
            logical
        )?
    );
    if collision {
        assert_eq!(
            owner.client.account_db()?.message_content(logical)?,
            Some(b"original content".to_vec())
        );
        assert_eq!(
            owner.client.direct_message_by_id(logical)?.ok_or("original row")?.conversation_id,
            "other-thread"
        );
    }
    assert_eq!(
        owner.client.account_db()?.message_content(&row.message_id)?,
        Some(b"first from implicit sibling".to_vec())
    );
    directory.abort();
    drop((owner, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn seed_existing_message(client: &RamfluxClient, logical: &str) -> Result<(), SdkError> {
    client.send_direct_message("other-thread", logical, "device-owner", b"original ciphertext")?;
    client.account_db()?.store_message_content("other-thread", logical, b"original content")?;
    Ok(())
}
