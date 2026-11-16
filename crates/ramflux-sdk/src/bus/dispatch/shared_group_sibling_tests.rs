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
    let config = crate::client::native_test_support::bus::config_for(&account.client, base)?;
    assert_eq!(config.device_id, device, "configured certified branch");
    account.gateway_config = config.clone();
    account.target_delivery_id.clone_from(&config.target_delivery_id);
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
        )?
        .with_collapse_key_from_x3dh_sk(&[71; 32], &[4; 32])?,
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
        )?
        .with_collapse_key_from_x3dh_sk(&[71; 32], &[4; 32])?,
    )?;
    owner.client.fixture_group_create(
        "group",
        "group-thread",
        Some("Sibling group".into()),
        "device-owner",
    )?;
    let state = owner.client.fixture_group_change(
        "group",
        "device-owner",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: peer.client.fixture_group_actor("sender")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    sibling.client.fixture_accept_group_state(&state, "device-sibling")?;
    peer.client.fixture_accept_group_state(&state, "sender")?;
    assert_eq!(state.view().members.len(), 2, "the sibling has not explicitly joined");
    assert_same_add_row(&owner.client, &sibling.client)?;
    assert_same_add_row(&owner.client, &peer.client)?;
    Ok(())
}

fn assert_same_add_row(owner: &RamfluxClient, other: &RamfluxClient) -> TestResult {
    let owner_ids = service_ids(owner)?;
    let other_ids = service_ids(other)?;
    assert_eq!(other_ids.len(), 1, "first admission projects the signed add");
    assert_eq!(other_ids, owner_ids, "first admission keeps the creator's event id");
    Ok(())
}

fn service_ids(client: &RamfluxClient) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let page = client.generated_message_view_page("group-thread", None, 100)?;
    Ok(page
        .messages
        .iter()
        .filter(|view| view.kind == "service")
        .map(|view| view.id.clone())
        .collect())
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
    let gateway = super::fixture::RecordingGateway::new(captured.clone());
    let own = Arc::clone(&gateway.own);
    sibling.install_test_session(GatewaySessionEngine::with_test_transport(
        sibling_config,
        Box::new(gateway),
    ));
    let request = LocalBusFrame::request(
        "sibling-first",
        Some("peer".into()),
        "ramflux.sdk.v1",
        "group.send",
        json!({"group_id":"group","conversation_id":"group-thread","message_id":logical,"sender_id":"device-sibling","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url("first from implicit sibling")}),
    );
    let sent =
        Box::pin(super::super::group::dispatch_group_send_request(&request, &mut sibling)).await?;
    let canonical = sent.response_body["message_id"].as_str().ok_or("allocated group identity")?;
    assert_eq!(sent.response_body["client_message_id"], logical);
    let owner_target = owner.client.owned_device_identity()?.storage_key().to_owned();
    let mut entries = captured.lock().map_err(|_| "capture")?.clone();
    entries.extend(own.lock().map_err(|_| "own capture")?.iter().cloned());
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
        .filter(|envelope| envelope.target_delivery_id == owner_target)
        .enumerate()
    {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(index + 1)?,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        owner.client.apply_routed_entry(&mut engine, &pool, &entry).await?;
        count += 1;
    }
    assert_eq!(count, 2, "owner must receive both key distribution and application payload");
    let rows = owner.client.direct_messages("group-thread")?;
    let applications: Vec<_> = rows.iter().filter(|row| row.message_id == canonical).collect();
    assert_eq!(applications.len(), 1, "first group message must be present exactly once");
    let row = *applications.first().expect("test: first group message");
    assert_member_add_is_one_service_row(&owner.client)?;
    assert_ne!(canonical, logical, "caller tokens cannot reserve canonical message ids");
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
        owner
            .client
            .generated_message_detail("group-thread", &row.message_id)?
            .message
            .text
            .as_deref(),
        Some("first from implicit sibling")
    );
    directory.abort();
    drop((owner, sibling, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn assert_member_add_is_one_service_row(client: &RamfluxClient) -> TestResult {
    let page = client.generated_message_view_page("group-thread", None, 100)?;
    assert_eq!(
        page.messages.iter().filter(|view| view.kind == "service").count(),
        1,
        "the member add is one service row beside the message"
    );
    assert_eq!(
        page.messages.iter().filter(|view| view.kind == "message").count(),
        1,
        "the service row is not a second application message"
    );
    Ok(())
}

fn seed_existing_message(client: &RamfluxClient, logical: &str) -> Result<(), SdkError> {
    client.send_direct_message("other-thread", logical, "device-owner", b"original ciphertext")?;
    client.account_db()?.store_message_content("other-thread", logical, b"original content")?;
    Ok(())
}
