// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A small authenticated hint refreshes implicit siblings at the unchanged signed group epoch.
use super::*;
use crate::bus::runtime_tests;
use crate::client::shared_group::{BeaconRecord, GroupControlBody};
use std::sync::{Arc, atomic::AtomicBool};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[tokio::test]
async fn shared_group_device_beacon_refreshes_existing_peer_roster_without_full_state_resend()
-> TestResult {
    let root = runtime_tests::root("group-beacon");
    let mut peer = runtime_tests::account(
        &root.join("peer"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, directory, .. } =
        super::dm_tests::peer_fixture(&root, &mut peer).await?;
    let mut creator = peers.remove(0);
    creator.client.fixture_group_create("group", "group-thread", None, "device-peer-one")?;
    let state = creator.client.fixture_group_change(
        "group",
        "device-peer-one",
        ramflux_protocol::GroupStateChange::Add {
            member: peer.client.fixture_group_actor("sender")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.client.fixture_accept_group_state(&state, "sender")?;
    assert_eq!(peer.client.group_state("group")?.members.len(), 3);
    // The creator's root enrols a third device after the peer cached the earlier roster.
    let sibling = Box::pin(crate::client::native_test_support::bus::sibling(
        &mut creator,
        "new-sibling",
        "new-sibling",
    ))
    .await?;
    let new_member = sibling.client.owned_device_identity()?.device_id().to_owned();
    let (address, updated_directory, updated_root) =
        updated_directory(&root, &creator.client, &peer.client).await?;
    let mut sender_config =
        crate::client::native_test_support::bus::config_for(&creator.client, &config)?;
    sender_config.gateway_addr = address;
    sender_config.tcp_gateway_addr = Some(address);
    sender_config.ca_cert = updated_root.join("ca.pem");
    let mut sender = GatewaySessionEngine::with_test_transport(
        sender_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let bytes = staged_beacon_body(&creator.client, &state)?;
    let envelope = seal_beacon(&creator.client, &peer.client, &mut sender, &bytes).await?;
    let mut receiver_config =
        crate::client::native_test_support::bus::config_for(&peer.client, &config)?;
    receiver_config.gateway_addr = address;
    receiver_config.tcp_gateway_addr = Some(address);
    receiver_config.ca_cert = updated_root.join("ca.pem");
    let target_delivery = receiver_config.target_delivery_id.clone();
    let mut receiver = GatewaySessionEngine::with_test_transport(
        receiver_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let entry = beacon_entry(envelope, target_delivery);
    let creator_root = creator.client.owned_device_identity()?.root_commitment().to_owned();
    // The hint names a sender head newer than the one the peer cached: it is refused as a typed
    // pending outcome until the head is refreshed from the directory, then redriven.
    match peer.client.apply_routed_entry(&mut receiver, &pool, &entry).await {
        Err(SdkError::FreshHeadRequired { root }) if root == creator_root => {}
        other => {
            let refusal = format!("stale sender head must demand a refresh: {:?}", other.err());
            return Err(refusal.into());
        }
    }
    peer.client
        .cache_verified_device_manifest(&receiver.config, &creator_root, "beacon-refresh")
        .await?;
    peer.client.apply_routed_entry(&mut receiver, &pool, &entry).await?;
    let view = peer.client.group_state("group")?;
    assert_eq!(view.group_epoch, 2);
    assert_eq!(view.members.len(), 4);
    assert!(view.members.contains(&new_member));
    assert!(
        peer.client.direct_chat_messages("group-thread")?.is_empty(),
        "beacon never projects chat content"
    );
    directory.abort();
    updated_directory.abort();
    drop((peer, creator, peers, sibling));
    Ok(())
}

/// Seal the staged hint as a group-control frame from the creator to the peer's device.
async fn seal_beacon(
    creator: &RamfluxClient,
    peer: &RamfluxClient,
    sender: &mut GatewaySessionEngine,
    bytes: &[u8],
) -> TestResult<ramflux_protocol::Envelope> {
    let recipient = peer.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: "group-thread".into(),
        message_id: "beacon".into(),
        envelope_id: "beacon-envelope".into(),
        source_principal_id: sender.config.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some(recipient.device_id().into()),
        recipient_principal_commitment: Some(recipient.root_commitment().into()),
        target_delivery_id: recipient.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let sealed = creator
        .seal_routed_as(
            sender,
            &message,
            bytes,
            crate::client::routed::Route::group_control("group"),
        )
        .await?;
    Ok(crate::dm::gateway_envelope_from_sealed(&sender.config, &mut message, sealed, None)?)
}

/// Stage the creator's device-set hint at its current certified epoch and return the sealed
/// control body; it must stay far below the full group snapshot it replaces.
fn staged_beacon_body(
    creator: &RamfluxClient,
    state: &ramflux_crypto::VerifiedGroupState,
) -> TestResult<Vec<u8>> {
    let epoch = creator
        .current_custody_authority(
            creator.owned_device_identity()?.root_commitment(),
            crate::custody::network_now()?,
        )?
        .ok_or("creator custody authority")?
        .envelope()
        .body
        .device_set_epoch;
    let device = creator.owned_device_identity()?.storage_key().to_owned();
    creator.stage_group_device_beacon("group", &device, epoch)?;
    let beacon: BeaconRecord = creator
        .account_db()?
        .load_actor_state(&format!("group-beacon/{}", ramflux_protocol::encode_base64url("group")))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert!(
        matches!(beacon.packet.body, GroupControlBody::DeviceSet { device_set_epoch, .. } if device_set_epoch == epoch)
    );
    let bytes = creator.generated_group_control_inner(&beacon.packet)?;
    let full_snapshot = serde_json::to_vec(state.snapshot())?;
    assert!(
        bytes.len() < full_snapshot.len(),
        "beacon ({} bytes) must be smaller than the full group snapshot ({} bytes)",
        bytes.len(),
        full_snapshot.len()
    );
    Ok(bytes)
}

fn beacon_entry(envelope: ramflux_protocol::Envelope, target: String) -> GatewayInboxEntry {
    GatewayInboxEntry { forwarded: false, inbox_seq: 1, target_delivery_id: target, envelope }
}

async fn updated_directory(
    root: &Path,
    creator: &RamfluxClient,
    peer: &RamfluxClient,
) -> TestResult<(SocketAddr, tokio::task::JoinHandle<()>, PathBuf)> {
    // The creator's own account now publishes the enlarged certified roster.
    let manifest = super::fixture::manifest(creator)?;
    creator.persist_fetched_identity_directory(&manifest)?;
    // The peer has the previous manifest until receipt of the authenticated hint.
    assert_eq!(peer.group_state("group")?.members.len(), 3);
    let own = super::fixture::manifest(peer)?;
    let updated_root = root.join("updated-directory");
    std::fs::create_dir_all(&updated_root)?;
    let (address, updated_directory) = super::fixture::directory(
        &updated_root,
        BTreeMap::from([
            (manifest.principal_commitment.clone(), serde_json::to_value(manifest)?),
            (own.principal_commitment.clone(), serde_json::to_value(own)?),
        ]),
    )
    .await?;
    Ok((address, updated_directory, updated_root))
}
