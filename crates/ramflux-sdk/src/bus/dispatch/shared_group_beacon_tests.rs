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
    let creator = peers.remove(0);
    creator.client.shared_group_create("group", "group-thread", None, "device-peer-one")?;
    let state = creator.client.shared_group_change(
        "group",
        "device-peer-one",
        ramflux_protocol::GroupStateChange::Add {
            member: peer.client.owned_group_actor("sender")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    peer.client.accept_shared_group_state(&state, "sender")?;
    assert_eq!(peer.client.group_state("group")?.members.len(), 3);
    let mut sibling =
        runtime_tests::account(&root.join("new"), "peer", None, Arc::new(AtomicBool::new(false)))?;
    sibling.client.create_identity_root("peer", [91; 32]);
    sibling.client.create_device_branch("peer", "new-sibling", 1, [95; 32]);
    let (address, updated_directory, updated_root) =
        updated_directory(&root, &creator.client, &sibling.client, &peer.client).await?;
    let mut sender_config = config.clone();
    sender_config.gateway_addr = address;
    sender_config.tcp_gateway_addr = Some(address);
    sender_config.ca_cert = updated_root.join("ca.pem");
    sender_config.principal_id = "peer".into();
    sender_config.device_id = "device-peer-one".into();
    sender_config.target_delivery_id = "device-peer-one".into();
    let mut sender = GatewaySessionEngine::with_test_transport(
        sender_config.with_account_identity(&creator.client)?,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    creator.client.stage_group_device_beacon("group", "device-peer-one", 3)?;
    let beacon: BeaconRecord = creator
        .client
        .account_db()?
        .load_actor_state(&format!("group-beacon/{}", ramflux_protocol::encode_base64url("group")))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert!(matches!(beacon.packet.body, GroupControlBody::DeviceSet { device_set_epoch: 3, .. }));
    let bytes = serde_json::to_vec(&beacon.packet)?;
    assert!(bytes.len() < 2048, "beacon does not contain a full group snapshot");
    let mut message = GatewayDirectMessage {
        conversation_id: "group-thread".into(),
        message_id: "beacon".into(),
        envelope_id: "beacon-envelope".into(),
        source_principal_id: sender.config.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some("device-sender".into()),
        recipient_principal_commitment: Some(
            peer.client.owned_device_identity()?.root_commitment().into(),
        ),
        target_delivery_id: "sender".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    message.encrypted_body = serde_json::to_vec(
        &creator
            .client
            .seal_routed_as(
                &mut sender,
                &message,
                &bytes,
                crate::client::routed::Route::group_control("group"),
            )
            .await?,
    )?;
    let envelope = crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?;
    let mut receiver_config = config;
    receiver_config.gateway_addr = address;
    receiver_config.tcp_gateway_addr = Some(address);
    receiver_config.ca_cert = updated_root.join("ca.pem");
    let mut receiver = GatewaySessionEngine::with_test_transport(
        receiver_config.with_account_identity(&peer.client)?,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let entry = beacon_entry(envelope);
    peer.client.apply_routed_entry(&mut receiver, &pool, &entry, false).await?;
    let view = peer.client.group_state("group")?;
    assert_eq!(view.group_epoch, 2);
    assert_eq!(view.members.len(), 4);
    assert!(view.members.contains("new-sibling"));
    assert!(
        peer.client.direct_messages("group-thread")?.is_empty(),
        "beacon never projects chat content"
    );
    directory.abort();
    updated_directory.abort();
    drop((peer, creator, peers, sibling));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn beacon_entry(envelope: ramflux_protocol::Envelope) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "sender".into(),
        envelope,
    }
}

async fn updated_directory(
    root: &Path,
    creator: &RamfluxClient,
    sibling: &RamfluxClient,
    peer: &RamfluxClient,
) -> TestResult<(SocketAddr, tokio::task::JoinHandle<()>, PathBuf)> {
    let creator_root = creator.owned_device_identity()?.root_commitment().to_owned();
    let mut manifest: crate::prekey::SdkDeviceManifestResponse = creator
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{creator_root}"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let mut new = super::fixture::manifest(sibling)?;
    new.devices[0].target_delivery_id = "new-sibling".into();
    manifest.devices.extend(new.devices);
    crate::client::identity_authority::test_support::sign_manifest(
        creator.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut manifest,
        3,
    )?;
    creator.persist_identity_directory(&manifest)?;
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
