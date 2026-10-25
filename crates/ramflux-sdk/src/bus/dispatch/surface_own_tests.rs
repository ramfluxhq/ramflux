// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-event own-device delivery has no history upload and retries independently of peers.
use super::*;
use crate::bus::runtime_tests;
use ramflux_protocol::{A2uiConversationCommand, StreamAppendCommand};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) async fn sibling_fixture(
    root: &Path,
    source: &mut LocalBusAccountState,
) -> Result<
    (LocalBusAccountState, GatewaySessionConfig, GatewaySessionConfig, tokio::task::JoinHandle<()>),
    Box<dyn std::error::Error>,
> {
    sibling_fixture_inner(root, source, true).await
}
async fn sibling_fixture_inner(
    root: &Path,
    source: &mut LocalBusAccountState,
    preseed: bool,
) -> Result<
    (LocalBusAccountState, GatewaySessionConfig, GatewaySessionConfig, tokio::task::JoinHandle<()>),
    Box<dyn std::error::Error>,
> {
    let (sibling, config, receiver, directory, _) =
        sibling_fixture_with_peer(root, source, preseed).await?;
    Ok((sibling, config, receiver, directory))
}
async fn sibling_fixture_with_peer(
    root: &Path,
    source: &mut LocalBusAccountState,
    preseed: bool,
) -> Result<
    (
        LocalBusAccountState,
        GatewaySessionConfig,
        GatewaySessionConfig,
        tokio::task::JoinHandle<()>,
        LocalBusAccountState,
    ),
    Box<dyn std::error::Error>,
> {
    let mut peer = super::dm_tests::peer_fixture(root, source).await?;
    peer.directory.abort();
    let mut sibling = runtime_tests::account(
        &root.join("sibling"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    sibling.client.create_device_branch("sender", "device-sibling", 1, [77; 32]);
    let mut own = super::fixture::manifest(&source.client)?;
    own.devices.extend(super::fixture::manifest(&sibling.client)?.devices);
    let mut remote = super::fixture::manifest(&peer.peers[0].client)?;
    remote.devices.extend(super::fixture::manifest(&peer.peers[1].client)?.devices);
    crate::client::identity_authority::test_support::sign_manifest(
        source.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut own,
        2,
    )?;
    crate::client::identity_authority::test_support::sign_manifest(
        peer.peers[0].client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &mut remote,
        2,
    )?;
    source.client.persist_root_verified_directory(&own)?;
    sibling.client.persist_root_verified_directory(&own)?;
    sibling.client.persist_root_verified_directory(&remote)?;
    let (address, directory) = super::fixture::directory(
        root,
        BTreeMap::from([
            (own.principal_commitment.clone(), serde_json::to_value(&own)?),
            (remote.principal_commitment.clone(), serde_json::to_value(&remote)?),
        ]),
    )
    .await?;
    let send = ramflux_crypto::DmSession::initiator(
        [79; 32],
        dm_device_id_hash("device-sender"),
        dm_device_id_hash("device-sibling"),
        [3; 32],
    )?;
    let recv = ramflux_crypto::DmSession::recipient(
        [79; 32],
        dm_device_id_hash("device-sibling"),
        dm_device_id_hash("device-sender"),
        [3; 32],
    )?;
    if preseed {
        source.client.persist_pair(
            &source.client.owned_device_identity()?,
            &sibling.client.owned_device_identity()?,
            &[4; 32],
            &send,
        )?;
        sibling.client.persist_pair(
            &sibling.client.owned_device_identity()?,
            &source.client.owned_device_identity()?,
            &[4; 32],
            &recv,
        )?;
    }
    let mut config = peer.config;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    let mut receiver = config.clone();
    receiver.device_id = "device-sibling".into();
    receiver = receiver.with_account_identity(&sibling.client)?;
    peer.peers[0].client.persist_root_verified_directory(&own)?;
    Ok((sibling, config, receiver, directory, peer.peers.remove(0)))
}
fn entry(envelope: ramflux_protocol::Envelope, sequence: u64) -> GatewayInboxEntry {
    // The node changes the outer routing identity, retaining the immutable signed inner body.
    let mut envelope = envelope;
    envelope.envelope_id = format!("node-own-copy-{sequence}");
    envelope.target_delivery_id = "sibling".into();
    GatewayInboxEntry { inbox_seq: sequence, target_delivery_id: "sibling".into(), envelope }
}
pub(super) fn append(
    client: &RamfluxClient,
    previous: &Carrier,
    version: u64,
) -> Result<Carrier, SdkError> {
    let wire = ramflux_protocol::encode_a2ui_conversation_event(
        "thread",
        version,
        &A2uiConversationCommand::StreamAppend(StreamAppendCommand {
            surface_id: "surface".into(),
            component_id: "result".into(),
            text_delta: "x".into(),
            final_: false,
        }),
    )?;
    let mut carrier = previous.clone();
    carrier.message_id = crate::new_surface_message_id()?;
    carrier.wire_base64 = ramflux_protocol::encode_base64url(wire);
    carrier.snapshot = None;
    client.attach_surface_snapshot(&mut carrier)?;
    client.sign_surface_carrier(carrier)
}
#[tokio::test]
async fn streamed_surface_fans_out_sixty_four_events_without_history_bundles_or_object_uploads()
-> TestResult {
    let root = runtime_tests::root("surface-own-stream");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    // Only Submit/OwnDeviceFanout/PrekeyFetch frames are accepted by this fixture: relay uploads fail.
    gateway.fail_own_ack = false;
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "submitted");
    let first = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(first, 1)).await?);
    for version in 2..=65 {
        let carrier = append(&source.client, &create, version)?;
        assert_eq!(send(&mut source, &carrier).await?["own_device_copy_state"], "submitted");
        let envelope = own
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .cloned()
            .ok_or("own event")?;
        assert!(
            sibling.client.receive_own_device_message(&receiver, &entry(envelope, version)).await?
        );
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 64);
    let source_view = source.client.surface_get("surface", 0, None)?;
    let sibling_view = sibling.client.surface_get("surface", 0, None)?;
    for field in ["snapshot", "version", "surface_hash"] {
        assert_eq!(source_view[field], sibling_view[field]);
    }
    assert_eq!(
        sibling.client.account_db()?.actor_state_usage(crate::client::delivery_receipts::PREFIX)?.0,
        0,
        "own-device copies must never create peer delivery receipts"
    );
    assert_eq!(sibling_view["version"], 65);
    assert_eq!(sibling_view["snapshot"]["components"][0]["text"], "x".repeat(64));
    for client in [&source.client, &sibling.client] {
        assert_eq!(
            client.account_db()?.client_directory_ids("object", "", 100)?,
            Vec::<String>::new()
        );
        assert_eq!(
            client.account_db()?.actor_state_key_page("own-device/send/", 256)?,
            Vec::<String>::new()
        );
        assert_eq!(
            client.account_db()?.actor_state_key_page("own_sync/", 256)?,
            Vec::<String>::new()
        );
    }
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn lost_own_copy_ack_keeps_peer_submitted_and_replays_one_immutable_message() -> TestResult {
    let root = runtime_tests::root("surface-own-retry");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.fail_own_ack = true;
    let own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway)));
    let carrier = super::dm_tests::create_carrier(&source.client)?;
    let result = send(&mut source, &carrier).await?;
    assert_eq!(result["delivery_state"], "submitted");
    assert_eq!(result["own_device_copy_state"], "pending");
    let first = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let mut forged = first.clone();
    let bytes = ramflux_protocol::decode_base64url(&forged.encrypted_payload)?;
    let raw = bytes.strip_prefix(crate::client::own_device_copy::PREFIX).ok_or("packet")?;
    let mut packet: crate::client::own_device_copy::OwnDeviceMessage = serde_json::from_slice(raw)?;
    packet.signature = "invalid".into();
    forged.encrypted_payload = ramflux_protocol::encode_base64url(packet.bytes()?);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(forged, 0)).await.is_err());
    assert!(sibling.client.surface_get("surface", 0, None)?.is_null());
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(first.clone(), 1)).await?);
    let before = sibling.client.surface_get("surface", 0, None)?;
    let db = source.client.account_db()?;
    for key in db.actor_state_key_page("own-device/send/", 256)? {
        let mut work: Value = db.load_actor_state(&key)?.ok_or("retry")?;
        work["next_at"] = json!(0);
        db.persist_actor_state(&key, &work)?;
    }
    let mut healthy = super::fixture::RecordingGateway::new(Arc::default());
    healthy.own = own.clone();
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(healthy)));
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    let second = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[1].clone();
    assert_ne!(first.envelope_id, second.envelope_id);
    assert_eq!(first.encrypted_payload, second.encrypted_payload);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(second, 2)).await?);
    assert_eq!(before, sibling.client.surface_get("surface", 0, None)?);
    assert_eq!(source.client.surface_get("surface", 0, None)?["delivery_state"], "submitted");
    assert_eq!(
        source.client.surface_get("surface", 0, None)?["own_device_copy_state"],
        "submitted"
    );
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn first_peer_device_failure_does_not_hide_delivery_to_the_second_device() -> TestResult {
    let root = runtime_tests::root("surface-first-failed");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let fixture = super::dm_tests::peer_fixture(&root, &mut source).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(captured.clone());
    gateway.fail_target = Some("device-peer-one".into());
    source.put_engine(GatewaySessionEngine::with_test_transport(fixture.config, Box::new(gateway)));
    let carrier = super::dm_tests::create_carrier(&source.client)?;
    assert!(send(&mut source, &carrier).await.is_err());
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    let view = source.client.surface_get("surface", 0, None)?;
    assert_eq!(view["delivery_devices"][0]["state"], "failed");
    assert_eq!(view["delivery_devices"][1]["state"], "submitted");
    assert_eq!(view["delivery_state"], "failed");
    fixture.directory.abort();
    drop(fixture.peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn recipient_resync_request_crosses_pair_authentication_and_sync_driver_replies() -> TestResult
{
    let root = runtime_tests::root("surface-resync-wire");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let fixture = super::dm_tests::peer_fixture(&root, &mut source).await?;
    let mut peers = fixture.peers;
    let peer = &mut peers[0];
    let peer_config = peer_receiver(peer, &source.client, &fixture.config)?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let initial = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        fixture.config.clone(),
        Box::new(super::fixture::RecordingGateway::new(initial.clone())),
    ));
    let create = super::dm_tests::create_carrier(&source.client)?;
    send(&mut source, &create).await?;
    let first = initial.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let incoming = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: first.target_delivery_id.clone(),
        envelope: first,
    };
    let mut receiver = GatewaySessionEngine::with_test_transport(
        peer_config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    peer.client.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    // The author advances while the recipient loses this event.
    let delta = append(&source.client, &create, 2)?;
    send(&mut source, &delta).await?;
    let reference = create.surface_reference()?;
    let mut view =
        peer.client.account_db()?.client_record("surface", &reference)?.ok_or("surface")?;
    view["out_of_sync"] = json!(true);
    peer.client.account_db()?.persist_client_record("surface", &reference, &view)?;
    peer.client
        .account_db()?
        .persist_actor_state(&crate::client::surface::key("out_of_sync", &reference), &2_u64)?;
    let controls = Arc::new(Mutex::new(Vec::new()));
    peer.put_engine(GatewaySessionEngine::with_test_transport(
        peer_config.clone(),
        Box::new(super::fixture::RecordingGateway::new(controls.clone())),
    ));
    assert_eq!(
        super::super::surface::request_resync(peer, &reference).await?["submitted_devices"],
        1
    );
    assert_eq!(
        super::super::surface::request_resync(peer, &reference).await?["rate_limited"],
        true
    );
    let request = controls.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let replies = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(replies.clone());
    gateway.inbox.push(GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: request.target_delivery_id.clone(),
        envelope: request,
    });
    source.put_engine(GatewaySessionEngine::with_test_transport(fixture.config, Box::new(gateway)));
    assert_eq!(crate::bus::sync_driver::run(&mut source).await?, 1);
    let reply = replies
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|e| e.target_delivery_id == "device-peer-one")
        .cloned()
        .ok_or("resync answer")?;
    let incoming = GatewayInboxEntry {
        inbox_seq: 2,
        target_delivery_id: reply.target_delivery_id.clone(),
        envelope: reply,
    };
    peer.client.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    let view = peer.client.surface_get("surface", 0, None)?;
    assert_eq!(view["version"], 2);
    assert_eq!(view["out_of_sync"], false);
    assert_eq!(
        view["surface_hash"],
        source.client.surface_get("surface", 0, None)?["surface_hash"]
    );
    assert_eq!(
        source.client.account_db()?.actor_state_key_page("surface/resync-response/", 100)?,
        Vec::<String>::new()
    );
    fixture.directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn peer_receiver(
    peer: &mut LocalBusAccountState,
    source: &RamfluxClient,
    config: &GatewaySessionConfig,
) -> Result<GatewaySessionConfig, SdkError> {
    let mut peer_config = config.clone();
    peer_config.principal_id = "peer".into();
    peer_config.device_id = "device-peer-one".into();
    peer_config = peer_config.with_account_identity(&peer.client)?;
    peer_config.target_delivery_id = "device-peer-one".into();
    peer.client.persist_identity_directory(&super::fixture::manifest(source)?)?;
    peer.client.account_db()?.establish_friend_link("source-link", "peer", "sender")?;
    Ok(peer_config)
}

#[tokio::test]
async fn own_copy_node_payload_hides_private_group_root_principal_and_dates() -> TestResult {
    let root = runtime_tests::root("own-private-metadata");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let group = "private-group-marker";
    source.client.create_group(group, "device-sender")?;
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":group}),
    )?;
    let create = super::dm_tests::create_carrier(&source.client)?;
    let own = Arc::default();
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.own = Arc::clone(&own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    assert!(source.client.queue_surface_own_copy(&create, Some(1))?);
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0].clone();
    let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
    let raw = bytes.strip_prefix(crate::client::own_device_copy::PREFIX).ok_or("packet")?;
    let packet: Value = serde_json::from_slice(raw)?;
    for field in
        ["principal", "root", "source", "conversation", "group", "created_at", "expires_at"]
    {
        assert!(packet.get(field).is_none(), "public field {field}");
    }
    let text = std::str::from_utf8(raw)?;
    for value in ["thread", group, "sender", &source.client.surface_local_root_commitment()?] {
        assert!(!text.contains(&serde_json::to_string(value)?), "private value escaped AEAD");
    }
    for slot in packet["slots"].as_array().ok_or("slots")? {
        assert!(slot.get("conversation_id").is_none());
        assert!(slot.get("object_id").is_none());
    }
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(envelope, 1)).await?);
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 1);
    assert_eq!(sibling.client.account_db()?.actor_state_usage("dm-pair/object-slot/")?.0, 0);
    assert_eq!(sibling.client.account_db()?.actor_state_usage("routed/slot-watermark/")?.0, 0);
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn a_backed_off_first_copy_blocks_newer_hash_ordered_copies_until_retry() -> TestResult {
    use crate::client::own_device_copy::OwnMessageInput;
    let root = runtime_tests::root("own-copy-order");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, _receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let mut ids = (0..20).map(|i| format!("copy-{i}")).collect::<Vec<_>>();
    ids.sort_by_key(|id| {
        crate::bus::own_device_copy::copy_id(&source.client, id).unwrap_or_default()
    });
    let first = ids.last().ok_or("first")?;
    let second = ids.first().ok_or("second")?;
    let now = now_unix_timestamp();
    let own = Arc::default();
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.own = Arc::clone(&own);
    gateway.fail_own_ack = true;
    source.put_engine(GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway)));
    for id in [first, second] {
        crate::bus::own_device_copy::stage(
            &source.client,
            OwnMessageInput {
                id,
                created_at: now,
                conversation: "thread",
                group: None,
                body: b"typed-control",
            },
            None,
        )?;
        let _ = crate::bus::own_device_copy::flush(&mut source).await?;
    }
    assert_eq!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 1);
    for key in source.client.account_db()?.actor_state_key_page("own-device/send/", 256)? {
        let mut work: Value = source.client.account_db()?.load_actor_state(&key)?.ok_or("work")?;
        work["next_at"] = json!(0);
        source.client.account_db()?.persist_actor_state(&key, &work)?;
    }
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.own = Arc::clone(&own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    for _ in 0..3 {
        let _ = crate::bus::own_device_copy::flush(&mut source).await?;
    }
    let captures = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(captures.len(), 3);
    assert_eq!(captures[0].encrypted_payload, captures[1].encrypted_payload);
    let packet =
        |envelope: &ramflux_protocol::Envelope| -> Result<Value, Box<dyn std::error::Error>> {
            let bytes = ramflux_protocol::decode_base64url(&envelope.encrypted_payload)?;
            Ok(serde_json::from_slice(
                bytes.strip_prefix(crate::client::own_device_copy::PREFIX).ok_or("packet")?,
            )?)
        };
    assert_eq!(
        packet(&captures[1])?["id"],
        crate::bus::own_device_copy::copy_id(&source.client, first)?
    );
    assert_eq!(
        packet(&captures[2])?["id"],
        crate::bus::own_device_copy::copy_id(&source.client, second)?
    );
    drop(captures);
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn an_oversized_prepared_copy_is_terminal_after_one_ratchet_step() -> TestResult {
    use crate::client::own_device_copy::OwnMessageInput;
    let root = runtime_tests::root("own-copy-too-large");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, _receiver, directory) = sibling_fixture(&root, &mut source).await?;
    let own = Arc::default();
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.own = Arc::clone(&own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let body = vec![b'x'; crate::client::own_device_copy::MAX_PACKET_BYTES - 100];
    crate::bus::own_device_copy::stage(
        &source.client,
        OwnMessageInput {
            id: "large",
            created_at: now_unix_timestamp(),
            conversation: "thread",
            group: None,
            body: &body,
        },
        None,
    )?;
    let _ = crate::bus::own_device_copy::flush(&mut source).await?;
    assert_eq!(crate::bus::own_device_copy::status(&source.client, "large")?, "failed");
    assert_eq!(source.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    let before = source.client.account_db()?.list_actor_states::<Value>("dm-pair/session/")?;
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 0);
    assert_eq!(before, source.client.account_db()?.list_actor_states::<Value>("dm-pair/session/")?);
    assert!(own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty());
    directory.abort();
    drop(sibling);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn fresh_sibling_bootstraps_its_first_surface_copy_without_a_preseeded_pair() -> TestResult {
    let root = runtime_tests::root("surface-own-fresh-bootstrap");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory) =
        sibling_fixture_inner(&root, &mut source, false).await?;
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    let own = Arc::clone(&gateway.own);
    let identity = sibling.client.owned_device_identity()?;
    gateway.prekeys.insert(
        source.client.root_qualified_device_lookup(identity.storage_key())?,
        crate::prekey::SdkPrekeyResponse {
            principal_commitment: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            target_delivery_id: Some("sibling".into()),
            bundle: Some(sibling.client.load_x3dh_private_state(&identity)?.bundle),
        },
    );
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let create = super::dm_tests::create_carrier(&source.client)?;
    assert_eq!(send(&mut source, &create).await?["own_device_copy_state"], "submitted");
    let packet = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(packet, 1)).await?);
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 1);
    directory.abort();
    drop(source);
    drop(sibling);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn receive_with_invalid_pending_row(
    root: &Path,
    mut sibling: LocalBusAccountState,
    receiver_engine: GatewaySessionEngine,
    incoming: GatewayInboxEntry,
) -> Result<LocalBusDaemonState, Box<dyn std::error::Error>> {
    // A stale/forged pending row cannot abort projection of the valid next DM.
    let mut bad = incoming.clone();
    bad.inbox_seq = 3;
    bad.envelope.envelope_id = "bad-pending-signature".into();
    bad.envelope.signed.signature = ramflux_protocol::encode_base64url([0_u8; 64]);
    sibling.pending_deliveries = vec![bad, incoming];
    sibling.put_engine(receiver_engine);
    let mut state = receiving_state(root, sibling);
    let (outbound, _) = tokio::sync::mpsc::channel(16);
    let connection = LocalBusConnectionState::new(1, outbound);
    let request = LocalBusFrame::request(
        "receive",
        Some("sender".into()),
        "message",
        "message.receive",
        json!({"limit":64}),
    );
    let response =
        super::super::message::dispatch_message_receive_request(&request, &mut state, &connection)
            .await?;
    let rows = response.response_body["decrypted_messages"].as_array().ok_or("rows")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        ramflux_protocol::decode_base64url(
            rows[0]["plaintext_body_base64"].as_str().ok_or("body")?
        )?,
        b"peer to restored device"
    );
    assert_eq!(state.accounts["sender"].pending_deliveries.len(), 1);
    Ok(state)
}

fn receiving_state(root: &Path, sibling: LocalBusAccountState) -> LocalBusDaemonState {
    LocalBusDaemonState {
        config: LocalBusConfig::new(root.join("bus.sock"), root),
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        accounts: BTreeMap::from([("sender".into(), sibling)]),
        active_account_id: Some("sender".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

fn fresh_sibling_gateway(
    sender: &RamfluxClient,
    sibling: &RamfluxClient,
) -> Result<super::fixture::RecordingGateway, SdkError> {
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    let identity = sibling.owned_device_identity()?;
    gateway.prekeys.insert(
        sender.root_qualified_device_lookup(identity.storage_key())?,
        crate::prekey::SdkPrekeyResponse {
            principal_commitment: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            target_delivery_id: Some("sender".into()),
            bundle: Some(sibling.load_x3dh_private_state(&identity)?.bundle),
        },
    );
    Ok(gateway)
}

#[tokio::test]
async fn sibling_control_is_applied_and_acked_without_entering_message_receive_projection()
-> TestResult {
    let root = runtime_tests::root("own-control-receive");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (mut sibling, config, receiver, directory) =
        sibling_fixture_inner(&root, &mut source, false).await?;
    let gateway = fresh_sibling_gateway(&source.client, &sibling.client)?;
    let own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let carrier = super::dm_tests::create_carrier(&source.client)?;
    send(&mut source, &carrier).await?;
    let envelope = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    let mut incoming = entry(envelope, 1);
    incoming.target_delivery_id.clone_from(&receiver.target_delivery_id);
    incoming.envelope.target_delivery_id.clone_from(&receiver.target_delivery_id);
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.inbox.push(incoming);
    sibling.put_engine(GatewaySessionEngine::with_test_transport(receiver, Box::new(gateway)));
    assert_eq!(crate::bus::sync_driver::run(&mut sibling).await?, 1);
    assert!(
        sibling.pending_deliveries.is_empty(),
        "authenticated controls have no ordinary DM projection"
    );
    assert_eq!(sibling.client.surface_get("surface", 0, None)?["version"], 1);
    let mut state = receiving_state(&root, sibling);
    let (outbound, _) = tokio::sync::mpsc::channel(16);
    let connection = LocalBusConnectionState::new(1, outbound);
    let request = LocalBusFrame::request(
        "receive",
        Some("sender".into()),
        "message",
        "message.receive",
        json!({"limit":64}),
    );
    let response =
        super::super::message::dispatch_message_receive_request(&request, &mut state, &connection)
            .await?;
    assert_eq!(response.response_body["decrypted_messages"], json!([]));
    directory.abort();
    drop((state, source));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn restored_owned_root_receives_contact_backfill_and_decrypts_a_fresh_peer_bootstrap()
-> TestResult {
    let root = runtime_tests::root("restored-contact-dm");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (sibling, config, receiver, directory, peer) =
        sibling_fixture_with_peer(&root, &mut source, false).await?;
    let peer_root = peer.client.owned_device_identity()?.root_commitment().to_owned();
    let own_root = source.client.owned_device_identity()?.root_commitment().to_owned();
    let db = sibling.client.account_db()?;
    db.remove_actor_state(&crate::client::identity_authority::record_key(&peer_root))?;
    db.remove_actor_state(&format!("identity/manifest-root/{peer_root}"))?;
    db.remove_actor_state("identity/manifest/peer")?;
    assert!(sibling.client.device_identity_for_root(&peer_root, "device-peer-one").is_err());
    source.client.establish_friend_link("accepted-before-restore", &own_root, &peer_root)?;
    let gateway = fresh_sibling_gateway(&source.client, &sibling.client)?;
    let own = Arc::clone(&gateway.own);
    source.put_engine(GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway)));
    // The live session has selected TCP-TLS; the original Auto endpoint is unavailable.
    source.gateway_config.transport_kind = GatewaySessionTransportKind::Auto;
    source.gateway_config.gateway_addr = "127.0.0.1:9".parse()?;
    assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 0);
    assert_eq!(crate::bus::own_contact_backfill::drive(&source).await?, 1);
    assert_eq!(crate::bus::own_device_copy::flush(&mut source).await?, 1);
    let packet = own.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    assert!(sibling.client.receive_own_device_message(&receiver, &entry(packet, 1)).await?);
    sibling.client.require_cached_root_authority(
        &sibling.client.device_identity_for_root(&peer_root, "device-peer-one")?,
    )?;
    let mut peer_config = config;
    peer_config.principal_id = "peer".into();
    peer_config.device_id = "device-peer-one".into();
    peer_config = peer_config.with_account_identity(&peer.client)?;
    let mut engine = GatewaySessionEngine::with_test_transport(
        peer_config,
        Box::new(fresh_sibling_gateway(&peer.client, &sibling.client)?),
    );
    let target = super::super::task_transport::Target {
        device: "device-sibling".into(),
        identity: sibling.client.owned_device_identity()?,
        delivery: receiver.target_delivery_id.clone(),
        federation: None,
        own: false,
    };
    let sealed = super::super::task_transport::seal(
        &peer,
        &mut engine,
        &target,
        "new-after-restore",
        b"peer to restored device",
        crate::client::routed::Route::direct(),
    )
    .await?;
    let incoming = GatewayInboxEntry {
        inbox_seq: 2,
        target_delivery_id: sealed.envelope.target_delivery_id.clone(),
        envelope: sealed.envelope,
    };
    let (sibling, receiver_engine) =
        receive_first_bootstrap(&root, sibling, receiver, incoming.clone()).await?;
    let state =
        Box::pin(receive_with_invalid_pending_row(&root, sibling, receiver_engine, incoming))
            .await?;
    directory.abort();
    drop((source, state, peer));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn receive_first_bootstrap(
    root: &Path,
    mut sibling: LocalBusAccountState,
    config: GatewaySessionConfig,
    incoming: GatewayInboxEntry,
) -> Result<(LocalBusAccountState, GatewaySessionEngine), Box<dyn std::error::Error>> {
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.inbox.push(incoming);
    sibling.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    let mut state = receiving_state(root, sibling);
    let (outbound, _) = tokio::sync::mpsc::channel(16);
    let request = LocalBusFrame::request(
        "first-receive",
        Some("sender".into()),
        "message",
        "message.receive",
        json!({"limit":10,"conversation_id":"new-after-restore"}),
    );
    let response = super::super::message::dispatch_message_receive_request(
        &request,
        &mut state,
        &LocalBusConnectionState::new(1, outbound),
    )
    .await?;
    let rows = response.response_body["decrypted_messages"].as_array().ok_or("rows")?;
    assert_eq!(rows.len(), 1, "first fresh bootstrap response: {}", response.response_body);
    assert_eq!(
        ramflux_protocol::decode_base64url(
            rows[0]["plaintext_body_base64"].as_str().ok_or("body")?
        )?,
        b"peer to restored device"
    );
    let mut sibling = state.accounts.remove("sender").ok_or("account")?;
    let engine = sibling.take_live_engine().await?;
    Ok((sibling, engine))
}
