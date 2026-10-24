// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface delivery exercises the same synchronous group adapter as text.
use super::*;
use crate::bus::runtime_tests;
use crate::client::surface::SurfaceSender;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
pub(in crate::bus::dispatch) struct Delivery {
    pub(in crate::bus::dispatch) envelope: ramflux_protocol::Envelope,
}

#[tokio::test]
async fn hundred_device_surface_uses_text_distribution_submit_and_measured_frame_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-text-group");
    let mut source = runtime_tests::account(
        &root.join("sender"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let peers = members(&root, &source, 99)?;
    let (config, directory) = directory_config(&root, &mut source, &peers).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let epoch = source.client.group_state("group")?.group_epoch;
    let command = A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
        surface_id: "surface".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "中文 é 🦀".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"result","text":"🦀".repeat(1500)})],
        data_model: serde_json::Map::default(),
        allowed_actions: Vec::new(),
    });
    let request = crate::SurfaceSendRequest::event("thread", 1, &command)?;
    let mut carrier = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: request.conversation_id,
        surface_id: "surface".into(),
        message_id: request.message_id,
        sender_principal_id: "sender".into(),
        sender_device_id: "device-sender".into(),
        author_principal_id: "sender".into(),
        wire_base64: request.wire_base64,
        signature: String::new(),
        snapshot: None,
    };
    source.client.attach_surface_snapshot(&mut carrier)?;
    carrier = source.client.sign_surface_carrier(carrier)?;
    let response = send(&mut source, &carrier).await?;
    assert_eq!(response["delivery_state"], "submitted");
    assert_eq!(response["accepted"], true);
    let envelopes = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(envelopes.len(), 198);
    let mut deliveries = Vec::new();
    for peer in &peers {
        let id = peer
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .as_str();
        deliveries.extend(
            envelopes
                .iter()
                .filter(|envelope| envelope.target_delivery_id == id)
                .cloned()
                .map(|envelope| Delivery { envelope }),
        );
    }
    assert_receivers(&peers, &deliveries, epoch, 1)?;
    assert_admission(&mut source, &carrier, &captured).await?;
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(in crate::bus::dispatch) fn members(
    root: &std::path::Path,
    source: &LocalBusAccountState,
    count: u8,
) -> Result<Vec<LocalBusAccountState>, SdkError> {
    source.client.create_group("group", "device-sender")?;
    let mut peers = Vec::new();
    let sender_key = ramflux_protocol::encode_base64url(
        source
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    for i in 0..count {
        let id = format!("peer-{i}");
        let device = format!("device-{id}");
        let mut peer =
            runtime_tests::account(&root.join(&id), &id, None, Arc::new(AtomicBool::new(false)))?;
        peer.client.create_identity_root(&id, [110 + i; 32]);
        peer.client.create_device_branch(&id, &device, 1, [111 + i; 32]);
        let commitment = super::fixture::manifest(&peer.client)?.principal_commitment;
        source.client.add_group_member("group", &device, "member")?;
        let key = ramflux_protocol::encode_base64url(
            peer.client
                .device_branch
                .as_ref()
                .ok_or(SdkError::IdentityRootMissing)?
                .signing_key
                .verifying_key()
                .to_bytes(),
        );
        source.client.account_db()?.persist_client_record(
            "device",
            &device,
            &json!({"principal_id":id}),
        )?;
        source.client.account_db()?.persist_client_record("identity",&id,&json!({"contact_identity_commitment":commitment,"devices":[{"device_id":device,"signing_public_key":key,"target_delivery_id":id}]}))?;
        // Pre-established authenticated pair sessions isolate this test from directory/prekey I/O.
        let send = ramflux_crypto::DmSession::initiator(
            [i + 1; 32],
            dm_device_id_hash("device-sender"),
            dm_device_id_hash(&device),
            [3; 32],
        )?;
        let recv = ramflux_crypto::DmSession::recipient(
            [i + 1; 32],
            dm_device_id_hash(&device),
            dm_device_id_hash("device-sender"),
            [3; 32],
        )?;
        source.client.persist_pair("device-sender", &device, &[4; 32], &send)?;
        peer.client.persist_pair(&device, "device-sender", &[4; 32], &recv)?;
        peer.client.account_db()?.persist_client_record(
            "device",
            "device-sender",
            &json!({"principal_id":"sender","principal_commitment":super::fixture::manifest(&source.client)?.principal_commitment,"signing_public_key":sender_key}),
        )?;
        peers.push(peer);
    }
    Ok(peers)
}
pub(in crate::bus::dispatch) fn assert_receivers(
    peers: &[LocalBusAccountState],
    deliveries: &[Delivery],
    epoch: u64,
    version: u64,
) -> Result<(), SdkError> {
    let mut inner_ciphertext = None;
    for pair in deliveries.as_chunks::<2>().0 {
        let peer = peers
            .iter()
            .find(|peer| {
                peer.client
                    .device_branch
                    .as_ref()
                    .is_some_and(|d| d.principal_id == pair[0].envelope.target_delivery_id)
            })
            .ok_or_else(|| SdkError::LocalBus("recipient fixture absent".into()))?;
        let local = peer.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        peer.client.account_db()?.upsert_group_local_membership_snapshot(
            "group",
            epoch,
            128,
            "none",
            &local.device_id,
            "member",
            1,
        )?;
        peer.client.account_db()?.upsert_group_member_snapshot(
            "group",
            "device-sender",
            "owner",
            1,
        )?;
        peer.client.account_db()?.persist_client_record(
            "conversation",
            "thread",
            &json!({"kind":"group","group_id":"group"}),
        )?;
        for (index, delivery) in pair.iter().enumerate() {
            let entry = GatewayInboxEntry {
                inbox_seq: u64::try_from(index + 1)
                    .map_err(|_| SdkError::LocalBus("index".into()))?,
                target_delivery_id: delivery.envelope.target_delivery_id.clone(),
                envelope: delivery.envelope.clone(),
            };
            let opened = peer.client.open_routed(&entry, &local.device_id)?;
            if index == 0 {
                assert!(matches!(opened.routing.kind, crate::client::routed::Kind::GroupControl));
                let wrapper: serde_json::Value = serde_json::from_slice(&opened.body)?;
                let bytes = ramflux_protocol::decode_base64url(
                    wrapper["distribution_base64"]
                        .as_str()
                        .ok_or_else(|| SdkError::LocalBus("distribution".into()))?,
                )
                .map_err(|_| SdkError::LocalBus("distribution bytes".into()))?;
                // The membership update pins the verified sender before a distribution is admitted.
                peer.client.pin_joined_group_member("group", "device-sender")?;
                peer.client.import_group_sender_key_distribution(&bytes)?;
            } else {
                assert!(matches!(opened.routing.kind, crate::client::routed::Kind::GroupMessage));
                if let Some(first) = &inner_ciphertext {
                    assert_eq!(&*opened.body, first);
                } else {
                    inner_ciphertext = Some(opened.body.to_vec());
                }
                let envelope = serde_json::from_slice(&opened.body)?;
                let plaintext =
                    peer.client.decrypt_group_envelope(&envelope, &opened.routing.message_id)?;
                let result = peer
                    .client
                    .project_surface_message(
                        "thread",
                        &opened.routing.message_id,
                        SurfaceSender {
                            principal: "sender",
                            device: "device-sender",
                            envelope_id: &entry.envelope.envelope_id,
                            expires_at: None,
                            group_epoch: Some(epoch),
                        },
                        &plaintext,
                        false,
                    )?
                    .ok_or_else(|| SdkError::LocalBus("projection".into()))?;
                assert!(result.accepted, "{:?}", result.renderer_error);
                assert_eq!(peer.client.surface_get("surface", 0, None)?["version"], version);
                assert!(result.fallback_text.contains("中文 é 🦀"));
            }
        }
    }
    Ok(())
}

pub(in crate::bus::dispatch) async fn directory_config(
    root: &std::path::Path,
    source: &mut LocalBusAccountState,
    peers: &[LocalBusAccountState],
) -> Result<(GatewaySessionConfig, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let own = super::fixture::manifest(&source.client)?;
    source.principal_commitment = own.principal_commitment.clone();
    let mut manifests = BTreeMap::new();
    manifests.insert(own.principal_commitment.clone(), serde_json::to_value(own)?);
    for peer in peers {
        let m = super::fixture::manifest(&peer.client)?;
        manifests.insert(m.principal_commitment.clone(), serde_json::to_value(m)?);
    }
    let (address, task) = super::fixture::directory(root, manifests).await?;
    let config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: address,
        server_name: "test-gateway".into(),
        ca_cert: root.join("ca.pem"),
        principal_id: "sender".into(),
        device_id: "device-sender".into(),
        target_delivery_id: "sender".into(),
        prekey_http_url: None,
    })
    .with_device_branch(source.client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?);
    Ok((config, task))
}

async fn assert_admission(
    source: &mut LocalBusAccountState,
    carrier: &Carrier,
    captured: &Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
) -> Result<(), SdkError> {
    let pair_rows = source.client.account_db()?.surface_history_page::<serde_json::Value>(
        "dm-pair/session/",
        "dm-pair/session/",
        200,
    )?;
    let mut oversized = carrier.clone();
    oversized.wire_base64 = "x".repeat(crate::client::surface::MAX_DELIVERY_BYTES);
    assert!(matches!(
        send(source, &oversized).await,
        Err(SdkError::SurfaceDeliveryTooLarge { .. })
    ));
    assert_eq!(
        source.client.account_db()?.surface_history_page::<serde_json::Value>(
            "dm-pair/session/",
            "dm-pair/session/",
            200
        )?,
        pair_rows
    );
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 198);
    assert_eq!(
        source.client.account_db()?.surface_history_page::<serde_json::Value>(
            "surface/transport/",
            "surface/transport/",
            100
        )?,
        Vec::<serde_json::Value>::new()
    );
    let epoch = source.client.group_state("group")?.group_epoch;
    let before = serde_json::to_value(source.client.load_group_sender_key_state(
        "group",
        "device-sender",
        epoch,
        "send",
    )?)?;
    let mut pin = source
        .client
        .account_db()?
        .client_record("identity", "peer-0")?
        .ok_or_else(|| invalid("peer pin"))?;
    pin["contact_identity_commitment"] = json!("wrong-root");
    source.client.account_db()?.persist_client_record("identity", "peer-0", &pin)?;
    let forged_route = source
        .client
        .prepare_surface_resync(&carrier.surface_reference()?, &crate::new_surface_message_id()?)?;
    assert!(send(source, &forged_route).await.is_err());
    assert_eq!(
        serde_json::to_value(source.client.load_group_sender_key_state(
            "group",
            "device-sender",
            epoch,
            "send"
        )?)?,
        before
    );
    Ok(())
}

#[tokio::test]
async fn maximal_create_and_full_resync_with_all_finality_seal_under_shared_frame_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-max-frame");
    let mut source = runtime_tests::account(
        &root.join("sender"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let peers = members(&root, &source, 1)?;
    let (config, directory) = directory_config(&root, &mut source, &peers).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let gateway = super::fixture::RecordingGateway::new(captured.clone());
    let frame_lengths = gateway.frame_lengths.clone();
    source.put_engine(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let carrier = maximal_carrier(&source.client)?;
    assert!(carrier.snapshot.as_ref().is_some_and(|proof| !proof.is_full()));
    assert_eq!(send(&mut source, &carrier).await?["delivery_state"], "submitted");
    let epoch = source.client.group_state("group")?.group_epoch;
    finalize_all_blocks(&source.client, &carrier, epoch)?;
    let resync = source
        .client
        .prepare_surface_resync(&carrier.surface_reference()?, &crate::new_surface_message_id()?)?;
    assert!(resync.snapshot.as_ref().ok_or("resync metadata")?.is_full());
    assert_eq!(send(&mut source, &resync).await?["delivery_state"], "submitted");
    let envelopes = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(envelopes.len(), 3); // The existing text adapter reuses the distributed sender key.
    let first =
        envelopes[..2].iter().cloned().map(|envelope| Delivery { envelope }).collect::<Vec<_>>();
    assert_receivers(&peers, &first, epoch, 1)?;
    let envelope = envelopes[2].clone();
    let entry = GatewayInboxEntry {
        inbox_seq: 3,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let peer = &peers[0];
    let local = peer.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let opened = peer.client.open_routed(&entry, &local.device_id)?;
    let group = serde_json::from_slice(&opened.body)?;
    let plaintext = peer.client.decrypt_group_envelope(&group, &opened.routing.message_id)?;
    let result = peer
        .client
        .project_surface_message(
            "thread",
            &opened.routing.message_id,
            SurfaceSender {
                principal: "sender",
                device: "device-sender",
                envelope_id: &entry.envelope.envelope_id,
                expires_at: None,
                group_epoch: Some(epoch),
            },
            &plaintext,
            false,
        )?
        .ok_or("resync projection")?;
    assert!(result.accepted, "{:?}", result.renderer_error);
    assert_eq!(peer.client.surface_get("surface", 0, None)?["version"], 65);
    {
        let lengths = frame_lengths.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let largest = lengths.iter().max().copied().ok_or("no frames")?;
        assert!(largest + 64 * 1024 < ramflux_transport::MAX_GATEWAY_FRAME_BYTES);
        eprintln!(
            "maximal create/resync actual adapter frame bytes: {lengths:?}; transport cap: {}",
            ramflux_transport::MAX_GATEWAY_FRAME_BYTES
        );
    }
    assert_eq!(source.client.surface_get("surface", 0, None)?["version"], 65);
    source.client.remove_group_member("group", "device-sender", "device-peer-0")?;
    source.client.add_group_member("group", "device-peer-0", "member")?;
    let error = send(&mut source, &resync).await.err().ok_or("old-epoch retry was accepted")?;
    assert!(error.to_string().contains("epoch changed"), "{error}");
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 3);
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn maximal_carrier(source: &RamfluxClient) -> Result<Carrier, Box<dyn std::error::Error>> {
    maximal_carrier_in(source, "thread", "surface")
}
fn maximal_carrier_in(
    source: &RamfluxClient,
    conversation: &str,
    surface: &str,
) -> Result<Carrier, Box<dyn std::error::Error>> {
    use ramflux_protocol::{MAX_SURFACE_DATA_BYTES, canonical_json_bytes};
    let mut content = CreateSurfaceCommand {
        surface_id: surface.into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "中文 é 🦀".into(),
        fallback_markdown: None,
        components: (0..64).map(|i| json!({"id":format!("block-{i}"),"text":""})).collect(),
        data_model: serde_json::Map::from_iter([("padding".into(), json!(""))]),
        allowed_actions: Vec::new(),
    };
    let padding = MAX_SURFACE_DATA_BYTES - canonical_json_bytes(&content)?.len();
    content.data_model.insert("padding".into(), json!("x".repeat(padding)));
    assert_eq!(canonical_json_bytes(&content)?.len(), MAX_SURFACE_DATA_BYTES);
    let request = crate::SurfaceSendRequest::event(
        conversation,
        1,
        &A2uiConversationCommand::CreateSurface(content),
    )?;
    let mut carrier = Carrier {
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: conversation.into(),
        surface_id: surface.into(),
        message_id: request.message_id,
        sender_principal_id: source
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone(),
        sender_device_id: source
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .device_id
            .clone(),
        author_principal_id: source
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .principal_id
            .clone(),
        wire_base64: request.wire_base64,
        signature: String::new(),
        snapshot: None,
    };
    source.attach_surface_snapshot(&mut carrier)?;
    carrier = source.sign_surface_carrier(carrier)?;
    Ok(carrier)
}
fn finalize_all_blocks(
    source: &RamfluxClient,
    carrier: &Carrier,
    epoch: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_protocol::StreamAppendCommand;
    for i in 0..64 {
        let wire = ramflux_protocol::encode_a2ui_conversation_event(
            &carrier.conversation_id,
            i + 2,
            &A2uiConversationCommand::StreamAppend(StreamAppendCommand {
                surface_id: carrier.surface_id.clone(),
                component_id: format!("block-{i}"),
                text_delta: String::new(),
                final_: true,
            }),
        )?;
        let mut delta = carrier.clone();
        delta.message_id = crate::new_surface_message_id()?;
        delta.wire_base64 = ramflux_protocol::encode_base64url(wire);
        delta.snapshot = None;
        source.attach_surface_snapshot(&mut delta)?;
        delta = source.sign_surface_carrier(delta)?;
        if carrier.conversation_id.len() <= 32 && carrier.sender_device_id.len() <= 32 {
            assert!(delta.bytes()?.len() < 2048);
        } else {
            assert!(delta.bytes()?.len() < crate::client::surface::MAX_DELIVERY_BYTES / 8);
        }
        assert!(!delta.snapshot.as_ref().ok_or("result hash")?.is_full());
        assert!(source.stage_surface_outgoing(&delta, Some(epoch))?.accepted);
    }
    Ok(())
}

#[tokio::test]
async fn maximum_identifiers_full_state_and_all_finality_fit_resync_and_real_dm_frame_with_margin()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-max-ids");
    let mut source =
        runtime_tests::account(&root, "sender", None, Arc::new(AtomicBool::new(false)))?;
    let principal = "a".repeat(256);
    let device = "d".repeat(256);
    let conversation = "c".repeat(256);
    let surface = "s".repeat(256);
    let remote = "r".repeat(256);
    source.client.create_identity_root(&principal, [97; 32]);
    source.client.create_device_branch(&principal, &device, 1, [98; 32]);
    source.client.account_db()?.persist_client_record(
        "conversation",
        &conversation,
        &json!({"kind":"direct","participants":[principal,"peer"]}),
    )?;
    let mut create = maximal_carrier_in(&source.client, &conversation, &surface)?;
    create.message_id = "m".repeat(256);
    create = source.client.sign_surface_carrier(create)?;
    assert!(source.client.stage_surface_outgoing(&create, None)?.accepted);
    finalize_all_blocks(&source.client, &create, 1)?;
    let mut resync =
        source.client.prepare_surface_resync(&create.surface_reference()?, &"z".repeat(256))?;
    // Transport framing must also fit the longest valid I-JSON version representation.
    let mut wire: Value =
        serde_json::from_slice(&ramflux_protocol::decode_base64url(&resync.wire_base64)?)?;
    wire["version"] = json!(9_007_199_254_740_991_u64);
    resync.wire_base64 =
        ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&wire)?);
    resync.snapshot.as_mut().ok_or("compact proof")?.metadata.as_mut().ok_or("metadata")?["version"] =
        wire["version"].clone();
    resync.posted_at = Some(253_402_300_799);
    resync.updated_at = Some(253_402_300_799);
    resync = source.client.sign_surface_carrier(resync)?;
    source.client.verify_surface_carrier(&resync, &principal, &device)?;
    let bytes = resync.bytes()?;
    let margin = crate::client::surface::MAX_DELIVERY_BYTES
        .checked_sub(bytes.len())
        .ok_or("maximum identifiers exceeded carrier cap")?;
    assert!(margin >= 128, "carrier margin {margin}");
    let session = ramflux_crypto::DmSession::initiator(
        [75; 32],
        dm_device_id_hash(&device),
        dm_device_id_hash(&remote),
        [3; 32],
    )?;
    source.client.persist_pair(&device, &remote, &[4; 32], &session)?;
    let config = GatewaySessionConfig::tcp_tls(crate::GatewayTcpTlsEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: "127.0.0.1:1".parse()?,
        server_name: "unused-test".into(),
        ca_cert: root.join("unused.pem"),
        principal_id: principal.clone(),
        device_id: device.clone(),
        target_delivery_id: device.clone(),
        prekey_http_url: None,
    })
    .with_device_branch(source.client.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?);
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let lengths = gateway.frame_lengths.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
    let mut message = GatewayDirectMessage {
        conversation_id: conversation,
        message_id: "l".repeat(256),
        envelope_id: "e".repeat(256),
        source_principal_id: principal,
        sender_id: device,
        recipient_device_id: Some(remote.clone()),
        target_delivery_id: remote,
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 600,
    };
    message.encrypted_body = serde_json::to_vec(&source.client.seal_routed_federated_as(
        &engine,
        &message,
        &bytes,
        None,
        crate::client::routed::Route::direct(),
    )?)?;
    engine
        .submit_envelope(gateway_direct_message_envelope(&engine.config, &message, None)?)
        .await?;
    let measured = lengths.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0];
    assert!(measured + 64 * 1024 < ramflux_transport::MAX_GATEWAY_FRAME_BYTES);
    eprintln!(
        "max-id resync carrier={} margin={} DM frame={} margin={}",
        bytes.len(),
        margin,
        measured,
        ramflux_transport::MAX_GATEWAY_FRAME_BYTES - measured
    );
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
