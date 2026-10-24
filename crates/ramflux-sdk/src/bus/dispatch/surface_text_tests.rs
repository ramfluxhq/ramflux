// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface delivery exercises the same synchronous group adapter as text.
use super::*;
use crate::bus::runtime_tests;
use crate::client::surface::SurfaceSender;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
struct Delivery {
    envelope: ramflux_protocol::Envelope,
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
    let peers = members(&root, &source)?;
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

fn members(
    root: &std::path::Path,
    source: &LocalBusAccountState,
) -> Result<Vec<LocalBusAccountState>, SdkError> {
    members_count(root, source, 99)
}
fn members_count(
    root: &std::path::Path,
    source: &LocalBusAccountState,
    count: u8,
) -> Result<Vec<LocalBusAccountState>, SdkError> {
    source.client.create_group("group", "device-sender")?;
    let mut peers = Vec::new();
    let sender_root = super::fixture::manifest(&source.client)?.principal_commitment;
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
            &json!({"principal_id":"sender","principal_commitment":sender_root,"signing_public_key":sender_key}),
        )?;
        peers.push(peer);
    }
    Ok(peers)
}
fn assert_receivers(
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
        peer.client.pin_joined_group_member("group", "device-sender")?;
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

async fn directory_config(
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
    let mut forged_route = carrier.clone();
    forged_route.message_id = crate::new_surface_message_id()?;
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
async fn task_group_and_own_control_bodies_fit_actual_encoded_gateway_frames()
-> Result<(), Box<dyn std::error::Error>> {
    use super::super::task_transport;
    use ramflux_protocol::{TaskEvent, TaskEventBody, TaskStart};
    let root = runtime_tests::root("task-frame-budget");
    let mut source = runtime_tests::account(
        &root.join("sender"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let peers = members_count(&root, &source, 1)?;
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
    let peer = &peers[0];
    let manifest = super::fixture::manifest(&peer.client)?;
    source.client.persist_identity_directory(&manifest)?;
    source.client.pin_joined_group_member("group", "device-peer-0")?;
    let event = TaskEvent::new(
        "thread".into(),
        TaskEventBody::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "sender".into(),
            assignee: "peer-0".into(),
            text: "🦀".repeat(1800),
            constraints: None,
        }),
        sdk_device_signed_fields("device-sender", ""),
    )?;
    let c = source.client.sign_task_event(event, "large-task".into(), None)?;
    let result = task_transport::send(&mut source, &c).await?;
    assert_eq!(result["accepted"], true);
    let before = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    assert_eq!(before, 2);
    let mut engine = source.take_live_engine().await?;
    let target = task_transport::Target {
        device: "device-peer-0".into(),
        delivery: "peer-0".into(),
        federation: None,
        own: true,
    };
    let page = vec![b'"'; crate::client::task::MAX_DELIVERY_BYTES];
    let delivery = task_transport::seal(
        &source,
        &mut engine,
        &target,
        "thread",
        &page,
        crate::client::routed::Route {
            kind: crate::client::routed::Kind::Control,
            group_id: Some("group".into()),
            attachments: false,
        },
    )
    .await?;
    source.put_engine(engine);
    crate::bus::task_delivery::submit_all(&mut source, vec![delivery]).await?;
    assert_eq!(
        captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
        before + 1
    );
    let mut oversized = c.clone();
    oversized.wire_base64 = "x".repeat(crate::client::task::MAX_DELIVERY_BYTES);
    assert!(matches!(
        task_transport::send(&mut source, &oversized).await,
        Err(SdkError::TaskDeliveryTooLarge { .. })
    ));
    assert_eq!(
        captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
        before + 1,
        "over-cap rejection must precede sealing and submission"
    );
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
