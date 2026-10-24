// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local cryptographic proof through the prepared standard group transport (no network).
use super::*;
use crate::bus::{runtime_tests, surface_jobs};
use crate::client::surface::SurfaceSender;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex, atomic::AtomicBool};

#[tokio::test]
async fn hundred_device_group_receives_one_sender_key_surface_and_retries_retained_ciphertexts()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-hundred-group");
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
    let epoch = source.client.group_state("group")?.group_epoch;
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let command = A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
        surface_id: "surface".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "中文 é 🦀".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"result","text":"done"})],
        data_model: serde_json::Map::default(),
        allowed_actions: Vec::new(),
    });
    let request = crate::SurfaceSendRequest::event("thread", 1, &command)?;
    let carrier = source.client.sign_surface_carrier(Carrier {
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
    })?;
    let plan =
        plan(&source, &carrier)?.ok_or_else(|| SdkError::LocalBus("group plan absent".into()))?;
    assert_eq!(plan.routes.len(), 99);
    surface_jobs::admit(&source, 1, plan.bytes)?;
    let deliveries = prepare(&mut source, &carrier, plan).await?;
    assert_eq!(deliveries.len(), 198);
    assert_receivers(&peers, &deliveries, epoch, 1)?;
    assert_full_queue_preserves_ratchets(&mut source, &carrier, &deliveries[0].envelope).await?;
    // 198 physical envelopes occupy one admitted publication, with no 64-recipient ceiling.
    surface_jobs::enqueue_group(&source, deliveries)?;
    let rows = source.client.account_db()?.surface_history_page::<serde_json::Value>(
        "surface/transport/",
        "surface/transport/",
        65,
    )?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["deliveries"].as_array().map(Vec::len), Some(198));
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut sent = 0;
    while sent < 198 && std::time::Instant::now() < deadline {
        sent += surface_jobs::run(&mut source).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(sent, 198);
    let remaining = source.client.account_db()?.surface_history_page::<serde_json::Value>(
        "surface/transport/",
        "surface/transport/",
        65,
    )?;
    assert_eq!(remaining, Vec::<serde_json::Value>::new());
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
    for i in 0..99u8 {
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
            &json!({"principal_id":"sender","signing_public_key":sender_key}),
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

async fn assert_full_queue_preserves_ratchets(
    source: &mut LocalBusAccountState,
    carrier: &Carrier,
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), SdkError> {
    let epoch = source.client.group_state("group")?.group_epoch;
    let before = serde_json::to_value(source.client.load_group_sender_key_state(
        "group",
        "device-sender",
        epoch,
        "send",
    )?)?;
    let pairs = source.client.account_db()?.surface_history_page::<serde_json::Value>(
        "dm-pair/session/",
        "dm-pair/session/",
        100,
    )?;
    surface_jobs::enqueue(source, vec![envelope.clone(); 64])?;
    let full = super::plan(source, carrier)?.ok_or_else(|| SdkError::LocalBus("plan".into()))?;
    assert!(prepare(source, carrier, full).await.is_err());
    let rows = source.client.account_db()?.surface_record_page::<serde_json::Value>(
        "surface/transport/",
        "surface/transport/",
        65,
    )?;
    for (key, _) in rows {
        source.client.account_db()?.delete_surface_state(&key)?;
    }
    let mut oversized =
        super::plan(source, carrier)?.ok_or_else(|| SdkError::LocalBus("plan".into()))?;
    oversized.bytes = 32 * 1024 * 1024 + 1;
    assert!(prepare(source, carrier, oversized).await.is_err());
    let mut wrong_root =
        super::plan(source, carrier)?.ok_or_else(|| SdkError::LocalBus("plan".into()))?;
    wrong_root.routes[0].member_principal_commitment = Some(source.principal_commitment.clone());
    assert!(prepare(source, carrier, wrong_root).await.is_err());
    assert_eq!(
        serde_json::to_value(source.client.load_group_sender_key_state(
            "group",
            "device-sender",
            epoch,
            "send"
        )?)?,
        before
    );
    assert_eq!(
        source.client.account_db()?.surface_history_page::<serde_json::Value>(
            "dm-pair/session/",
            "dm-pair/session/",
            100
        )?,
        pairs
    );
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

#[tokio::test]
async fn hundred_devices_converge_after_fifty_production_sends_with_real_clock()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-burst");
    let mut source = runtime_tests::account(
        &root.join("sender"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let peers = members(&root, &source)?;
    let epoch = source.client.group_state("group")?.group_epoch;
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let (config, directory) = directory_config(&root, &mut source, &peers).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    let started = std::time::Instant::now();
    author_burst(&mut source).await?;
    let db = source.client.account_db()?;
    let mut rows = db.surface_record_page::<serde_json::Value>(
        "surface/transport/",
        "surface/transport/",
        65,
    )?;
    assert_eq!(rows.len(), 1); // 50 updates retain one full state, not 50 recipient batches.
    assert!(rows[0].1["deliveries"].as_array().is_some_and(Vec::is_empty));
    // An expired coalesced job regenerates the retained full snapshot, with fresh packet TTLs.
    rows[0].1["group"]["enqueued_at"] = json!(now_unix_timestamp() - 601);
    db.persist_actor_state(&rows[0].0, &rows[0].1)?;
    loop {
        super::super::super::sync_driver::run(&mut source).await?;
        if source
            .client
            .account_db()?
            .surface_history_page::<serde_json::Value>(
                "surface/transport/",
                "surface/transport/",
                65,
            )?
            .is_empty()
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "real-clock burst convergence exceeded 120 seconds"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let envelopes =
        std::mem::take(&mut *captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    assert_eq!(envelopes.len(), 198);
    let deliveries = envelopes
        .into_iter()
        .map(|envelope| Delivery {
            envelope,
            federation: None,
            ack_key: None,
            attempts: 0,
            next_at: 0,
        })
        .collect::<Vec<_>>();
    assert_receivers(&peers, &deliveries, epoch, 50)?;
    let hash = source.client.surface_get("surface", 0, None)?["surface_hash"].clone();
    for peer in &peers {
        assert_eq!(peer.client.surface_get("surface", 0, None)?["surface_hash"], hash);
    }
    assert!(started.elapsed() < Duration::from_secs(120));
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn author_burst(source: &mut LocalBusAccountState) -> Result<(), SdkError> {
    for version in 1..=50 {
        let command = if version == 1 {
            A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
                surface_id: "surface".into(),
                surface_type: SurfaceType::StatusPanel,
                catalog: "basic".into(),
                catalog_version: "1".into(),
                fallback_text: "中文 é 🦀".into(),
                fallback_markdown: None,
                components: vec![json!({"id":"result","text":""})],
                data_model: serde_json::Map::default(),
                allowed_actions: Vec::new(),
            })
        } else {
            A2uiConversationCommand::StreamAppend(ramflux_protocol::StreamAppendCommand {
                surface_id: "surface".into(),
                component_id: "result".into(),
                text_delta: version.to_string(),
                final_: false,
            })
        };
        let request = crate::SurfaceSendRequest::event("thread", version, &command)?;
        let mut carrier = Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            payload_kind: PayloadKind::Event,
            conversation_id: "thread".into(),
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
        assert_eq!(
            super::super::surface_transport::send(source, &carrier).await?["accepted"],
            true
        );
    }
    Ok(())
}
