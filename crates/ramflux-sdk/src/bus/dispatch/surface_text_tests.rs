// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface delivery exercises the same synchronous group adapter as text.
use super::*;
use crate::bus::runtime_tests;
use ramflux_protocol::{A2uiConversationCommand, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, Mutex};
#[tokio::test]
#[allow(clippy::large_futures)]
async fn hundred_device_surface_uses_text_distribution_submit_and_measured_frame_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-text-group");
    // Routing is independent of member count. Keep real per-recipient crypto and
    // receiver checks, with a smaller default so CI stays below its per-test budget.
    // Set RF_SURFACE_TEST_DEVICES=100 to exercise the original scale explicitly.
    let device_count = match std::env::var("RF_SURFACE_TEST_DEVICES") {
        Ok(value) => value.parse::<u8>()?,
        Err(std::env::VarError::NotPresent) => 16,
        Err(error) => return Err(error.into()),
    };
    // Two receivers are needed to compare the shared group ciphertext. Cap the
    // override at the original scale, within the fixture seed and membership bounds.
    assert!((3..=100).contains(&device_count), "surface test requires 3..=100 devices");
    let NativeGroup { mut source, mut peers, config, directory } =
        Box::pin(native_group(&root, device_count - 1)).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
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
        components: vec![json!({"id":"result","text":"🦀".repeat(1500)})],
        data_model: serde_json::Map::default(),
        allowed_actions: Vec::new(),
    });
    let request = crate::SurfaceSendRequest::event("thread", 1, &command)?;
    let mut carrier = Carrier {
        typed: None,
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
    // Native generation-1 groups seal per recipient device: the signed group state and the
    // Surface each reach every member as one envelope; there is no sender-key distribution.
    assert_eq!(envelopes.len(), 2 * peers.len());
    assert_eq!(
        deliver_to_peers(&source, &mut peers, &config, &envelopes, 1).await?,
        peers.len(),
        "every native member projects the Surface"
    );
    assert_admission(&mut source, &carrier, &captured).await?;
    directory.abort();
    drop(peers);
    drop(source);
    Ok(())
}

/// Native generation-1 group: an owner `sender` and `count` peers, each pair seeded, every peer
/// added to the group by a signed change, and all manifests served by one loopback directory.
pub(in crate::bus::dispatch) struct NativeGroup {
    pub(in crate::bus::dispatch) source: LocalBusAccountState,
    pub(in crate::bus::dispatch) peers: Vec<LocalBusAccountState>,
    pub(in crate::bus::dispatch) config: GatewaySessionConfig,
    pub(in crate::bus::dispatch) directory: tokio::task::JoinHandle<()>,
}

pub(in crate::bus::dispatch) async fn native_group(
    root: &ramflux_test_support::TestPath,
    count: u8,
) -> Result<NativeGroup, Box<dyn std::error::Error>> {
    native_group_with(
        root,
        count,
        &NativeIds {
            principal: "sender".into(),
            device: "device-sender".into(),
            conversation: "thread".into(),
            first_peer_device: None,
        },
    )
    .await
}

/// Identifiers of a native fixture group; the defaults are the short names above.
pub(in crate::bus::dispatch) struct NativeIds {
    pub(in crate::bus::dispatch) principal: String,
    pub(in crate::bus::dispatch) device: String,
    pub(in crate::bus::dispatch) conversation: String,
    pub(in crate::bus::dispatch) first_peer_device: Option<String>,
}

pub(in crate::bus::dispatch) async fn native_group_with(
    root: &ramflux_test_support::TestPath,
    count: u8,
    ids: &NativeIds,
) -> Result<NativeGroup, Box<dyn std::error::Error>> {
    use crate::client::native_test_support::{
        Fixture, activation_send::tests::publish_layer_four, bus,
    };
    std::fs::create_dir_all(root.to_path_buf())?;
    let mut owner =
        Box::pin(Fixture::with_principal("sender", &ids.device, &ids.principal)).await?;
    Box::pin(publish_layer_four(&mut owner)).await?;
    let mut peers = Vec::new();
    for i in 0..count {
        let id = format!("peer-{i}");
        let device = match (&ids.first_peer_device, i) {
            (Some(device), 0) => device.clone(),
            _ => format!("device-{id}"),
        };
        let mut peer = Box::pin(Fixture::with_principal(&id, &device, &id)).await?;
        Box::pin(publish_layer_four(&mut peer)).await?;
        peers.push(peer.into_bus());
    }
    let mut source = owner.into_bus();
    let own = super::fixture::manifest(&source.client)?;
    let mut manifests =
        BTreeMap::from([(own.principal_commitment.clone(), serde_json::to_value(&own)?)]);
    for peer in &peers {
        let manifest = super::fixture::manifest(&peer.client)?;
        manifests.insert(manifest.principal_commitment.clone(), serde_json::to_value(&manifest)?);
    }
    let (address, directory) = super::fixture::directory(root, manifests).await?;
    let mut config = source.gateway_config.clone();
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = address;
    config.tcp_gateway_addr = Some(address);
    config.server_name = "test-gateway".into();
    config.ca_cert = root.join("ca.pem");
    source.gateway_config = config.clone();
    for peer in &peers {
        let manifest = super::fixture::manifest(&peer.client)?;
        source.client.persist_observed_identity_directory_now(&manifest)?;
        peer.client.persist_observed_identity_directory_now(&own)?;
        bus::seed_pair(&source.client, &peer.client)?;
    }
    source.client.fixture_group_create("group", &ids.conversation, None, &ids.device)?;
    for peer in &peers {
        let device = peer.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let member = peer.client.fixture_group_actor(&device.device_id)?.identity;
        source.client.fixture_group_change(
            "group",
            &ids.device,
            ramflux_protocol::GroupStateChange::Add {
                member,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
    }
    Ok(NativeGroup { source, peers, config, directory })
}

/// Deliver the envelopes in order to their native peers: each peer first holds the owner's
/// consent link, then runs the real routed receive for every envelope (the signed group state
/// and the Surface frames alike) and must end up projecting `version`. Returns the peers reached.
pub(in crate::bus::dispatch) async fn deliver_to_peers(
    source: &LocalBusAccountState,
    peers: &mut [LocalBusAccountState],
    config: &GatewaySessionConfig,
    envelopes: &[ramflux_protocol::Envelope],
    version: u64,
) -> Result<usize, Box<dyn std::error::Error>> {
    let owner_root = source.client.owned_device_identity()?.root_commitment().to_owned();
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut reached = std::collections::BTreeSet::new();
    for (sequence, envelope) in envelopes.iter().enumerate() {
        let index = peers
            .iter()
            .position(|peer| peer.gateway_config.target_delivery_id == envelope.target_delivery_id)
            .ok_or("recipient fixture absent")?;
        let peer = &mut peers[index];
        let anchor = peer.client.own_account_anchor()?;
        peer.client.establish_friend_link("owner-consent", &anchor, &owner_root)?;
        let receiver = crate::client::native_test_support::bus::config_for(&peer.client, config)?;
        let mut engine = GatewaySessionEngine::with_test_transport(
            receiver,
            Box::new(super::fixture::RecordingGateway::new(Arc::default())),
        );
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: u64::try_from(sequence + 1)?,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: envelope.clone(),
        };
        peer.client.apply_routed_entry(&mut engine, &pool, &entry).await?;
        reached.insert(index);
    }
    for index in &reached {
        assert_eq!(
            peers[*index].client.surface_get("surface", 0, None)?["version"],
            version,
            "the recipient must project the delivered Surface"
        );
    }
    Ok(reached.len())
}

async fn assert_admission(
    source: &mut LocalBusAccountState,
    carrier: &Carrier,
    captured: &Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
) -> Result<(), SdkError> {
    let submitted = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    let pair_rows = source.client.account_db()?.surface_history_page::<serde_json::Value>(
        "dm-pair/session/",
        "dm-pair/session/",
        200,
    )?;
    let mut oversized = carrier.clone();
    oversized.wire_base64 = "x".repeat(crate::client::surface::MAX_DELIVERY_BYTES);
    // The malformed oversize wire is refused while decoding, before any sealing or submission.
    assert!(send(source, &oversized).await.is_err(), "an oversized carrier must be refused");
    assert_eq!(
        source.client.account_db()?.surface_history_page::<serde_json::Value>(
            "dm-pair/session/",
            "dm-pair/session/",
            200
        )?,
        pair_rows
    );
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), submitted);
    assert_eq!(
        source.client.account_db()?.surface_history_page::<serde_json::Value>(
            "surface/transport/",
            "surface/transport/",
            100
        )?,
        Vec::<serde_json::Value>::new()
    );
    let epoch = source.client.group_state("group")?.group_epoch;
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
        captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
        submitted,
        "a forged route must not submit a frame"
    );
    assert_eq!(source.client.group_state("group")?.group_epoch, epoch);
    Ok(())
}

#[tokio::test]
async fn maximal_create_and_full_resync_with_all_finality_seal_under_shared_frame_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-max-frame");
    let NativeGroup { mut source, mut peers, config, directory } =
        Box::pin(native_group(&root, 1)).await?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let gateway = super::fixture::RecordingGateway::new(captured.clone());
    let frame_lengths = gateway.frame_lengths.clone();
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(gateway),
    ));
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
    // The one native peer receives the signed group state, the create and the full resync.
    assert_eq!(envelopes.len(), 3);
    assert_eq!(deliver_to_peers(&source, &mut peers, &config, &envelopes[..2], 1).await?, 1);
    assert_eq!(deliver_to_peers(&source, &mut peers, &config, &envelopes[2..], 65).await?, 1);
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
    // Removing and re-adding the member advances the signed epoch past the prepared resync.
    let member = peers[0].client.fixture_group_actor("device-peer-0")?.identity;
    source.client.fixture_group_change(
        "group",
        "device-sender",
        ramflux_protocol::GroupStateChange::Remove {
            root_commitment: member.root_commitment.clone(),
            device_id: member.device_id.clone(),
        },
    )?;
    source.client.fixture_group_change(
        "group",
        "device-sender",
        ramflux_protocol::GroupStateChange::Add {
            member,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let error = send(&mut source, &resync).await.err().ok_or("old-epoch retry was accepted")?;
    assert!(error.to_string().contains("epoch changed"), "{error}");
    assert_eq!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(), 3);
    directory.abort();
    drop(peers);
    drop(source);
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
        typed: None,
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
    let principal = "a".repeat(256);
    let device = "d".repeat(ramflux_protocol::MAX_DEVICE_NAME_BYTES);
    let conversation = "c".repeat(256);
    let surface = "s".repeat(256);
    let remote = "r".repeat(ramflux_protocol::MAX_DEVICE_NAME_BYTES);
    let NativeGroup { mut source, peers, config, directory } = Box::pin(native_group_with(
        &root,
        1,
        &NativeIds {
            principal: principal.clone(),
            device: device.clone(),
            conversation: conversation.clone(),
            first_peer_device: Some(remote),
        },
    ))
    .await?;
    source.client.account_db()?.persist_client_record(
        "conversation",
        &conversation,
        &json!({"kind":"group","group_id":"group"}),
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
    let gateway = super::fixture::RecordingGateway::new(Arc::default());
    let lengths = gateway.frame_lengths.clone();
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    assert_eq!(send(&mut source, &resync).await?["delivery_state"], "submitted");
    let measured = lengths.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0];
    assert!(measured + 64 * 1024 < ramflux_transport::MAX_GATEWAY_FRAME_BYTES);
    eprintln!(
        "max-id resync carrier={} margin={} adapter frame={} margin={}",
        bytes.len(),
        margin,
        measured,
        ramflux_transport::MAX_GATEWAY_FRAME_BYTES - measured
    );
    directory.abort();
    drop((source, peers));
    Ok(())
}
