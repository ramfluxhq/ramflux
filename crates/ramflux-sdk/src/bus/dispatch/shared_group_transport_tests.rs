// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted group-state fanout across partial drains and one failed recipient.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn pending(client: &RamfluxClient) -> Result<Value, SdkError> {
    client
        .account_db()?
        .list_actor_states::<Value>("group-state/send/")?
        .into_iter()
        .next()
        .ok_or_else(|| SdkError::LocalBus("expected pending group state".into()))
}
fn create_group(
    source: &RamfluxClient,
    target: ramflux_protocol::group_state::GroupMemberIdentity,
) -> Result<(), SdkError> {
    source.shared_group_create("group", "group-thread", Some("Shared name".into()), "sender")?;
    source.shared_group_change(
        "group",
        "sender",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: target,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    Ok(())
}
#[tokio::test]
async fn shared_group_routed_fanout_resumes_one_round_and_one_failed_device_does_not_hide_siblings()
-> TestResult {
    let root = runtime_tests::root("group-routed-fanout");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let devices = [
        "device-peer-0",
        "device-peer-1",
        "device-peer-2",
        "device-peer-3",
        "device-peer-4",
        "device-peer-5",
    ];
    let super::dm_tests::PeerFixture { mut peers, config, address: _, directory } =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &devices).await?;
    source.gateway_config = config.clone();
    source.target_delivery_id = config.target_delivery_id.clone();
    source.principal_commitment = source.client.owned_device_identity()?.root_commitment().into();
    let target = peers[0].client.owned_group_actor(devices[0])?.identity;
    create_group(&source.client, target)?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = super::fixture::RecordingGateway::new(captured.clone());
    gateway.fail_target = Some(devices[0].into());
    source.put_engine(GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway)));
    assert_eq!(crate::bus::shared_group_sync::flush(&mut source).await?, 3);
    let first = pending(&source.client)?;
    assert_eq!(first["attempt"], 1);
    assert_eq!(first["round_active"], true);
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    assert_work_window_yields(&mut source, first).await?;
    assert_eq!(crate::bus::shared_group_sync::flush(&mut source).await?, 2);
    let mut second = pending(&source.client)?;
    assert_eq!(second["attempt"], 1, "partial drains do not consume another retry");
    assert_eq!(second["round_active"], false);
    second["next_at"] = json!(0);
    let id = format!("group-state/send/{}", ramflux_protocol::encode_base64url("group"));
    source.client.account_db()?.persist_actor_state(&id, &second)?;
    assert_eq!(crate::bus::shared_group_sync::flush(&mut source).await?, 1);
    assert_eq!(
        source.client.account_db()?.list_actor_states::<Value>("group-state/send/")?.len(),
        0
    );
    let entries = captured.lock().map_err(|_| "capture lock")?.clone();
    assert_eq!(entries.len(), 6);
    let body =
        source.client.encrypt_group_message("group", "device-sender", b"first group message")?;
    let encrypted: crate::group::SdkGroupEncryptedEnvelope = serde_json::from_slice(&body)?;
    for envelope in entries {
        let index = devices
            .iter()
            .position(|device| *device == envelope.target_delivery_id)
            .ok_or("unexpected target")?;
        let peer = &mut peers[index];
        let root_commitment = source.client.owned_device_identity()?.root_commitment().to_owned();
        peer.client.establish_friend_link("owner-consent", "peer", &root_commitment)?;
        let mut receiver = config.clone();
        receiver.principal_id = "peer".into();
        receiver.device_id = devices[index].into();
        receiver.target_delivery_id = devices[index].into();
        let mut receiver = GatewaySessionEngine::with_test_transport(
            receiver.with_account_identity(&peer.client)?,
            Box::new(super::fixture::RecordingGateway::new(Arc::default())),
        );
        let pool = ramflux_transport::RelayQuicPool::new(
            ramflux_transport::RelayQuicPoolConfig::functional_default()?,
        );
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        peer.client.apply_routed_entry(&mut receiver, &pool, &entry, false).await?;
        assert_eq!(peer.client.group_state("group")?.group_epoch, 2);
        let sender = peer.client.device_identity_for_root(&root_commitment, "device-sender")?;
        assert_eq!(
            peer.client.decrypt_group_envelope_for_identity(
                &encrypted,
                "first-group-message",
                &sender
            )?,
            b"first group message"
        );
    }
    directory.abort();
    drop((source, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn shared_group_member_cap_snapshot_seals_and_submits_within_one_gateway_frame() -> TestResult
{
    use ramflux_protocol::group_state::{
        GroupStateChange, MAX_GROUP_STATE_BYTES, MAX_GROUP_STATE_MEMBERS, SharedGroupRole,
    };
    let root = runtime_tests::root("group-frame-cap");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { peers, config, address: _, directory } =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &["device-peer-0"]).await?;
    create_group(&source.client, peers[0].client.owned_group_actor("peer-0")?.identity)?;
    populate_member_cap(&source.client)?;
    let state = source
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(state.view().members.len(), MAX_GROUP_STATE_MEMBERS);
    let extra = ramflux_crypto::certify_group_state_actor(
        &ramflux_crypto::create_identity_root("extra", [250; 32]),
        &ramflux_crypto::create_device_branch("extra", "extra", 1, [251; 32]),
        "extra",
    )?
    .identity;
    assert!(matches!(
        source.client.shared_group_change(
            "group",
            "sender",
            GroupStateChange::Add { member: extra, role: SharedGroupRole::Member }
        ),
        Err(SdkError::Crypto(CryptoError::Protocol(
            ramflux_protocol::ProtocolError::GroupStateLimit(
                ramflux_protocol::group_state::GroupStateLimit::Members
            )
        )))
    ));
    let payload = source.client.shared_group_packet(&state, true)?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let gateway = super::fixture::RecordingGateway::new(captured.clone());
    let lengths = gateway.frame_lengths.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(config.clone(), Box::new(gateway));
    let recipient = peers[0].client.owned_device_identity()?;
    let mut message = GatewayDirectMessage {
        conversation_id: "group-thread".into(),
        message_id: "max-state".into(),
        envelope_id: "max-state".into(),
        source_principal_id: config.principal_id.clone(),
        sender_id: config.device_id.clone(),
        recipient_device_id: Some(recipient.device_id().into()),
        recipient_principal_commitment: Some(recipient.root_commitment().into()),
        target_delivery_id: "peer-0".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let sealed = source
        .client
        .seal_routed_as(
            &mut engine,
            &message,
            &payload,
            crate::client::routed::Route::group_control("group"),
        )
        .await?;
    message.encrypted_body = serde_json::to_vec(&sealed)?;
    engine
        .submit_envelope(crate::dm::gateway_direct_message_envelope(&config, &message, None)?)
        .await?;
    assert_eq!(captured.lock().map_err(|_| "capture lock")?.len(), 1);
    let state_bytes = ramflux_protocol::canonical_json_bytes(state.snapshot())?.len();
    let frame_bytes = *lengths.lock().map_err(|_| "length lock")?.last().ok_or("missing submit")?;
    eprintln!(
        "group cap: members={} state_bytes={state_bytes} frame_bytes={frame_bytes} budget={MAX_GROUP_STATE_BYTES}",
        state.view().members.len()
    );
    assert!(state_bytes <= MAX_GROUP_STATE_BYTES);
    assert!(frame_bytes <= 10 * state_bytes + 64 * 1024);
    assert!(frame_bytes <= 1024 * 1024);
    drop((source, peers, directory));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn assert_work_window_yields(source: &mut LocalBusAccountState, first: Value) -> TestResult {
    let mut window = first;
    window["round_devices"] = json!(1024);
    let window_id = format!("group-state/send/{}", ramflux_protocol::encode_base64url("group"));
    source.client.account_db()?.persist_actor_state(&window_id, &window)?;
    assert_eq!(
        crate::bus::shared_group_sync::flush(source).await?,
        0,
        "work window yields instead of rejecting the group"
    );
    let yielded = pending(&source.client)?;
    assert_eq!(yielded["round_active"], true);
    assert_eq!(yielded["attempt"], 1);
    assert_eq!(yielded["round_devices"], 0);
    Ok(())
}

fn populate_member_cap(client: &RamfluxClient) -> TestResult {
    for index in 2..ramflux_protocol::group_state::MAX_GROUP_STATE_MEMBERS {
        let mut seed = [0xd5; 32];
        seed[..8].copy_from_slice(&u64::try_from(index)?.to_le_bytes());
        let identity = ramflux_crypto::certify_group_state_actor(
            &ramflux_crypto::create_identity_root(&format!("member-{index}"), seed),
            &ramflux_crypto::create_device_branch(
                &format!("member-{index}"),
                &format!("phone-{index}"),
                1,
                seed,
            ),
            &format!("target-{index}"),
        )?
        .identity;
        client.shared_group_change(
            "group",
            "sender",
            ramflux_protocol::group_state::GroupStateChange::Add {
                member: identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn shared_group_removal_is_delivered_first_above_forty_pending_groups_without_a_seed()
-> TestResult {
    use ramflux_protocol::group_state::GroupStateChange;
    let root = runtime_tests::root("group-priority-delivery");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { peers, config, address: _, directory } =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &["device-peer-0"]).await?;
    source.gateway_config = config.clone();
    source.target_delivery_id = config.target_delivery_id.clone();
    source.principal_commitment = source.client.owned_device_identity()?.root_commitment().into();
    for index in 0..40 {
        source.client.shared_group_create(
            &format!("pending-{index}"),
            &format!("thread-{index}"),
            None,
            "sender",
        )?;
    }
    let peer = &peers[0].client;
    create_group(&source.client, peer.owned_group_actor("peer-0")?.identity)?;
    let removed = source.client.shared_group_change(
        "group",
        "sender",
        GroupStateChange::Remove {
            root_commitment: peer.owned_device_identity()?.root_commitment().into(),
            device_id: "device-peer-0".into(),
        },
    )?;
    source.client.shared_group_change(
        "group",
        "sender",
        GroupStateChange::SetName { name: "Private later title".into() },
    )?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::fixture::RecordingGateway::new(captured.clone())),
    ));
    assert_eq!(crate::bus::shared_group_sync::flush(&mut source).await?, 1);
    let envelopes = captured.lock().map_err(|_| "capture lock")?.clone();
    assert_eq!(envelopes.len(), 1);
    let envelope = envelopes.into_iter().next().ok_or("missing boundary")?;
    assert_eq!(envelope.target_delivery_id, "device-peer-0");
    peer.establish_friend_link(
        "owner-consent",
        "sender",
        source.client.owned_device_identity()?.root_commitment(),
    )?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    };
    let opened = peer.open_routed(&entry, "device-peer-0")?;
    let packet: Value = serde_json::from_slice(&opened.body)?;
    assert!(packet.get("distribution_base64").is_none());
    let snapshot = ramflux_protocol::decode_base64url(
        packet["snapshot_base64"].as_str().ok_or("missing proof")?,
    )?;
    let verified = ramflux_crypto::verify_group_state_snapshot(
        ramflux_protocol::group_state::GroupStateSnapshot::from_wire_bytes(&snapshot)?,
    )?;
    assert_eq!(verified.view(), removed.view());
    assert_eq!(verified.view().name.as_deref(), Some("Shared name"));
    let alias = other_root_snapshot(&config)?;
    assert!(matches!(peer.verify_shared_group_source(&config, &alias, &entry).await,
        Err(SdkError::InboundRejected(reason)) if reason == "group state issuer differs from authenticated transport"));
    directory.abort();
    drop((source, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn other_root_snapshot(
    config: &GatewaySessionConfig,
) -> Result<ramflux_crypto::VerifiedGroupState, SdkError> {
    let root = ramflux_crypto::create_identity_root(&config.principal_id, [7; 32]);
    let branch =
        ramflux_crypto::create_device_branch(&config.principal_id, &config.device_id, 1, [8; 32]);
    let actor =
        ramflux_crypto::certify_group_state_actor(&root, &branch, &config.target_delivery_id)?;
    Ok(ramflux_crypto::create_group_state(
        &root,
        &branch,
        &actor,
        ramflux_crypto::GroupStateCreateInput {
            group_id: "group",
            conversation_id: "thread",
            max_members: 200,
            new_member_history: "no_history",
            name: None,
            now: now_unix_timestamp(),
        },
    )?)
}
