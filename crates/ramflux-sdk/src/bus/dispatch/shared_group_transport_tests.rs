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
