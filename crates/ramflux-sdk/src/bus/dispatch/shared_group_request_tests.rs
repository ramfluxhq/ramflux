// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed admin intent and creator result traverse the real encrypted courier and receive path.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[tokio::test]
async fn shared_group_signed_request_and_result_round_trip_without_admin_state_authority()
-> TestResult {
    let root = runtime_tests::root("group-request-wire");
    let mut owner = runtime_tests::account(
        &root.join("owner"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, directory, .. } =
        super::dm_tests::peer_fixture(&root, &mut owner).await?;
    let mut admin = peers.remove(0);
    owner.gateway_config = config.clone();
    owner.target_delivery_id = config.target_delivery_id.clone();
    let admin_config = admin_gateway(&config, &admin.client)?;
    admin.gateway_config = admin_config.clone();
    admin.target_delivery_id = admin_config.target_delivery_id.clone();
    owner.client.shared_group_create("group", "group-thread", None, "sender")?;
    let base = owner.client.shared_group_change(
        "group",
        "sender",
        ramflux_protocol::GroupStateChange::Add {
            member: admin.client.owned_group_actor("device-peer-one")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    admin.client.accept_shared_group_state(&base, "device-peer-one")?;
    admin.client.stage_group_change_request(
        "group",
        "device-peer-one",
        ramflux_protocol::GroupStateChange::SetName { name: "Requested name".into() },
        Some("wire-request"),
    )?;
    assert_eq!(admin.client.group_state("group")?.group_epoch, 2);
    let outgoing = Arc::new(Mutex::new(Vec::new()));
    admin.put_engine(GatewaySessionEngine::with_test_transport(
        admin_config.clone(),
        Box::new(super::fixture::RecordingGateway::new(outgoing.clone())),
    ));
    assert_eq!(crate::bus::shared_group_sync::flush_requests(&mut admin).await?, 1);
    let request = outgoing.lock().map_err(|_| "capture lock")?[0].clone();
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let incoming = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: request.target_delivery_id.clone(),
        envelope: request,
    };
    let mut receiver = GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    owner.client.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    assert_eq!(
        owner.client.group_state("group")?.group_epoch,
        2,
        "admission alone is not a group mutation"
    );
    let replies = Arc::new(Mutex::new(Vec::new()));
    owner.put_engine(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(replies.clone())),
    ));
    assert_eq!(crate::bus::shared_group_sync::flush_requests(&mut owner).await?, 1);
    let current = owner
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(current.view().epoch, 3);
    assert_eq!(current.view().name.as_deref(), Some("Requested name"));
    let result = replies.lock().map_err(|_| "reply lock")?[0].clone();
    let incoming = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: result.target_delivery_id.clone(),
        envelope: result,
    };
    let mut receiver = GatewaySessionEngine::with_test_transport(
        admin_config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    admin.client.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    assert_eq!(
        admin.client.group_change_statuses(Some("group"))?["requests"][0]["status"],
        "applied"
    );
    assert_eq!(
        admin.client.group_state("group")?.group_epoch,
        2,
        "result cannot substitute for a creator snapshot"
    );
    admin.client.accept_shared_group_state(&current, "device-peer-one")?;
    assert_eq!(admin.client.group_state("group")?.group_epoch, 3);
    assert_eq!(owner.client.direct_messages("group-thread")?.len(), 0);
    assert_eq!(admin.client.direct_messages("group-thread")?.len(), 0);
    directory.abort();
    drop((owner, admin, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn admin_gateway(
    config: &GatewaySessionConfig,
    client: &RamfluxClient,
) -> Result<GatewaySessionConfig, SdkError> {
    let mut admin_config = config.clone();
    admin_config.principal_id = "peer".into();
    admin_config.device_id = "device-peer-one".into();
    admin_config.target_delivery_id = "device-peer-one".into();
    admin_config = admin_config.with_account_identity(client)?;
    Ok(admin_config)
}
