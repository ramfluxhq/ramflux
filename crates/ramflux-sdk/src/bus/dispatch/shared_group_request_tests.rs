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
    Box::pin(check_request_round_trip(false, None)).await
}
#[tokio::test]
async fn r5_group_result_created_after_the_flush_start_is_sent_in_the_same_round() -> TestResult {
    Box::pin(check_request_round_trip(true, None)).await
}
#[tokio::test]
async fn a_poisoned_deadline_does_not_stop_encrypted_group_requests_or_results() -> TestResult {
    for prefix in ["pending", "lease", "send"] {
        Box::pin(check_request_round_trip(false, Some(prefix))).await?;
    }
    Ok(())
}
async fn check_request_round_trip(step_clock: bool, poisoned_deadline: Option<&str>) -> TestResult {
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
    if let Some(prefix) = poisoned_deadline {
        poison_deadlines(&[&owner.client, &admin.client], prefix)?;
    }
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
    Box::pin(receive_control(&mut owner, config.clone(), request, &pool)).await?;
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
    let sent = flush_owner_requests(&mut owner, step_clock).await?;
    let current = owner
        .client
        .account_db()?
        .shared_group_state("group")?
        .ok_or(StorageError::GroupPermissionDenied)?;
    assert_eq!(current.view().epoch, 3);
    assert_eq!(sent, 1, "a newly committed result is immediately eligible for delivery");
    assert_eq!(current.view().name.as_deref(), Some("Requested name"));
    let result = replies.lock().map_err(|_| "reply lock")?[0].clone();
    Box::pin(receive_control(&mut admin, admin_config, result, &pool)).await?;
    if let Some(prefix) = poisoned_deadline {
        assert_poisoned_deadlines(&[&owner.client, &admin.client], prefix)?;
    }
    assert_result_did_not_replace_snapshot(&admin.client)?;
    admin.client.accept_shared_group_state(&current, "device-peer-one")?;
    assert_eq!(admin.client.group_state("group")?.group_epoch, 3);
    assert_eq!(owner.client.direct_messages("group-thread")?.len(), 0);
    assert_eq!(admin.client.direct_messages("group-thread")?.len(), 0);
    Box::pin(reject_demoted_federated_add(
        &mut owner.client,
        &admin.client,
        &peers[0].client,
        &owner.gateway_config,
    ))
    .await?;
    directory.abort();
    drop((owner, admin, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn receive_control(
    account: &mut LocalBusAccountState,
    config: GatewaySessionConfig,
    envelope: ramflux_protocol::Envelope,
    pool: &ramflux_transport::RelayQuicPool,
) -> TestResult {
    let incoming = request_entry(1, envelope);
    let mut receiver = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    account.client.apply_routed_entry(&mut receiver, pool, &incoming, false).await?;
    Ok(())
}

fn poison_deadlines(clients: &[&RamfluxClient], prefix: &str) -> TestResult {
    for client in clients {
        client.account_db()?.persist_actor_state(
            &format!("group-transfer/{prefix}/!poison"),
            &serde_json::json!({"invalid":true,"expires_at":now_unix_timestamp() + 3600}),
        )?;
    }
    Ok(())
}
fn assert_poisoned_deadlines(clients: &[&RamfluxClient], prefix: &str) -> TestResult {
    for client in clients {
        assert!(
            client.account_db()?.actor_state_exists(&format!("group-transfer/{prefix}/!poison"))?,
            "failed item stays retryable"
        );
    }
    Ok(())
}

async fn flush_owner_requests(
    owner: &mut LocalBusAccountState,
    step_clock: bool,
) -> Result<usize, SdkError> {
    if !step_clock {
        return crate::bus::shared_group_sync::flush_requests(owner).await;
    }
    let at = now_unix_timestamp();
    let mut phase = 0;
    crate::bus::shared_group_sync::flush_requests_with_clock(owner, || {
        phase += 1;
        if phase == 1 { at - 10 } else { at + 10 }
    })
    .await
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

async fn reject_demoted_federated_add(
    owner: &mut RamfluxClient,
    admin: &RamfluxClient,
    sibling: &RamfluxClient,
    config: &GatewaySessionConfig,
) -> TestResult {
    let request = admin.stage_group_change_request(
        "group",
        "device-peer-one",
        ramflux_protocol::GroupStateChange::Add {
            member: sibling.owned_group_actor("device-peer-two")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some("stale-federation-add"),
    )?;
    let before = owner.shared_group_change(
        "group",
        "sender",
        ramflux_protocol::GroupStateChange::SetRole {
            root_commitment: admin.owned_device_identity()?.root_commitment().into(),
            device_id: "device-peer-one".into(),
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let packet = crate::client::shared_group::GroupControlPacket::new(
        crate::client::shared_group::GroupControlBody::Request {
            request: request.clone(),
            federation: Some(LocalBusFederationRoute {
                federation_url: "invalid://must-not-fetch".into(),
                source_node_id: "source".into(),
                target_node_id: "remote".into(),
                required_capability: "opaque_event".into(),
                admin_token: None,
                recipient_prekey_url: Some("invalid://must-not-fetch".into()),
            }),
        },
    );
    let mut sender = GatewaySessionEngine::with_test_transport(
        admin_gateway(config, admin)?,
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let mut message = GatewayDirectMessage {
        conversation_id: "group-thread".into(),
        message_id: "stale-add".into(),
        envelope_id: "stale-add-envelope".into(),
        source_principal_id: sender.config.principal_id.clone(),
        sender_id: sender.config.device_id.clone(),
        recipient_device_id: Some(config.device_id.clone()),
        recipient_principal_commitment: Some(
            owner.owned_device_identity()?.root_commitment().into(),
        ),
        target_delivery_id: config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    message.encrypted_body = serde_json::to_vec(
        &admin
            .seal_routed_as(
                &mut sender,
                &message,
                &serde_json::to_vec(&packet)?,
                crate::client::routed::Route::group_control("group"),
            )
            .await?,
    )?;
    let incoming = request_entry(
        2,
        crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
    );
    let mut receiver = GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(super::fixture::RecordingGateway::new(Arc::default())),
    );
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    owner.apply_routed_entry(&mut receiver, &pool, &incoming, false).await?;
    assert_eq!(
        owner.process_group_request(&request, "sender")?.status,
        ramflux_protocol::GroupChangeStatus::PermissionDenied
    );
    assert_eq!(
        owner
            .account_db()?
            .shared_group_state("group")?
            .ok_or(StorageError::GroupPermissionDenied)?
            .view(),
        before.view()
    );
    Ok(())
}

fn request_entry(inbox_seq: u64, envelope: ramflux_protocol::Envelope) -> GatewayInboxEntry {
    GatewayInboxEntry {
        forwarded: false,
        inbox_seq,
        target_delivery_id: envelope.target_delivery_id.clone(),
        envelope,
    }
}

fn assert_result_did_not_replace_snapshot(client: &RamfluxClient) -> TestResult {
    assert_eq!(client.group_change_statuses(Some("group"))?["requests"][0]["status"], "applied");
    assert_eq!(
        client.group_state("group")?.group_epoch,
        2,
        "result cannot substitute for a creator snapshot"
    );
    Ok(())
}
