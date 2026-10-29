// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native consent uses the production directory projection and ordinary send transport.
use super::*;
use crate::client::native_test_support::{Fixture as NativeFixture, TestResult};

#[tokio::test]
async fn native_contact_request_crosses_the_ordinary_transport_before_first_direct_message()
-> TestResult {
    let sender = NativeFixture::with_device("native-transport-alice", "alice-device").await?;
    let target = NativeFixture::with_device("native-transport-bob", "bob-device").await?;
    let directory = Directory::from_records(
        &sender.root.0,
        vec![sender.manifest.clone(), target.manifest.clone()],
    )
    .await?;
    let mut config = sender.config.clone();
    config.transport_kind = GatewaySessionTransportKind::TcpTls;
    config.gateway_addr = directory.addr;
    config.tcp_gateway_addr = Some(directory.addr);
    config.server_name = "directory.test".into();
    config.ca_cert = directory.ca.clone();
    let mut engine = GatewaySessionEngine::with_test_transport(
        config,
        Box::new(DirectorySession {
            captured: directory.captured.clone(),
            incoming: directory.incoming.clone(),
            acknowledged: directory.acknowledged.clone(),
            records: directory.records.clone(),
            unavailable: directory.unavailable.clone(),
            responses: VecDeque::new(),
        }),
    );
    sender.client.persist_fetched_identity_directory(&target.manifest)?;
    sender.client.stage_contact_request(&target.manifest, "native-transport-contact", None)?;
    let mut intent = sender
        .client
        .account_db()?
        .list_actor_states::<crate::client::contact_requests::delivery::Intent>(
            "contact-request/send/",
        )?
        .pop()
        .ok_or("intent missing")?;
    let outcome = crate::client::contact_requests::delivery::deliver(
        &sender.client,
        &mut engine,
        &mut intent,
    )
    .await?;
    assert_eq!(outcome, (1, true));
    let entry = directory.captured.lock().map_err(|_| "capture poisoned")?[0].clone();
    let entry = GatewayInboxEntry {
        inbox_seq: 1,
        target_delivery_id: entry.target_delivery_id.clone(),
        envelope: entry,
    };
    let (route, body) = target
        .client
        .preview_native_contact_request(&entry, &sender.manifest, "bob-device")?
        .ok_or("native contact preview absent")?;
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &body,
            Some(&sender.manifest),
        )
        .await?;
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "bob-device")?;
    let message = GatewayDirectMessage {
        conversation_id: "native-transport-thread".into(),
        message_id: "first-direct".into(),
        envelope_id: "first-direct".into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: "alice-device".into(),
        recipient_device_id: Some("bob-device".into()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.client.owned_device_identity()?.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    sender.client.seal_routed_as(&mut engine, &message, b"first message", Route::direct()).await?;
    Ok(())
}
