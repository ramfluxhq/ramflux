// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Task carrier and own-control frame limits through the real encrypted transport adapters.
use super::super::surface_transport::{
    fixture,
    tests::{directory_config, members as members_count},
};
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
#[tokio::test]
async fn task_group_and_own_control_bodies_fit_actual_encoded_gateway_frames()
-> Result<(), Box<dyn std::error::Error>> {
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
        Box::new(fixture::RecordingGateway::new(captured.clone())),
    ));
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let peer = &peers[0];
    let manifest = fixture::manifest(&peer.client)?;
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
    let result = super::send(&mut source, &c).await?;
    assert_eq!(result["accepted"], true);
    let before = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    assert_eq!(before, 2);
    let mut engine = source.take_live_engine().await?;
    let target = super::Target {
        device: "device-peer-0".into(),
        delivery: "peer-0".into(),
        federation: None,
        own: true,
    };
    let page = vec![b'"'; crate::client::task::MAX_DELIVERY_BYTES];
    let delivery = super::seal(
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
        super::send(&mut source, &oversized).await,
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

#[tokio::test]
async fn requester_cancellation_after_compaction_prepares_original_sibling_events_and_submits_to_peers()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_protocol::{TaskCancel, TaskEvent, TaskEventBody, TaskStart};
    let root = runtime_tests::root("task-compacted-cancel");
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
        Box::new(fixture::RecordingGateway::new(captured.clone())),
    ));
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    source.client.persist_identity_directory(&fixture::manifest(&peers[0].client)?)?;
    source.client.pin_joined_group_member("group", "device-peer-0")?;
    let event = TaskEvent::new(
        "thread".into(),
        TaskEventBody::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "sender".into(),
            assignee: "peer-0".into(),
            text: "work".into(),
            constraints: None,
        }),
        sdk_device_signed_fields("device-sender", ""),
    )?;
    let start = source.client.sign_task_event(event, "start".into(), None)?;
    assert_eq!(super::send(&mut source, &start).await?["accepted"], true);
    let key = crate::client::task::scoped("lifecycle", "thread", "task")?;
    let mut row =
        source.client.account_db()?.load_actor_state::<Value>(&key)?.ok_or("lifecycle")?;
    row["compaction_eligible"] = json!(true);
    source.client.account_db()?.persist_actor_state(&key, &row)?;
    source.client.maintain_task_lifecycle(now_unix_timestamp())?;
    let event = TaskEvent::new(
        "thread".into(),
        TaskEventBody::Cancel(TaskCancel { task_id: "task".into(), base_revision: 1 }),
        sdk_device_signed_fields("device-sender", ""),
    )?;
    let cancel = source.client.sign_task_event(event, "cancel".into(), None)?;
    let bytes = cancel.bytes()?;
    let (own, original) =
        super::own_payloads(&source.client, &cancel, &bytes, &super::Mode::Event)?;
    assert!(original);
    assert_eq!(own, vec![bytes.clone()]);
    assert_eq!(
        super::own_payloads(&source.client, &cancel, &bytes, &super::Mode::Own)?.0,
        Vec::<Vec<u8>>::new()
    );
    let before = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
    assert_eq!(super::send(&mut source, &cancel).await?["accepted"], true);
    assert!(captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len() > before);
    assert_eq!(source.client.task_get(Some("thread"), "task")?["state"], "cancelled");
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn private_task_approvals_are_pair_encrypted_only_to_the_requester_among_group_members()
-> Result<(), Box<dyn std::error::Error>> {
    use ramflux_protocol::{TaskEvent, TaskEventBody, TaskStart};
    let root = runtime_tests::root("task-private-approval");
    let mut source = runtime_tests::account(
        &root.join("sender"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let peers = members_count(&root, &source, 2)?;
    let (config, directory) = directory_config(&root, &mut source, &peers).await?;
    for peer in &peers {
        source.client.persist_identity_directory(&fixture::manifest(&peer.client)?)?;
        source.client.pin_joined_group_member(
            "group",
            &peer.client.device_branch.as_ref().ok_or("peer device")?.device_id,
        )?;
    }
    let captured = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(fixture::RecordingGateway::new(captured.clone())),
    ));
    source.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"group","group_id":"group"}),
    )?;
    let event = TaskEvent::new(
        "thread".into(),
        TaskEventBody::Start(TaskStart {
            task_id: "task".into(),
            conversation_id: "thread".into(),
            requester: "sender".into(),
            assignee: "peer-0".into(),
            text: "work".into(),
            constraints: None,
        }),
        sdk_device_signed_fields("device-sender", ""),
    )?;
    let anchor = source.client.sign_task_event(event, "anchor".into(), None)?;
    super::super::task_approval_transport::send(
        &mut source,
        &anchor.conversation_id,
        "peer-0",
        b"PRIVATE_MCP_ARGUMENTS",
    )
    .await?;
    let envelopes = captured.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_eq!(envelopes.len(), 1, "the unrelated group member receives no approval payload");
    assert_eq!(envelopes[0].target_delivery_id, "peer-0");
    assert!(!serde_json::to_string(&envelopes)?.contains("PRIVATE_MCP_ARGUMENTS"));
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
