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

fn manifest_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn confirmation_preparation_allows_slow_verified_directory_refresh() {
    let outcome = super::await_preparation(
        async { Ok::<_, SdkError>(()) },
        "task confirmation preparation deferred",
    )
    .await;
    assert!(
        matches!(outcome, Ok(super::Preparation::Ready(()))),
        "a ready verified directory refresh must remain deliverable"
    );
}

#[tokio::test]
async fn manifest_worker_capacity_is_the_only_retry_neutral_preparation_outcome() {
    let deferred = super::await_preparation(
        async { Err::<(), _>(SdkError::TaskManifestWorkerCapacity) },
        "worker-cap preparation",
    )
    .await;
    assert!(matches!(deferred, Ok(super::Preparation::Deferred)));

    let charged = super::await_preparation(
        async { Err::<(), _>(SdkError::InboundPending("transport timeout".into())) },
        "charged preparation timeout",
    )
    .await;
    assert!(matches!(charged, Err(SdkError::InboundPending(_))));
}

#[tokio::test]
async fn stalled_federated_manifest_fetch_respects_the_preparation_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;
    use std::sync::mpsc;

    tokio::time::timeout(Duration::from_secs(30), async {
        let _guard = manifest_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || -> Result<(), String> {
            let (stream, _) = listener.accept().map_err(|error| error.to_string())?;
            accepted_tx.send(()).map_err(|error| error.to_string())?;
            release_rx.recv_timeout(Duration::from_secs(10)).map_err(|error| error.to_string())?;
            drop(stream);
            Ok(())
        });
        let started = std::time::Instant::now();
        let outcome = super::await_preparation(
            super::fetch_federated_manifest(&format!("http://{address}"), "stalled-root"),
            "task federated manifest preparation deferred",
        )
        .await;
        assert!(
            !matches!(outcome, Ok(super::Preparation::Ready(_))),
            "a stalled fetch must report its per-item timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(7));
        accepted_rx.recv_timeout(Duration::from_secs(1))?;
        release_tx.send(())?;
        server.join().map_err(|_| "stalled manifest server panicked")??;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "stalled manifest test exceeded its outer timeout")??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_stalled_manifest_fetches_never_exceed_the_global_worker_cap()
-> Result<(), Box<dyn std::error::Error>> {
    use std::net::TcpListener;

    tokio::time::timeout(Duration::from_secs(12), async {
        let _guard = manifest_test_lock().lock().await;
        let listeners =
            (0..12).map(|_| TcpListener::bind("127.0.0.1:0")).collect::<Result<Vec<_>, _>>()?;
        let urls = listeners
            .iter()
            .map(|listener| listener.local_addr().map(|address| format!("http://{address}")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut jobs = tokio::task::JoinSet::new();
        for (index, url) in urls.into_iter().enumerate() {
            jobs.spawn(async move {
                super::fetch_federated_manifest(&url, &format!("stalled-{index}")).await
            });
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire) <= 4);
        let mut capacity_deferrals = 0;
        while let Some(result) = jobs.join_next().await {
            if matches!(result?, Err(SdkError::TaskManifestWorkerCapacity)) {
                capacity_deferrals += 1;
            }
        }
        assert!(capacity_deferrals >= 8, "excess stalled fetches must be deferred");
        drop(listeners);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| "manifest worker cap regression exceeded its outer timeout")??;
    Ok(())
}

#[tokio::test]
async fn manifest_flight_guard_releases_panics_and_groups_by_full_manifest_url()
-> Result<(), Box<dyn std::error::Error>> {
    let _test_guard = manifest_test_lock().lock().await;
    let before = super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire);
    let first = match super::reserve_manifest_flight("http://node/manifest/root-a")? {
        super::ManifestReservation::Start(guard) => guard,
        super::ManifestReservation::Wait(_) => {
            return Err("unexpected existing first flight".into());
        }
    };
    let second = match super::reserve_manifest_flight("http://node/manifest/root-b")? {
        super::ManifestReservation::Start(guard) => guard,
        super::ManifestReservation::Wait(_) => {
            return Err("distinct manifest URL was grouped".into());
        }
    };
    assert!(matches!(
        super::reserve_manifest_flight("http://node/manifest/root-a")?,
        super::ManifestReservation::Wait(_)
    ));
    assert_eq!(
        super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire),
        before + 2
    );
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = first;
        std::panic::resume_unwind(Box::new("manifest worker panic"));
    }));
    assert!(panicked.is_err());
    assert_eq!(
        super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire),
        before + 1
    );
    drop(second);
    assert_eq!(super::manifest_worker_count().load(std::sync::atomic::Ordering::Acquire), before);
    Ok(())
}

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
        identity: source.client.device_identity_for_root(
            &source
                .client
                .account_db()?
                .client_record("identity", "peer-0")?
                .and_then(|r| r["contact_identity_commitment"].as_str().map(str::to_owned))
                .ok_or(SdkError::IdentityRootMissing)?,
            "device-peer-0",
        )?,
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
    defer_then_drain_confirmation_jobs(&mut source, &c).await?;
    directory.abort();
    drop(peers);
    drop(source);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn defer_then_drain_confirmation_jobs(
    source: &mut LocalBusAccountState,
    carrier: &Carrier,
) -> Result<(), Box<dyn std::error::Error>> {
    let (ack_key, forward_key) = store_healthy_confirmation_jobs(source, carrier)?;
    let mut malformed = source
        .client
        .account_db()?
        .load_actor_state::<crate::client::task::control::AckJob>(&ack_key)?
        .ok_or("healthy acknowledgement missing")?;
    malformed.ack.carrier_base64 = "not-base64".into();
    source.client.account_db()?.persist_actor_state("task/ack/000-malformed", &malformed)?;
    let now = now_unix_timestamp();
    let mut thread = source
        .client
        .account_db()?
        .client_record("conversation", "thread")?
        .ok_or("conversation")?;
    thread["test_preparation_outcome"] = json!("worker_capacity");
    source.client.account_db()?.persist_client_record("conversation", "thread", &thread)?;
    let deferred = super::drain_confirmations_at(source, now).await?;
    assert_eq!(deferred, 0);
    assert!(!source.client.account_db()?.actor_state_exists("task/ack/000-malformed")?);
    assert!(source.client.account_db()?.actor_state_exists("task/ack_quarantine/000-malformed")?);
    let deferred_ack = source
        .client
        .account_db()?
        .load_actor_state::<crate::client::task::control::AckJob>(&ack_key)?
        .ok_or("capacity-deferred acknowledgement missing")?;
    let deferred_forward = source
        .client
        .account_db()?
        .load_actor_state::<crate::client::task::control::ForwardJob>(&forward_key)?
        .ok_or("capacity-deferred forward missing")?;
    assert_eq!((deferred_ack.attempts, deferred_ack.next_at), (0, 0));
    assert_eq!((deferred_forward.attempts, deferred_forward.next_at), (0, 0));
    assert!(source.task_ack_cursor > 0 && source.task_forward_cursor > 0);

    thread["test_preparation_outcome"] = json!("ready");
    source.client.account_db()?.persist_client_record("conversation", "thread", &thread)?;
    let drained =
        tokio::time::timeout(Duration::from_secs(10), super::drain_confirmations_at(source, now))
            .await
            .map_err(|_| "stored confirmation drain exceeded its outer timeout")??;
    assert_eq!(drained, 2);
    assert!(!source.client.account_db()?.actor_state_exists(&ack_key)?);
    assert!(!source.client.account_db()?.actor_state_exists(&forward_key)?);
    Ok(())
}

fn store_healthy_confirmation_jobs(
    source: &LocalBusAccountState,
    carrier: &Carrier,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let now = now_unix_timestamp();
    let ack_key = "task/ack/healthy".to_owned();
    source.client.account_db()?.persist_actor_state(
        &ack_key,
        &crate::client::task::control::AckJob {
            ack: crate::client::task::control::Ack {
                carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
                certificate: crate::client::task::certificate::Certificate {
                    conversation_id: "thread".into(),
                    resolution: ramflux_protocol::TaskResolve {
                        task_id: "task".into(),
                        base_revision: 1,
                        step_id: "step".into(),
                        target: ramflux_protocol::NeedsMe::Approval { grant_id: "grant".into() },
                        decision_id: "decision".into(),
                        decision: ramflux_protocol::TaskDecision::Resume,
                    },
                    assignee: "sender".into(),
                    issuer_device: "device-sender".into(),
                    issued_at: now,
                    phase: crate::client::task::certificate::Phase::Committed,
                    committed_version: Some(2),
                    carrier_hash: None,
                    decision_key: "decision".into(),
                    evidence_hash: "evidence".into(),
                    signature: String::new(),
                },
                manifests: Vec::new(),
                signer_principal: "sender".into(),
                signer_device: "device-sender".into(),
                signature: String::new(),
            },
            attempts: 0,
            next_at: 0,
            created_at: now,
        },
    )?;
    let forward_key = crate::client::task::scoped("forward", "thread", "task")?;
    source.client.account_db()?.persist_actor_state(
        &forward_key,
        &crate::client::task::control::ForwardJob {
            conversation_id: "thread".into(),
            task_id: "task".into(),
            attempts: 0,
            next_at: 0,
            created_at: now,
        },
    )?;
    Ok((ack_key, forward_key))
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
    let prepared = super::super::task_approval_transport::send(
        &mut source,
        &anchor.conversation_id,
        "peer-0",
        b"PRIVATE_MCP_ARGUMENTS",
    )
    .await?;
    assert!(matches!(prepared, super::Preparation::Ready(())));
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
