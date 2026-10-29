// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Courier regressions through the real account actor and preparation signal loop.

use super::*;
use crate::bus::{
    task_courier::{Outcome, Preparation, TaskCourier},
    task_courier_queue,
};
use crate::client::task::{
    approval,
    carrier::Carrier,
    control::{Ack, AckJob, ForwardJob},
};
use ramflux_protocol::{NeedsMe, TaskDecision, TaskEvent, TaskEventBody, TaskResolve, TaskStart};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
#[path = "task_courier_fixture.rs"]
mod fixture;
use fixture::{Case, Fixture};

#[derive(Debug)]
pub(super) enum CourierEvent {
    Requested(std::time::Instant),
    Item { key: String, attempts: u32, charged: bool },
    Finished,
}
impl CourierEvent {
    pub(super) fn from_outcome(
        outcome: &Outcome,
        account: Option<&LocalBusAccountState>,
    ) -> Result<Self, SdkError> {
        Ok(match outcome {
            Outcome::Requested { .. } => Self::Requested(std::time::Instant::now()),
            Outcome::Finished => Self::Finished,
            Outcome::Item { item, preparation } => {
                let attempts = account
                    .map(|account| task_courier_queue::load(account, &item.key))
                    .transpose()?
                    .flatten()
                    .map_or(0, |(job, _)| job.attempts());
                Self::Item {
                    key: item.key.clone(),
                    attempts,
                    charged: matches!(preparation, Preparation::Charged(_)),
                }
            }
        })
    }
}

fn carrier(account: &LocalBusAccountState, conversation: &str, task: &str) -> Case<Carrier> {
    Ok(account.client.sign_task_event(
        TaskEvent::new(
            conversation.into(),
            TaskEventBody::Start(TaskStart {
                task_id: task.into(),
                conversation_id: conversation.into(),
                requester: "sender".into(),
                assignee: "peer".into(),
                text: "courier regression".into(),
                constraints: None,
            }),
            sdk_device_signed_fields("device-sender", ""),
        )?,
        format!("{task}-start"),
        None,
    )?)
}

fn ack(account: &LocalBusAccountState, key: &str, carrier: &Carrier) -> Case {
    account.client.account_db()?.persist_actor_state(
        key,
        &AckJob {
            ack: Ack {
                carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
                certificate: crate::client::task::certificate::Certificate {
                    conversation_id: carrier.conversation_id.clone(),
                    resolution: TaskResolve {
                        task_id: carrier.event()?.event().task_id().into(),
                        base_revision: 1,
                        step_id: "step".into(),
                        target: NeedsMe::Approval { grant_id: "grant".into() },
                        decision_id: "decision".into(),
                        decision: TaskDecision::Resume,
                    },
                    assignee: "sender".into(),
                    issuer_device: "device-sender".into(),
                    issued_at: now_unix_timestamp(),
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
            created_at: now_unix_timestamp(),
        },
    )?;
    Ok(())
}

fn forward(account: &LocalBusAccountState, key: &str, carrier: &Carrier) -> Case {
    use crate::client::task::Delivery;
    account.client.project_task_message(
        &Delivery {
            conversation: &carrier.conversation_id,
            message: &carrier.message_id,
            principal: &carrier.principal_id,
            device: &carrier.device_id,
            at: now_unix_timestamp(),
        },
        &carrier.bytes()?,
    )?;
    account.client.account_db()?.delete_task_state(&crate::client::task::scoped(
        "forward",
        &carrier.conversation_id,
        carrier.event()?.event().task_id(),
    )?)?;
    account.client.account_db()?.persist_actor_state(
        key,
        &ForwardJob {
            conversation_id: carrier.conversation_id.clone(),
            task_id: carrier.event()?.event().task_id().into(),
            attempts: 0,
            next_at: 0,
            created_at: now_unix_timestamp(),
        },
    )?;
    Ok(())
}

fn runtime(
    account: LocalBusAccountState,
    root: &Path,
) -> (
    AccountRuntime,
    mpsc::Sender<AccountCommand>,
    watch::Sender<bool>,
    mpsc::UnboundedReceiver<CourierEvent>,
) {
    let (sender, receiver) = mpsc::channel(64);
    let (stop, shutdown) = watch::channel(false);
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (observations, observed) = mpsc::unbounded_channel();
    let runtime = AccountRuntime {
        id: "sender".into(),
        state: LocalBusDaemonState {
            account_index: None,
            config: LocalBusConfig::new(root.join("bus.sock"), root),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("sender".into(), account)]),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        },
        receiver,
        readers: Arc::new(Mutex::new(None)),
        events,
        shutdown,
        courier: Some(TaskCourier::start()),
        courier_events: Some(observations),
    };
    (runtime, sender, stop, observed)
}

async fn command(sender: &mpsc::Sender<AccountCommand>, method: &str, body: Value) -> Case<Value> {
    let (reply, received) = oneshot::channel();
    let (outbound, _) = mpsc::channel(1);
    sender
        .send(AccountCommand {
            backup: None,
            request: LocalBusFrame::request(method, Some("sender".into()), "test", method, body),
            connection_id: 1,
            topics: BTreeSet::new(),
            attended: true,
            nodes: None,
            outbound,
            reply: Some(reply),
        })
        .await?;
    Ok(tokio::time::timeout(Duration::from_secs(15), received).await???.body)
}

async fn next(events: &mut mpsc::UnboundedReceiver<CourierEvent>) -> Case<CourierEvent> {
    Ok(tokio::time::timeout(Duration::from_secs(15), events.recv())
        .await?
        .ok_or("actor stopped during courier work")?)
}

async fn pass(
    events: &mut mpsc::UnboundedReceiver<CourierEvent>,
) -> Case<Vec<(String, u32, bool)>> {
    Ok(observe_pass(events).await?.0)
}

async fn observe_pass(
    events: &mut mpsc::UnboundedReceiver<CourierEvent>,
) -> Case<(Vec<(String, u32, bool)>, Duration)> {
    let mut start = None;
    let mut items = Vec::new();
    loop {
        match next(events).await? {
            CourierEvent::Item { key, attempts, charged } => items.push((key, attempts, charged)),
            CourierEvent::Finished => break,
            CourierEvent::Requested(at) => start = Some(at),
        }
    }
    let elapsed = start.ok_or("courier pass did not begin with Requested")?.elapsed();
    eprintln!("courier pass: {} items in {elapsed:?}", items.len());
    Ok((items, elapsed))
}

async fn serving(runtime: &mut AccountRuntime) -> Result<(), SdkError> {
    let (ready, _) = std::sync::mpsc::sync_channel(1);
    let result = runtime.serve(ready).await;
    runtime.stop_courier().await;
    runtime.close_readers().await;
    result
}

#[tokio::test]
async fn r6_dead_rows_are_quarantined_and_actor_delivers_dm_and_call_after_restart() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            let mut fixture = Box::pin(Fixture::new("courier-dead-rows-r6")).await?;
            let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
            ack(&fixture.source, "task/ack/healthy", &healthy)?;
            forward(&fixture.source, "task/forward/healthy", &healthy)?;
            intervention(&fixture.source, &fixture.peer)?;
            // A valid decision packet exercises the third queue's real submission path.
            let packet = fixture.source.client.sign_task_approval(approval::Payload::Decision {
                request: approval_request(&fixture.source)?,
                approved: false,
                grant_signature: None,
            })?;
            fixture.source.client.account_db()?.persist_actor_state(
                "task/approval_decision_out/healthy",
                &approval::Job { packet, attempts: 0, next_at: 0 },
            )?;
            for key in
                ["task/approval_decision_out/000-bad", "task/ack/000-bad", "task/forward/000-bad"]
            {
                fixture
                    .source
                    .client
                    .account_db()?
                    .persist_actor_state(key, &json!({"invalid_legacy_row":true}))?;
            }
            let call_id = fixture.inbound().await?;
            let inbound = std::mem::take(&mut fixture.gateway.lock().map_err(|_| "gateway")?.inbox);
            let Fixture { root, source, peer, sibling, gateway, .. } = fixture;
            let (mut actor, sender, stop, mut events) = runtime(source, &root.join("source"));
            if let Some(courier) = actor.courier.take() {
                courier.stop().await;
            }
            actor.courier = Some(TaskCourier::start());
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                let mut sent = BTreeSet::new();
                for _ in 0..4 {
                    if sent.len() == 3 {
                        break;
                    }
                    for (key, attempts, charged) in pass(&mut events).await? {
                        assert!(!charged, "healthy item was charged: {key}");
                        assert_eq!(attempts, 0);
                        sent.insert(key);
                    }
                    command(&sender, "identity.directory", json!({"limit":16})).await?;
                }
                assert_eq!(sent.len(), 3, "valid queue rows did not continue after quarantine");
                gateway.lock().map_err(|_| "gateway")?.inbox.extend(inbound);
                inbound_delivered(&sender, &call_id).await?;
                stop.send(true)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut actor), driver);
            served?;
            result?;
            let account = actor.state.accounts.get("sender").ok_or("account")?;
            let db = account.client.account_db()?;
            assert_eq!(db.load_actor_state::<u64>("task/courier_dead_count")?, Some(3));
            let dead =
                db.task_record_page::<Value>("task/courier_dead/", "task/courier_dead/", 16)?;
            assert_eq!(dead.len(), 3);
            assert!(dead.iter().all(|(_, row)| row.as_object().is_some_and(|row| row.len() == 2
                && row.contains_key("id")
                && row.contains_key("reason"))));
            assert!(gateway.lock().map_err(|_| "gateway")?.sent.len() >= 3);
            let account = actor.state.accounts.remove("sender").ok_or("account")?;
            let config = account.gateway_config.clone();
            let commitment = account.principal_commitment.clone();
            drop(account);
            // Close and reload the database, then reenter the real serve loop.
            let mut reopened = crate::bus::runtime_tests::account(
                &root.join("source"),
                "sender",
                None,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )?;
            reopened.principal_commitment = commitment;
            reopened.engine = None;
            reopened.put_engine(GatewaySessionEngine::connect(config).await?);
            let (mut restarted, sender, stop, mut events) = runtime(reopened, &root.join("source"));
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                pass(&mut events).await?;
                command(&sender, "identity.directory", json!({"limit":16})).await?;
                stop.send(true)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut restarted), driver);
            served?;
            result?;
            drop(restarted);
            drop(actor);
            drop(peer);
            drop(sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

fn approval_request(account: &LocalBusAccountState) -> Case<Box<approval::Request>> {
    let binding = account.client.task_approval_binding(
        "healthy",
        "healthy-task",
        "step",
        &NeedsMe::Approval { grant_id: "grant".into() },
    )?;
    let expires_at = now_unix_timestamp() + 300;
    Ok(Box::new(approval::Request {
        binding: binding.clone(),
        approval: LocalMcpApprovalRecord {
            approval_id: "approval".into(),
            server_id: "shell".into(),
            tool_name: "run".into(),
            capability: McpCapability::RunShell,
            risk_level: RiskLevel::High,
            tool_scope: None,
            confirmation_mode: "remote_app".into(),
            expires_at,
            status: "pending".into(),
            details: json!({}),
        },
        grant_body: LocalMcpGrantSigningBody {
            task_binding: Some(binding),
            approval_id: "approval".into(),
            grant_id: "grant".into(),
            server_id: "shell".into(),
            tool_name: "run".into(),
            tool_scope: None,
            capability: McpCapability::RunShell,
            registry_hash: "registry".into(),
            tool_manifest_set_hash: "manifest".into(),
            full_delegation: false,
            single_use: true,
            arguments_hash: None,
            expires_at,
        },
    }))
}

async fn stall(
    account: &LocalBusAccountState,
) -> Case<(tokio::task::JoinHandle<()>, mpsc::Receiver<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let db = account.client.account_db()?;
    let mut row = db.client_record("conversation", "stalled")?.ok_or("stalled conversation")?;
    row["direct_route"] = json!({"federation":{"recipient_prekey_url":url}});
    db.persist_client_record("conversation", "stalled", &row)?;
    let (entered, received) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            sockets.push(socket);
            let _ = entered.send(()).await;
        }
    });
    Ok((task, received))
}

#[tokio::test]
async fn r6_real_preparation_charges_only_the_stalled_item_and_keeps_healthy_attempts_zero() -> Case
{
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            let fixture = Box::pin(Fixture::new("courier-independent-items-r6")).await?;
            let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
            let slow = carrier(&fixture.source, "stalled", "slow-task")?;
            ack(&fixture.source, "task/ack/000-stalled", &slow)?;
            ack(&fixture.source, "task/ack/100-healthy", &healthy)?;
            forward(&fixture.source, "task/forward/healthy", &healthy)?;
            let (stalled, mut entered) = stall(&fixture.source).await?;
            let root = fixture.root.clone();
            let gateway = fixture.gateway.clone();
            let (mut actor, _sender, stop, mut events) =
                runtime(fixture.source, &root.join("source"));
            // Use the default five-second deadline on the real manifest-fetch path.
            if let Some(courier) = actor.courier.take() {
                courier.stop().await;
            }
            actor.courier = Some(TaskCourier::start());
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                tokio::time::timeout(Duration::from_secs(10), entered.recv())
                    .await?
                    .ok_or("manifest never stalled")?;
                let rows = pass(&mut events).await?;
                assert_eq!(rows.len(), 3, "{rows:?}");
                assert!(rows.iter().any(|(key, attempts, charged)| key == "task/ack/000-stalled"
                    && *attempts == 0
                    && *charged));
                assert!(
                    rows.iter()
                        .filter(|(key, _, _)| key != "task/ack/000-stalled")
                        .all(|(_, attempts, charged)| *attempts == 0 && !charged)
                );
                assert!(
                    rows.iter()
                        .position(|(key, _, _)| key == "task/ack/000-stalled")
                        .is_some_and(|index| index == 2),
                    "healthy results must be returned before the stalled deadline: {rows:?}"
                );
                stop.send(true)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut actor), driver);
            stalled.abort();
            let _ = stalled.await;
            served?;
            result?;
            let account = actor.state.accounts.get("sender").ok_or("account")?;
            let db = account.client.account_db()?;
            let slow: AckJob = db.load_actor_state("task/ack/000-stalled")?.ok_or("stalled job")?;
            assert_eq!(slow.attempts, 1);
            assert!(!db.actor_state_exists("task/ack/100-healthy")?);
            assert!(!db.actor_state_exists("task/forward/healthy")?);
            let failures =
                db.task_record_page::<Value>("task/courier_failure/", "task/courier_failure/", 16)?;
            assert_eq!(
                failures.len(),
                1,
                "healthy items must never receive shared failure bookkeeping"
            );
            assert_eq!(failures[0].1["id"], "task/ack/000-stalled");
            assert!(failures[0].1["start"].as_i64().is_some_and(|at| slow.next_at >= at + 2));
            let sent = &gateway.lock().map_err(|_| "gateway")?.sent;
            assert!(sent.iter().any(|e| e.target_delivery_id == "peer"));
            assert!(sent.iter().any(|e| e.target_delivery_id == "sibling"));
            drop(actor);
            drop(fixture.peer);
            drop(fixture.sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn r6_twenty_busy_actor_passes_keep_one_gateway_session_deliver_inbound_and_lock() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            let mut fixture = Box::pin(Fixture::new("courier-session-ownership-r6")).await?;
            let slow = carrier(&fixture.source, "stalled", "slow-task")?;
            let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
            for index in 0..44 {
                ack(&fixture.source, &format!("task/ack/stalled-{index:02}"), &slow)?;
            }
            for index in 0..20 {
                forward(&fixture.source, &format!("task/forward/healthy-{index:02}"), &healthy)?;
            }
            let call_id = fixture.inbound().await?;
            let (stalled, mut entered) = stall(&fixture.source).await?;
            let root = fixture.root.clone();
            let gateway = fixture.gateway.clone();
            let (mut actor, sender, stop, mut events) =
                runtime(fixture.source, &root.join("source"));
            if let Some(courier) = actor.courier.take() {
                courier.stop().await;
            }
            actor.courier = Some(TaskCourier::with_limits(Duration::from_millis(750), 4));
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                tokio::time::timeout(Duration::from_secs(10), entered.recv())
                    .await?
                    .ok_or("manifest never stalled")?;
                let mut charged = 0;
                let mut finished = 0;
                while finished < 20 {
                    let rows = pass(&mut events).await?;
                    charged += rows.iter().filter(|(_, _, charged)| *charged).count();
                    finished += 1;
                    let (sessions, protocol_errors) = {
                        let gateway = gateway.lock().map_err(|_|"gateway")?;
                        (gateway.sessions.get("device-sender").copied(), gateway.protocol_errors.clone())
                    };
                    assert_eq!(sessions, Some(1),
                        "gateway session reopened on pass {finished}; protocol errors: {protocol_errors:?}");
                    // Each command executes in the live actor and signals the preparation loop.
                    command(&sender, "identity.directory", json!({"limit":16})).await?;
                    if finished == 2 {
                        inbound_delivered(&sender, &call_id).await?;
                    }
                }
                assert!(charged >= 20, "courier passes did not contain stalled work");
                // Wait until another pass is in preparation, then lock through the normal mailbox.
                loop {
                    if matches!(next(&mut events).await?, CourierEvent::Requested(_)) {
                        break;
                    }
                }
                let start = std::time::Instant::now();
                command(&sender, "account.lock", json!({})).await?;
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "lock waited for off-loop preparation"
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut actor), driver);
            stalled.abort();
            let _ = stalled.await;
            served?;
            result?;
            assert!(actor.state.accounts.is_empty());
            assert!(
                gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .any(|envelope| envelope.target_delivery_id == "sibling"),
                "healthy forwarding did not progress during stalled courier passes"
            );
            assert_eq!(
                gateway.lock().map_err(|_| "gateway")?.sessions.get("device-sender"),
                Some(&1)
            );
            drop(actor);
            drop(fixture.peer);
            drop(fixture.sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn r6_hundred_ack_backlog_drains_through_signal_loop_with_a_per_pass_bound() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            let fixture = Box::pin(Fixture::new("courier-backlog-r6")).await?;
            let c = carrier(&fixture.source, "healthy", "backlog-task")?;
            for index in 0..100 {
                ack(&fixture.source, &format!("task/ack/{index:03}"), &c)?;
            }
            let root = fixture.root.clone();
            let gateway = fixture.gateway.clone();
            let (mut actor, _sender, stop, mut events) =
                runtime(fixture.source, &root.join("source"));
            if let Some(courier) = actor.courier.take() {
                courier.stop().await;
            }
            actor.courier = Some(TaskCourier::start());
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                let mut sent = 0;
                let mut passes = 0;
                while sent < 100 {
                    let (rows, elapsed) = observe_pass(&mut events).await?;
                    assert!(
                        elapsed < Duration::from_secs(12),
                        "ack courier pass exceeded its bound: {elapsed:?}"
                    );
                    assert_eq!(rows.len(), 2, "ack throughput fell below two per pass");
                    assert!(rows.iter().all(|(_, attempts, charged)| *attempts == 0 && !charged));
                    sent += rows.len();
                    passes += 1;
                }
                assert_eq!(passes, 50);
                stop.send(true)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut actor), driver);
            served?;
            result?;
            assert_eq!(
                actor.state.accounts["sender"]
                    .client
                    .account_db()?
                    .task_state_usage("task/ack/")?
                    .0,
                0
            );
            assert_eq!(
                gateway
                    .lock()
                    .map_err(|_| "gateway")?
                    .sent
                    .iter()
                    .filter(|e| e.target_delivery_id == "peer")
                    .count(),
                100
            );
            drop(actor);
            drop(fixture.peer);
            drop(fixture.sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

fn intervention(account: &LocalBusAccountState, peer: &LocalBusAccountState) -> Case {
    let update = peer.client.sign_task_event(
        TaskEvent::new(
            "healthy".into(),
            TaskEventBody::Update(ramflux_protocol::TaskUpdate {
                task_id: "healthy-task".into(),
                version: 2,
                state: ramflux_protocol::TaskStatus::NeedsMe,
                steps: vec![ramflux_protocol::TaskStep {
                    id: "step".into(),
                    title: "Run".into(),
                    state: ramflux_protocol::TaskStatus::NeedsMe,
                    needs_me: Some(NeedsMe::Approval { grant_id: "grant".into() }),
                }],
                result_ref: None,
                result_summary: None,
            }),
            sdk_device_signed_fields("device-peer", ""),
        )?,
        "intervention".into(),
        None,
    )?;
    let result = account
        .client
        .project_task_message(
            &crate::client::task::Delivery {
                conversation: "healthy",
                message: &update.message_id,
                principal: "peer",
                device: "device-peer",
                at: now_unix_timestamp(),
            },
            &update.bytes()?,
        )?
        .ok_or("intervention projection")?;
    assert!(result.accepted, "{:?}", result.reject);
    account.client.account_db()?.delete_task_state(&crate::client::task::scoped(
        "forward",
        "healthy",
        "healthy-task",
    )?)?;
    Ok(())
}

#[tokio::test]
async fn r6_application_error_charges_one_forward_and_account_keeps_serving() -> Case {
    LocalSet::new()
        .run_until(Box::pin(async {
            let _guard = crate::bus::dispatch::task_transport::manifest_test_lock().lock().await;
            let fixture = Box::pin(Fixture::new("courier-application-error-r6")).await?;
            let healthy = carrier(&fixture.source, "healthy", "healthy-task")?;
            ack(&fixture.source, "task/ack/healthy", &healthy)?;
            fixture.source.client.account_db()?.persist_actor_state(
                "task/forward/bad-history",
                &ForwardJob {
                    conversation_id: "healthy".into(),
                    task_id: "broken-task".into(),
                    attempts: 0,
                    next_at: 0,
                    created_at: now_unix_timestamp(),
                },
            )?;
            // A decodable job whose failure occurs only in the actor-owned application path.
            let history = crate::client::task::scoped("history", "healthy", "broken-task")?;
            fixture
                .source
                .client
                .account_db()?
                .persist_actor_state(&history, &json!({"events":false}))?;
            let root = fixture.root.clone();
            let (mut actor, sender, stop, mut events) =
                runtime(fixture.source, &root.join("source"));
            let driver = async {
                let _shutdown = Shutdown(stop.clone());
                let rows = pass(&mut events).await?;
                assert_eq!(rows.len(), 2);
                command(&sender, "identity.directory", json!({"limit":16})).await?;
                stop.send(true)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let (served, result) = tokio::join!(serving(&mut actor), driver);
            served?;
            result?;
            let db = actor.state.accounts["sender"].client.account_db()?;
            let failed: ForwardJob =
                db.load_actor_state("task/forward/bad-history")?.ok_or("failed forward")?;
            assert_eq!(failed.attempts, 1);
            assert!(!db.actor_state_exists("task/ack/healthy")?);
            let failures =
                db.task_record_page::<Value>("task/courier_failure/", "task/courier_failure/", 16)?;
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].1["reason"], "application");
            let charged_at = failures[0].1["start"].as_i64().ok_or("charge timestamp")?;
            assert_eq!(failed.next_at, charged_at + 2);
            drop(actor);
            drop(fixture.peer);
            drop(fixture.sibling);
            std::fs::remove_dir_all(root)?;
            Ok(())
        }))
        .await
}

struct Shutdown(watch::Sender<bool>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

#[test]
fn r6_only_explicit_account_stop_errors_escape_item_isolation() {
    use crate::bus::task_courier_queue::stop_class;
    assert!(stop_class(&SdkError::AccountDbNotUnlocked));
    assert!(stop_class(&SdkError::IdentityRootMissing));
    assert!(stop_class(&SdkError::Storage(StorageError::AccountKeyMismatch)));
    assert!(!stop_class(&SdkError::Io(std::io::Error::other("transient I/O"))));
    assert!(!stop_class(&SdkError::TaskManifestWorkerCapacity));
    assert!(!stop_class(&SdkError::InboundRejected("item-local".into())));
    let error = serde_json::from_value::<AckJob>(json!({})).err();
    assert!(error.is_some_and(|error| !stop_class(&SdkError::Json(error))));
}

async fn inbound_delivered(sender: &mpsc::Sender<AccountCommand>, call_id: &str) -> Case {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let calls = command(sender, "call.list", json!({})).await?;
        let messages =
            command(sender, "message.read", json!({"conversation_id":"healthy"})).await?;
        let dm = messages["messages"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| row["body_utf8"] == "courier stays responsive")
        });
        if dm && calls["calls"][0]["call_id"] == call_id {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("inbound delivery did not continue: {calls}; {messages}").into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
