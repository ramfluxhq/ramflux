// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native account reads and local mutations stay responsive during a held admission attempt.

use crate::bus::{
    actor::{AccountActor, AccountCommand, ActorOptions},
    connection_manager::{SessionConnector, SessionFuture},
    events::EventBatch,
};
use crate::client::native_test_support::Fixture as Native;
use crate::prelude::*;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ID: &str = "busy-native";
struct Attempt(Arc<AtomicBool>);
impl Drop for Attempt {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct BusyConnector {
    attempts: AtomicUsize,
    progress: Arc<AtomicUsize>,
    held: Arc<AtomicBool>,
    limits: crate::bus::runtime_limits::RuntimeTimeouts,
}
impl SessionConnector for BusyConnector {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            self.held.store(true, Ordering::Release);
            let _attempt = Attempt(Arc::clone(&self.held));
            crate::custody::retry::TEST_BUSY_PROGRESS
                .scope(
                    Arc::clone(&self.progress),
                    GatewaySessionEngine::connect_with_opener(
                        config,
                        Some(deadline),
                        self.limits.clone(),
                        Arc::new(crate::gateway::transport_opener::ConfiguredTransport),
                    ),
                )
                .await
        })
    }
}
struct Harness {
    actor: AccountActor,
    connector: Arc<BusyConnector>,
    reader: AccountDb,
    _gateway: crate::bus::native_account_tests::CauseGateway,
    root: crate::custody::tests::Root,
    _peer: Native,
    peer_root: String,
    principal: String,
    router: tokio::task::JoinHandle<()>,
    clock: tokio::task::JoinHandle<()>,
}
async fn harness() -> Case<Harness> {
    harness_with_limits(crate::bus::runtime_limits::RuntimeTimeouts::held_for_test()).await
}
async fn harness_with_limits(limits: crate::bus::runtime_limits::RuntimeTimeouts) -> Case<Harness> {
    harness_with_receipts(limits, Vec::new()).await
}
async fn harness_with_receipts(
    mut limits: crate::bus::runtime_limits::RuntimeTimeouts,
    receipts: Vec<(LocalBusFrame, Option<Value>)>,
) -> Case<Harness> {
    limits.attempt = Duration::from_mins(20);
    let clock = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let native = Box::pin(Native::new(ID)).await?;
    let gateway = crate::bus::native_account_tests::CauseGateway::start(
        &native.root.0,
        crate::bus::native_account_tests::GatewayCause::Refused(
            ramflux_protocol::custody::CustodyRefusal::Busy,
        ),
    )
    .await?;
    let peer = Box::pin(Native::new("busy-peer")).await?;
    let peer_root = peer.manifest.principal_commitment.clone();
    let own = native.manifest.principal_commitment.clone();
    prepare_controls(&native, &peer, receipts)?;
    let index = native.client.account_index()?.clone();
    let reader = native.client.account_db()?.open_reader()?;
    let crate::client::native_test_support::Fixture { client, mut config, root, .. } = native;
    config.gateway_addr = gateway.address;
    config.tcp_gateway_addr = Some(gateway.address);
    config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    config.server_name = "localhost".into();
    config.ca_cert = root.0.join("cause-ca.pem");
    config.timeout = Duration::from_secs(600);
    config.quic_fallback_timeout = Duration::from_secs(600);
    let principal = config.principal_id.clone();
    drop(client);
    let connector = Arc::new(BusyConnector {
        attempts: AtomicUsize::new(0),
        progress: Arc::new(AtomicUsize::new(0)),
        held: Arc::new(AtomicBool::new(false)),
        limits: limits.clone(),
    });
    let initial_connector = Arc::clone(&connector);
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    let router = tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let actor = AccountActor::start_local(
        ID.into(),
        LocalBusConfig::new(root.0.join("bus.sock"), &root.0),
        crate::node::NodeStore::default(),
        index,
        events,
        ActorOptions {
            timeouts: limits,
            initial: Some(Box::new(move |index| {
                let mut client = RamfluxClient::new();
                client.open_account_index(index.root())?;
                client.unlock_account(ID, b"native fixture data passphrase")?;
                // Reinstall the fixture's certified signer; private prekeys remain in the DB.
                let branch = config.device_branch.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
                client.device_branch = Some(branch.as_ref().clone());
                client
                    .active_account_db
                    .as_mut()
                    .ok_or(SdkError::AccountDbNotUnlocked)?
                    .set_device_signer(branch.as_ref().clone());
                let mut state = LocalBusAccountState::disconnected(client, config, own);
                state.test_connector = Some(initial_connector);
                Ok(state)
            })),
        },
    )
    .await?;
    Ok(Harness {
        actor,
        connector,
        reader,
        _gateway: gateway,
        root,
        _peer: peer,
        peer_root,
        principal,
        router,
        clock,
    })
}
fn prepare_controls(
    native: &Native,
    peer: &Native,
    receipts: Vec<(LocalBusFrame, Option<Value>)>,
) -> Case {
    native.client.persist_fetched_identity_directory(&peer.manifest)?;
    native.client.account_db()?.establish_friend_link(
        "busy-link",
        &native.manifest.principal_commitment,
        &peer.manifest.principal_commitment,
    )?;
    let primary = native
        .client
        .born_v3_account
        .as_ref()
        .ok_or("native account")?
        .group_primary(native.vault.as_ref())?;
    native.client.shared_group_create_with_primary(
        "busy-group",
        "busy-thread",
        None,
        &native.config.target_delivery_id,
        Some(&primary),
    )?;
    for (request, result) in receipts {
        let intent = crate::bus::mutation_intent::MutationIntent::new(&request)?;
        assert!(intent.reserve(native.client.account_db()?)?.is_none());
        if let Some(result) = result {
            native
                .client
                .account_db()?
                .complete_operation(intent.key.ok_or("receipt key")?, &result)?;
        }
    }
    Ok(())
}
fn command(method: &str, body: Value) -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: LocalBusFrame::request(method, Some(ID.into()), "test", method, body),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound: outbound.into(),
        reply: None,
    }
}
async fn reads(fixture: &Harness) -> Case<Value> {
    let mut status = Value::Null;
    for (method, body) in [
        ("account.status", json!({})),
        ("contact.list", json!({})),
        ("contact.requests.list", json!({})),
        ("contact.requests.policy.get", json!({})),
        ("contact.verification.status", json!({"contact_identity_commitment":fixture.peer_root})),
        ("message.list", json!({"conversation_id":"healthy"})),
        ("message.read", json!({"conversation_id":"healthy"})),
        ("conversation.list", json!({})),
        ("group.list", json!({})),
        ("group.members", json!({"group_id":"busy-group"})),
        ("grant.list", json!({})),
        ("object.list", json!({})),
        ("device.list", json!({})),
    ] {
        let wall = std::time::Instant::now();
        let response =
            tokio::time::timeout(super::HANG, fixture.actor.request(command(method, body)))
                .await?
                .map_err(|error| format!("{method}: {error}"))?;
        assert!(wall.elapsed() < super::HANG, "{method} waited on native admission");
        if method == "account.status" {
            status = response.body;
        }
    }
    Ok(status)
}
async fn finish(fixture: Harness) -> Case {
    fixture.clock.abort();
    let wall = std::time::Instant::now();
    fixture.actor.stop().await?;
    assert!(wall.elapsed() < super::HANG);
    assert!(!fixture.connector.held.load(Ordering::Acquire));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(fixture.root.0.join("custody_accounts").join(ID).join(".network.lock"))?;
    fs2::FileExt::try_lock_exclusive(&file)?;
    fs2::FileExt::unlock(&file)?;
    drop(fixture.actor);
    fixture.router.await?;
    Ok(())
}
async fn advance_to_held(fixture: &Harness) -> Case {
    let handle = fixture.actor.connection_for_test().ok_or("manager was not started at open")?;
    while fixture.connector.progress.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    // Expire the inner admission budget after a real Busy response, leaving its outer bound later.
    tokio::time::advance(Duration::from_secs(600)).await;
    while handle.snapshot().phase != crate::bus::connection_manager::ConnectionPhase::Backoff {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        handle.snapshot().cause.as_ref().map(serde_json::to_value).transpose()?,
        Some(json!({"kind":"node_busy","retry_after_ms":16000}))
    );
    let first = fixture.connector.progress.load(Ordering::Acquire);
    tokio::time::advance(Duration::from_secs(16)).await;
    while fixture.connector.progress.load(Ordering::Acquire) == first {
        tokio::task::yield_now().await;
    }
    let path = fixture.root.0.join("custody_accounts").join(ID).join(".network.lock");
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    assert!(
        fs2::FileExt::try_lock_exclusive(&file).is_err(),
        "the native admission lease is not held"
    );
    Ok(())
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reads_answer_in_under_a_second_while_admission_is_busy() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
            let fixture = harness().await?;
            let cold = reads(&fixture).await?;
            assert_eq!(cold["networking"], "networking_pending");
            let cold_attempt =
                cold["networking_snapshot"]["attempt"].as_u64().ok_or("cold attempt")?;
            advance_to_held(&fixture).await?;
            let owner = fixture.actor.clone();
            let pending =
                tokio::task::spawn_local(async move { owner.request(network_command(None)).await });
            let _connection = wait_for_gate(&fixture).await?;
            tokio::time::resume();
            fixture.clock.abort();
            let status = reads(&fixture).await?;
            assert_eq!(status["networking"], "networking_pending");
            assert_eq!(status["networking_snapshot"]["cause"]["kind"], "node_busy");
            assert!(
                status["networking_snapshot"]["attempt"].as_u64().ok_or("attempt")? > cold_attempt
            );
            assert!(fixture.connector.held.load(Ordering::Acquire));
            finish(fixture).await?;
            assert!(pending.await?.is_err());
            Ok(())
        })))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn actor_mailbox_stays_responsive_while_admission_is_busy() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
            let fixture = harness().await?;
            advance_to_held(&fixture).await?;
            tokio::time::resume();
            fixture.clock.abort();
            let wall = std::time::Instant::now();
            fixture
                .actor
                .request(command(
                    "contact.requests.policy.set",
                    json!({"contact_requests":"auto_accept"}),
                ))
                .await?;
            assert!(
                wall.elapsed() < super::HANG,
                "local policy mutation waited for native admission"
            );
            assert!(fixture.connector.held.load(Ordering::Acquire));
            finish(fixture).await
        })))
        .await
}

fn network_command(key: Option<&str>) -> AccountCommand {
    let mut command = command(
        "message.ack",
        json!({"envelope_id":"held-envelope","receiver_device_id":"primary","received_at":now_unix_timestamp()}),
    );
    command.request.operation_id = key.map(str::to_owned);
    command
}
fn submit_command(fixture: &Harness) -> Case<AccountCommand> {
    let target = ramflux_protocol::qualified_device_id(&fixture.peer_root, "primary")?;
    Ok(command(
        "message.submit",
        json!({
            "conversation_id":"native-budget-thread","message_id":"native-budget-message",
            "envelope_id":"native-budget-envelope","source_principal_id":fixture.principal,
            "sender_id":"primary","recipient_device_id":"primary",
            "recipient_principal_commitment":fixture.peer_root,
            "target_delivery_id":target,
            "encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"native admission budget"),
            "created_at":now_unix_timestamp(),"ttl":600,
        }),
    ))
}
async fn wait_for_gate(
    fixture: &Harness,
) -> Case<crate::bus::connection_manager::ConnectionHandle> {
    let connection = fixture.actor.connection_for_test().ok_or("connection")?;
    while connection.test_live_waiters() == 0 {
        tokio::task::yield_now().await;
    }
    Ok(connection)
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn network_command_answers_networking_pending_within_bound() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
            let mut limits = crate::bus::runtime_limits::RuntimeTimeouts::held_for_test();
            limits.network_wait = Duration::from_secs(5);
            let fixture = harness_with_limits(limits).await?;
            advance_to_held(&fixture).await?;
            let actor = fixture.actor.clone();
            let admitted = tokio::time::Instant::now();
            let command = submit_command(&fixture)?;
            let request = tokio::task::spawn_local(async move { actor.request(command).await });
            let connection = wait_for_gate(&fixture).await?;
            tokio::time::advance(Duration::from_secs(5)).await;
            let error = request.await?.err().ok_or("offline network command succeeded")?;
            assert_eq!(admitted.elapsed(), Duration::from_secs(5));
            assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
            let wire = crate::bus::io::local_bus_error_body(&error);
            assert!(
                wire.details
                    .as_ref()
                    .is_some_and(|details| details["networking"]["state"] == "networking_pending")
            );
            assert_eq!(wire.retry_after_ms, connection.snapshot().retry_after_ms);
            let wall = std::time::Instant::now();
            let second = fixture.actor.request(submit_command(&fixture)?).await;
            assert!(matches!(second, Err(SdkError::NetworkingPendingContext { .. })));
            assert!(wall.elapsed() < super::HANG);
            assert!(fixture.connector.held.load(Ordering::Acquire));
            tokio::time::resume();
            finish(fixture).await
        })))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn lock_aborts_connect_and_releases_lease() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
            let fixture = harness().await?;
            advance_to_held(&fixture).await?;
            let connection = fixture.actor.connection_for_test().ok_or("connection")?;
            tokio::time::resume();
            fixture.clock.abort();
            let wall = std::time::Instant::now();
            tokio::time::timeout(
                super::HANG,
                fixture.actor.request(command("account.lock", json!({}))),
            )
            .await??;
            assert!(wall.elapsed() < super::HANG);
            assert!(
                connection.test_finished(),
                "manager and its children were not joined before lock reply"
            );
            assert!(!fixture.connector.held.load(Ordering::Acquire));
            finish(fixture).await
        })))
        .await
}
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn lock_preempts_a_held_require_live() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
            let fixture = harness().await?;
            advance_to_held(&fixture).await?;
            let network_request = network_command(Some("preempt-before-effects"));
            let intent =
                crate::bus::mutation_intent::MutationIntent::new(&network_request.request)?;
            let key = intent.key.ok_or("key")?.to_owned();
            let fingerprint = ramflux_crypto::blake3_256_base64url(
                "ramflux.operation.v1",
                &ramflux_protocol::canonical_json_bytes(&(
                    &network_request.request.method,
                    &network_request.request.body,
                ))?,
            );
            let actor = fixture.actor.clone();
            let pending =
                tokio::task::spawn_local(async move { actor.request(network_request).await });
            let connection = wait_for_gate(&fixture).await?;
            let generation = connection.generation();
            assert!(matches!(
                fixture.reader.lookup_operation(&key, &fingerprint)?,
                ramflux_storage::OperationLookup::Absent
            ));
            tokio::time::resume();
            fixture.clock.abort();
            let wall = std::time::Instant::now();
            tokio::time::timeout(
                super::HANG,
                fixture.actor.request(command("account.lock", json!({}))),
            )
            .await??;
            assert!(wall.elapsed() < super::HANG);
            assert!(connection.test_finished());
            assert_ne!(connection.generation(), generation);
            let error = pending.await?.err().ok_or("held request unexpectedly succeeded")?;
            assert_eq!(crate::bus::io::local_bus_error_code(&error), "NetworkingPending");
            assert!(matches!(
                fixture.reader.lookup_operation(&key, &fingerprint)?,
                ramflux_storage::OperationLookup::Absent
            ));
            finish(fixture).await
        })))
        .await
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn keyed_replay_and_conflicts_resolve_locally_while_offline() -> Case {
    LocalSet::new().run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(async {
        let completed = network_command(Some("completed"));
        let pending = network_command(Some("pending"));
        let erased = network_command(Some("erased"));
        let fixture = harness_with_receipts(
            crate::bus::runtime_limits::RuntimeTimeouts::held_for_test(),
            vec![
                (completed.request.clone(),Some(json!({"replayed":"stored-result"}))),
                (pending.request.clone(),None),
                (erased.request.clone(),Some(json!({"object_erased":true}))),
            ],
        ).await?;
        tokio::time::resume(); fixture.clock.abort();
        let wall = std::time::Instant::now();
        let replay = fixture.actor.request(completed).await?;
        assert_eq!(replay.body,json!({"replayed":"stored-result"}));
        let mut conflict = network_command(Some("completed"));
        conflict.request.body["envelope_id"] = json!("different-intent");
        let error = fixture.actor.request(conflict).await.err().ok_or("mismatch replayed")?;
        assert!(matches!(error,SdkError::Storage(StorageError::EventIdConflict(ref key)) if key=="completed"));
        let error = fixture.actor.request(pending).await.err().ok_or("pending key was accepted")?;
        assert!(matches!(error,SdkError::Storage(StorageError::OperationReconciliationRequired { .. })));
        assert!(matches!(fixture.actor.request(erased).await,Err(SdkError::ObjectErased)));
        assert!(wall.elapsed() < super::HANG,"local receipt resolution must bypass admission");
        assert_eq!(fixture.actor.connection_for_test().ok_or("manager")?.test_live_waiters(),0);
        finish(fixture).await
    }))).await
}
