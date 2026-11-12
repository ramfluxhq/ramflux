// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A held inbox ACK leaves the actual account mailbox and both local readers available.

use super::fixture::{AckHold, Case, Fixture};
use crate::bus::events::EventBatch;
use crate::bus::{
    actor::{AccountActor, AccountCommand, ActorOptions},
    runtime_limits::RuntimeTimeouts,
};
use crate::prelude::*;
use serde_json::json;
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::{oneshot, watch};

#[cfg_attr(
    not(feature = "itest-local-mint"),
    expect(dead_code, reason = "Used by local-mint transfer fixtures")
)]
pub(super) struct Started {
    pub actor: AccountActor,
    pub root: PathBuf,
    pub router: tokio::task::JoinHandle<()>,
    peer: LocalBusAccountState,
    sibling: LocalBusAccountState,
    resume: ResumeConfig,
}
impl Started {
    pub(super) fn peer(&mut self) -> &mut LocalBusAccountState {
        &mut self.peer
    }
}
#[tokio::test(flavor = "current_thread")]
async fn held_inbox_ack_does_not_occupy_the_actor_or_its_readers() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(case()))))
        .await
}
async fn case() -> Case {
    let mut fixture = Box::pin(Fixture::new("receive-background-ack")).await?;
    fixture.inbound().await?;
    let hold = Arc::new(AckHold::default());
    fixture.gateway.lock().map_err(|_| "gateway")?.ack_hold = Some(Arc::clone(&hold));
    let gateway = Arc::clone(&fixture.gateway);
    let started = Box::pin(start(fixture)).await?;
    tokio::time::timeout(Duration::from_secs(10), hold.entered.notified()).await?;
    // The only active receive trigger is Connected; all competing budgets are 600 seconds.
    controls(&started.actor).await?;
    let received = started
        .actor
        .request(command("message.read", json!({"conversation_id":"healthy"})))
        .await?;
    assert!(
        received.body["messages"].as_array().is_some_and(|rows| rows
            .iter()
            .any(|row| row["body_utf8"] == "courier stays responsive"))
    );
    assert!(
        gateway.lock().map_err(|_| "gateway")?.acked.is_empty(),
        "the fake gateway must still be held"
    );
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !gateway.lock().map_err(|_| "gateway")?.acked.is_empty() {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let Started { actor, root, router, .. } = started;
    actor.stop().await?;
    drop(actor);
    router.await?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
pub(super) async fn controls(actor: &AccountActor) -> Case {
    for (method, body) in [
        ("account.status", json!({})),
        ("contact.list", json!({})),
        ("contact.requests.policy.set", json!({"contact_requests":"auto_accept"})),
    ] {
        let wall = std::time::Instant::now();
        let response =
            tokio::time::timeout(Duration::from_secs(5), actor.request(command(method, body)))
                .await??;
        assert!(
            wall.elapsed() < Duration::from_secs(5),
            "{method} waited for the held receive step"
        );
        if method == "account.status" {
            assert_eq!(response.body["networking"], "live");
        }
    }
    Ok(())
}

pub(super) async fn start(fixture: Fixture) -> Case<Started> {
    let Fixture { root, mut source, peer, sibling, .. } = fixture;
    let mut engine = source.engine.take().ok_or("fixture engine")?;
    engine.frame_timeout = Duration::from_secs(600);
    let config = source.gateway_config.clone();
    let commitment = source.principal_commitment.clone();
    let relay_options = source.client.node_relay_options.clone();
    let transfer_hook = source.test_transfer_hook.clone();
    drop(source);
    let resume = ResumeConfig { config, commitment, relay_options, transfer_hook };
    let (actor, router) = launch(&root, &resume, Some(engine)).await?;
    Ok(Started { actor, root, router, peer, sibling, resume })
}
#[derive(Clone)]
struct ResumeConfig {
    config: GatewaySessionConfig,
    commitment: String,
    relay_options: Option<RelayTransferOptions>,
    transfer_hook: Option<Arc<crate::bus::transfer_slots::test_hooks::Hook>>,
}
impl Started {
    #[cfg_attr(
        not(feature = "itest-local-mint"),
        expect(dead_code, reason = "Used by local-mint transfer fixtures")
    )]
    pub(super) async fn restart(self) -> Case<Self> {
        let Self { actor, root, router, peer, sibling, resume } = self;
        actor.stop().await?;
        drop(actor);
        router.await?;
        let (actor, router) = launch(&root, &resume, None).await?;
        Ok(Self { actor, root, router, peer, sibling, resume })
    }
}
async fn launch(
    root: &Path,
    resume: &ResumeConfig,
    engine: Option<GatewaySessionEngine>,
) -> Case<(AccountActor, tokio::task::JoinHandle<()>)> {
    let loaded_root = root.join("source");
    let data_root = loaded_root.clone();
    let ResumeConfig { config, commitment, relay_options, transfer_hook } = resume.clone();
    let index = AccountIndex::open(&loaded_root)?;
    let (events, mut batches) = mpsc::channel::<EventBatch>(64);
    let router = tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let actor = AccountActor::start_local(
        "sender".into(),
        LocalBusConfig {
            itest_legacy_accounts: true,
            ..LocalBusConfig::new(root.join("bus.sock"), data_root)
        },
        crate::node::NodeStore::default(),
        index,
        events,
        ActorOptions {
            timeouts: limits(),
            initial: Some(Box::new(move |_| {
                let mut account = crate::bus::runtime_tests::account(
                    &loaded_root,
                    "sender",
                    None,
                    Arc::new(AtomicBool::new(false)),
                )?;
                account.principal_commitment = commitment;
                account.gateway_config = config;
                account.client.node_relay_options = relay_options;
                account.test_transfer_hook = transfer_hook;
                account.target_delivery_id = account.gateway_config.target_delivery_id.clone();
                account.engine = None;
                crate::bus::dispatch::object::hydrate_local_object_state(&mut account)?;
                if let Some(engine) = engine {
                    account.install_test_session(engine);
                }
                Ok(account)
            })),
        },
    )
    .await?;
    Ok((actor, router))
}
pub(super) fn limits() -> RuntimeTimeouts {
    RuntimeTimeouts::held_for_test()
}
struct PendingConnect;
impl crate::bus::connection_manager::SessionConnector for PendingConnect {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> crate::bus::connection_manager::SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(std::future::pending())
    }
}

fn wire(target: &str, sequence: u64) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&json!({"inbox_seq":sequence,"target_delivery_id":target,"envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":format!("env-{sequence}"),"source_principal_id":"source","source_device_id":"device","target_delivery_id":target,
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":format!("H{sequence}")
    }}))?)
}

fn inbox_entry(target: &str, sequence: u64) -> Result<GatewayInboxEntry, SdkError> {
    Ok(serde_json::from_slice(&wire(target, sequence)?)?)
}

fn ack_state(target: &str, sequence: u64) -> Result<crate::bus::sync_driver::AckState, SdkError> {
    Ok(crate::bus::sync_driver::AckState {
        entry: inbox_entry(target, sequence)?,
        key: format!("ack-{sequence}"),
        already_seen: false,
        strip_call_ciphertext: false,
        accepted: true,
        received_at: 1,
    })
}

fn cover(
    account: &LocalBusAccountState,
    target: &str,
    sequence: u64,
    generation: u64,
    cursor: u64,
    kind: ramflux_storage::ReceiveCoverKind,
) -> Case {
    let db = account.client.account_db()?;
    let entry = wire(target, sequence)?;
    let expected = ramflux_storage::ReceiveExpectation {
        target,
        incarnation: "e",
        cursor,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
    };
    db.receive_transaction(expected, generation, |tx| {
        tx.stage(ramflux_storage::ReceiveStage {
            target,
            incarnation: "e",
            sequence,
            entry_json: &entry,
            admission_key: "authenticated-key",
            retain_until: now_unix_timestamp() + 300,
            first_seen: 1,
        })?;
        tx.cover(ramflux_storage::ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
    })?;
    Ok(())
}

fn turn(
    account: &LocalBusAccountState,
    target: &str,
    cursor: u64,
    generation: u64,
) -> Case<crate::bus::connection_manager::ReceiveTurn> {
    Ok(crate::bus::connection_manager::ReceiveTurn {
        target: target.into(),
        incarnation: "e".into(),
        cursor,
        generation,
        erasure_generation: account.client.account_db()?.privacy_erasure_generation()?,
        compat: false,
    })
}

fn ack_runtime(mut account: LocalBusAccountState) -> (super::super::AccountRuntime, u64, String) {
    let handle = crate::bus::connection_manager::ConnectionHandle::start_with(
        account.gateway_config.clone(),
        account.engine.take(),
        limits(),
        Arc::new(PendingConnect),
        None,
    );
    let generation = handle.generation();
    account.connection = Some(handle);
    let target = account.target_delivery_id.clone();
    let (commands, receiver) = mpsc::channel(8);
    drop(commands);
    let (_stop, shutdown) = watch::channel(false);
    let (events, mut batches) = mpsc::channel::<EventBatch>(8);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (connection_sender, connection_work) = mpsc::channel(8);
    let (_lifecycle_sender, lifecycle) = mpsc::channel(4);
    let (_preempt_sender, preempt) = watch::channel(0_u64);
    let runtime = super::super::AccountRuntime {
        timeouts: limits(),
        lifecycle,
        preempt,
        connection_sender,
        connection_work,
        ledger: None,
        transient: crate::bus::account_runtime::TransientHost::default(),
        transfers: super::super::uploads::Transfers::start(),
        id: "sender".into(),
        state: crate::bus::state::LocalBusDaemonState {
            account_index: None,
            config: LocalBusConfig::new(PathBuf::from("ack.sock"), PathBuf::from("ack-data")),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("sender".into(), account)]),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        },
        receiver,
        readers: Arc::new(std::sync::Mutex::new(None)),
        events,
        shutdown,
        courier: None,
        networking_expiry_pending: None,
        networking_expiry_warned: false,
        networking_observation_warned: false,
        courier_events: None,
        receive_gate_hook: None,
    };
    (runtime, generation, target)
}

async fn send_ack(
    runtime: &mut super::super::AccountRuntime,
    generation: u64,
    turn: Option<crate::bus::connection_manager::ReceiveTurn>,
    state: crate::bus::sync_driver::AckState,
    cursor: Result<GatewayCursor, SdkError>,
) -> Result<Result<bool, SdkError>, Box<dyn std::error::Error>> {
    let (reply, response) = oneshot::channel();
    runtime
        .apply_connection_work(crate::bus::connection_manager::AccountWork::AckResults {
            generation,
            turn: turn.map(Box::new),
            state: Box::new(state),
            cursor: Box::new(cursor),
            backpressure: Box::new(crate::bus::contact_backpressure::Backpressure::default()),
            reply,
        })
        .await?;
    Ok(match response.await {
        Ok(result) => result.map(|(accepted, _)| accepted),
        Err(_) => Err(SdkError::LocalBus("ack reply dropped".into())),
    })
}

fn cursor_ok(target: &str, sequence: u64) -> GatewayCursor {
    GatewayCursor {
        target_delivery_id: target.into(),
        inbox_seq: sequence,
        last_envelope_id: None,
        acked_envelope_ids: Vec::new(),
        nacked_envelope_ids: BTreeMap::new(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cursor_error_leaves_receive_cursor_unchanged() -> Case {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(
            cursor_error_case(),
        ))))
        .await
}

async fn cursor_error_case() -> Case {
    let mut fixture = Box::pin(Fixture::new("ack-cursor-err")).await?;
    let account = &mut fixture.source;
    let target = account.target_delivery_id.clone();
    account.client.persist_gateway_receive_cursor(&target, 5)?;
    let before = account.client.gateway_receive_cursor(&target)?;
    assert_eq!(before, 5);
    let state = ack_state(&target, 9)?;
    let mut backpressure = crate::bus::contact_backpressure::Backpressure::default();
    let error = crate::bus::sync_driver::finish_prepared_ack(
        account,
        &state,
        Err(SdkError::InboundRejected("cursor failed".into())),
        &mut backpressure,
    )
    .err()
    .ok_or("finish must return the cursor error")?;
    assert!(
        matches!(error, SdkError::InboundRejected(ref reason) if reason == "cursor failed"),
        "{error:?}"
    );
    assert_eq!(
        account.client.gateway_receive_cursor(&target)?,
        before,
        "C unchanged on cursor error"
    );
    let root = fixture.root.clone();
    drop(fixture);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn db_of(runtime: &super::super::AccountRuntime) -> Result<&AccountDb, SdkError> {
    runtime
        .state
        .accounts
        .get("sender")
        .ok_or(SdkError::LocalBus("account".into()))?
        .client
        .account_db()
}

fn is_storage(error: &SdkError, expected: &ramflux_storage::StorageError) -> bool {
    match (error, expected) {
        (SdkError::ObjectErased, ramflux_storage::StorageError::ObjectErased) => true,
        (SdkError::Storage(found), _) => {
            std::mem::discriminant(found) == std::mem::discriminant(expected)
        }
        _ => false,
    }
}

/// Pumps the account writer while the receive-side ACK step runs on the real path.
async fn drive<T>(
    runtime: &mut super::super::AccountRuntime,
    future: impl std::future::Future<Output = T>,
) -> Result<T, Box<dyn std::error::Error>> {
    tokio::pin!(future);
    loop {
        tokio::select! {
            result = &mut future => return Ok(result),
            work = runtime.connection_work.recv() => {
                runtime.apply_connection_work(work.ok_or("writer closed")?).await?;
            }
        }
    }
}

async fn ack_step(
    runtime: &mut super::super::AccountRuntime,
    generation: u64,
    turn: crate::bus::connection_manager::ReceiveTurn,
    target: &str,
    sequence: u64,
) -> Result<Result<bool, SdkError>, Box<dyn std::error::Error>> {
    let (handle, work, ack, state) = {
        let account = runtime.state.accounts.get("sender").ok_or("account")?;
        let receiver = account.client.owned_device_identity()?;
        let state = ack_state(target, sequence)?;
        let mut ack =
            crate::dm::gateway_ack(&state.entry.envelope.envelope_id, &receiver, state.received_at);
        ack.ext.ext.insert("inbox_seq".into(), json!(sequence));
        (account.connection.clone().ok_or("handle")?, runtime.connection_sender.clone(), ack, state)
    };
    let step = crate::bus::connection_manager::receive::ack_prepared(
        &handle,
        &work,
        generation,
        Some(turn),
        ack,
        state,
        Box::default(),
        Duration::from_secs(5),
    );
    Ok(drive(runtime, step).await?.map(|(acked, _)| acked))
}

/// Cursor failure keeps C; Recorded honours `state.accepted`.
async fn ack_outcomes(
    runtime: &mut super::super::AccountRuntime,
    generation: u64,
    target: &str,
) -> Case {
    // A cursor failure keeps C and still surfaces the error.
    let at_two = {
        let account = runtime.state.accounts.get("sender").ok_or("account")?;
        turn(account, target, 2, generation)?
    };
    let failed = send_ack(
        runtime,
        generation,
        Some(at_two.clone()),
        ack_state(target, 1)?,
        Err(SdkError::InboundRejected("cursor failed".into())),
    )
    .await?;
    assert!(
        matches!(&failed, Err(SdkError::InboundRejected(reason)) if reason == "cursor failed"),
        "{failed:?}"
    );
    assert_eq!(db_of(runtime)?.receive_ledger_snap_for_test(target)?.cursor, 2);
    // A Recorded outcome honours state.accepted like the live finish().
    let mut declined = ack_state(target, 1)?;
    declined.accepted = false;
    let kept =
        send_ack(runtime, generation, Some(at_two), declined, Ok(cursor_ok(target, 1))).await??;
    assert!(!kept, "Recorded honours state.accepted");
    Ok(())
}

/// `lifecycle_fence` ACK leg: the actor decides before any ACK is transmitted.
pub(super) async fn ack_fence() -> Case {
    use crate::bus::account_runtime::lifecycle_fence::{AckRecord, ack_permit, ack_results};
    use ramflux_storage::{ReceiveCoverKind, StorageError};
    let fixture = Box::pin(Fixture::new("ack-fence")).await?;
    let gateway = Arc::clone(&fixture.gateway);
    let sent = || -> Result<usize, Box<dyn std::error::Error>> {
        Ok(gateway.lock().map_err(|_| "gateway")?.acked.len())
    };
    let (mut runtime, generation, target) = ack_runtime(fixture.source);
    {
        let account = runtime.state.accounts.get("sender").ok_or("account")?;
        let db = account.client.account_db()?;
        db.install_receive_ledger_schema()?;
        db.seed_receive_epoch_for_test(&target, "e")?;
        cover(account, &target, 1, generation, 0, ReceiveCoverKind::Terminal)?;
        db.seed_ack_intent_for_test(&target, "e", 9)?;
        let snap = db.receive_ledger_snap_for_test(&target)?;
        assert_eq!((snap.cursor, snap.intents), (1, vec![1, 9]), "intent 9 sits above C");
    }
    let good = {
        let account = runtime.state.accounts.get("sender").ok_or("account")?;
        turn(account, &target, 1, generation)?
    };
    // Exact records through the fence.
    let db = db_of(&runtime)?;
    assert_eq!(ack_permit(db, generation, &good, 1)?, AckRecord::Permitted);
    assert_eq!(
        ack_permit(db, generation, &good, 9)?,
        AckRecord::AboveCursor,
        "bound check alone refuses 9"
    );
    assert_eq!(ack_results(db, generation, &good, 1, true)?, AckRecord::Recorded);
    assert_eq!(ack_results(db, generation, &good, 1, false)?, AckRecord::CursorFailed);
    assert_eq!(ack_results(db, generation, &good, 9, true)?, AckRecord::AboveCursor);
    // Stale turn generation, E change and erase (L1): exact storage errors.
    let mut stale_generation = good.clone();
    stale_generation.generation = generation.wrapping_add(1);
    let mut stale_epoch = good.clone();
    stale_epoch.incarnation = "other".into();
    let mut stale_erase = good.clone();
    stale_erase.erasure_generation = good.erasure_generation.wrapping_add(1);
    for (label, stale, expected) in [
        ("generation", &stale_generation, StorageError::AuthorizationRejected),
        ("epoch", &stale_epoch, StorageError::AuthorizationRejected),
        ("erase", &stale_erase, StorageError::ObjectErased),
    ] {
        let permit = ack_permit(db, generation, stale, 1).err();
        let record = ack_results(db, generation, stale, 1, true).err();
        for found in [permit, record] {
            let found = found.ok_or_else(|| format!("stale {label} must be refused"))?;
            assert!(
                is_storage(&found, &expected)
                    || matches!(
                        (&found, &expected),
                        (SdkError::ObjectErased, StorageError::ObjectErased)
                    ),
                "{label}: {found:?}"
            );
        }
    }
    // Wire: zero ACKs unless intent, seq <= C and fence all hold.
    for (label, turn, expected) in [
        ("stale generation", stale_generation, StorageError::AuthorizationRejected),
        ("stale epoch", stale_epoch, StorageError::AuthorizationRejected),
        ("stale erase", stale_erase, StorageError::ObjectErased),
    ] {
        let refused = ack_step(&mut runtime, generation, turn, &target, 1).await?;
        let found = refused.err().ok_or_else(|| format!("{label} must not ACK"))?;
        assert!(is_storage(&found, &expected), "{label}: {found:?}");
        assert_eq!(sent()?, 0, "{label}: no ACK on the wire");
    }
    let stale_message =
        ack_step(&mut runtime, generation.wrapping_add(1), good.clone(), &target, 1).await?;
    let found = stale_message.err().ok_or("stale message generation must not ACK")?;
    assert!(
        matches!(&found, SdkError::NetworkingPendingContext { .. }),
        "stale message generation: {found:?}"
    );
    assert_eq!(sent()?, 0, "stale message generation: no ACK on the wire");
    let above = ack_step(&mut runtime, generation, good.clone(), &target, 9).await??;
    assert!(!above, "above C is not acknowledged");
    assert_eq!(sent()?, 0, "above C: no ACK on the wire");
    let held = {
        let account = runtime.state.accounts.get("sender").ok_or("account")?;
        cover(account, &target, 2, generation, 1, ReceiveCoverKind::Held)?;
        turn(account, &target, 2, generation)?
    };
    let held_sent = ack_step(&mut runtime, generation, held.clone(), &target, 2).await??;
    assert!(!held_sent, "held is not acknowledged");
    assert_eq!(sent()?, 0, "held: no ACK on the wire");
    let acked = ack_step(&mut runtime, generation, held, &target, 1).await??;
    assert!(acked, "terminal intent at C is acknowledged");
    assert_eq!(sent()?, 1, "good case: exactly one ACK");
    let snap = db_of(&runtime)?.receive_ledger_snap_for_test(&target)?;
    assert_eq!(snap.cursor, 2, "AckResults never writes C");
    ack_outcomes(&mut runtime, generation, &target).await?;
    let root = fixture.root.clone();
    drop(runtime);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) fn command(method: &str, body: serde_json::Value) -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    AccountCommand {
        admission: None,
        private: None,
        request: LocalBusFrame::request(method, Some("sender".into()), "test", method, body),
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    }
}
