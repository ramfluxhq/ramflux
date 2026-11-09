// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S6b P20d r2 (M2): the actor `SettleRetained` arm honours its generation field and,
//! for the current generation, settles the retained sequence and writes its intent.
#![allow(clippy::expect_used)]

use super::*;
use crate::bus::connection_manager::{
    ConnectionHandle, ReceiveTurn, SessionConnector, SessionFuture,
};
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_storage::{
    ProjectionStore, ReceiveCover, ReceiveCoverKind, ReceiveCoverResult, ReceiveExpectation,
    ReceiveLedgerSnap, ReceiveMigrate, ReceiveStage, ReceiveStageResult, StorageError,
};
use tokio::sync::oneshot;

// Session never completes: the arm under test performs no network I/O.
struct Pending;
impl SessionConnector for Pending {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(std::future::pending())
    }
}

fn expected(db: &AccountDb, cursor: u64) -> Result<ReceiveExpectation<'static>, StorageError> {
    Ok(ReceiveExpectation {
        target: "t",
        incarnation: "e",
        cursor,
        generation: 1,
        erasure_generation: db.privacy_erasure_generation()?,
    })
}

fn wire(seq: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"inbox_seq":seq,"target_delivery_id":"t","envelope":{
        "schema":"test","version":1,"domain":"test","signing_key_id":"key","signature_alg":"ed25519","signature":"sig",
        "envelope_id":"env","source_principal_id":"source","source_device_id":"device","target_delivery_id":"t",
        "delivery_class":"opaque_event","priority":"normal","ttl":60,"created_at":1,"encrypted_payload":"cipher","payload_hash":"hash"
    }}))
    .expect("entry")
}

fn stage(db: &AccountDb, cursor: u64, sequence: u64) -> Result<(), StorageError> {
    let bytes = wire(sequence);
    let result = db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        tx.stage(ReceiveStage {
            target: "t",
            incarnation: "e",
            sequence,
            entry_json: &bytes,
            admission_key: "authenticated-key",
            retain_until: 100,
            first_seen: 1,
        })
    })?;
    assert!(matches!(result, ReceiveStageResult::Staged), "{result:?}");
    Ok(())
}

fn cover(
    db: &AccountDb,
    cursor: u64,
    sequence: u64,
    kind: ReceiveCoverKind,
) -> Result<ReceiveCoverResult, StorageError> {
    db.receive_transaction(expected(db, cursor)?, 1, |tx| {
        tx.cover(ReceiveCover { sequence, kind, gaps: &[], retain_until: 0 })
    })
}

// Same shape as the storage-level `hold_then_advance`: seq 1 held, cursor advanced to 2.
fn hold_then_advance(db: &AccountDb) -> Result<ReceiveLedgerSnap, StorageError> {
    stage(db, 0, 1)?;
    assert_eq!(cover(db, 0, 1, ReceiveCoverKind::Held)?, ReceiveCoverResult::Covered);
    stage(db, 1, 2)?;
    assert_eq!(cover(db, 1, 2, ReceiveCoverKind::Terminal)?, ReceiveCoverResult::Covered);
    let advanced = db.receive_ledger_snap_for_test("t")?;
    assert_eq!(advanced.cursor, 2);
    assert_eq!(advanced.work, 1, "held seq1 keeps its work");
    assert_eq!(advanced.intents, vec![2]);
    assert_eq!(advanced.receipts, vec![(1, "held".into())]);
    Ok(advanced)
}

#[tokio::test(flavor = "current_thread")]
async fn settle_retained_arm_honours_generation() -> TestResult {
    tokio::task::LocalSet::new().run_until(Box::pin(case())).await
}

async fn case() -> TestResult {
    let fixture = Fixture::new("settle-arm").await?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment.clone(),
    );
    let db = account.client.account_db()?;
    db.install_receive_ledger_schema()?;
    db.seed_receive_epoch_for_test("t", "e")?;
    let before = hold_then_advance(db)?;
    let erasure_generation = db.privacy_erasure_generation()?;

    let handle = ConnectionHandle::start_with(
        account.gateway_config.clone(),
        None,
        crate::bus::runtime_limits::RuntimeTimeouts::held_for_test(),
        std::sync::Arc::new(Pending),
        None,
    );
    let generation = handle.generation();
    account.connection = Some(handle);

    let (events, mut batches) = mpsc::channel::<EventBatch>(8);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (connection_sender, connection_work) = mpsc::channel(2);
    let (_lifecycle_sender, lifecycle) = mpsc::channel(4);
    let (_preempt_sender, preempt) = watch::channel(0);
    let (_stop, shutdown) = watch::channel(false);
    let (_commands, receiver) = mpsc::channel(1);
    let mut runtime = AccountRuntime {
        timeouts: crate::bus::runtime_limits::RuntimeTimeouts::default(),
        lifecycle,
        preempt,
        connection_sender,
        connection_work,
        transfers: super::uploads::Transfers::start(),
        id: "settle-arm".into(),
        state: LocalBusDaemonState {
            account_index: None,
            config: LocalBusConfig::new(fixture.root.0.join("bus.sock"), &fixture.root.0),
            nodes: crate::node::NodeStore::default(),
            accounts: BTreeMap::from([("settle-arm".into(), account)]),
            active_account_id: None,
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        },
        receiver,
        readers: std::sync::Arc::new(RoutingMutex::new(None)),
        events,
        shutdown,
        courier: None,
        networking_expiry_pending: None,
        networking_expiry_warned: false,
        networking_observation_warned: false,
        courier_events: None,
        receive_gate_hook: None,
    };
    let turn = ReceiveTurn {
        target: "t".into(),
        incarnation: "e".into(),
        cursor: 2,
        generation,
        erasure_generation,
    };

    // Stale generation: the arm refuses before any write. The reply sender is dropped unsent.
    let (reply, stale_reply) = oneshot::channel();
    runtime.settle_retained_for_test(generation + 1, turn.clone(), 1, reply).await?;
    assert!(stale_reply.await.is_err(), "stale generation sends no reply");
    {
        let account = runtime.state.accounts.get("settle-arm").ok_or("account missing")?;
        let db = account.client.account_db()?;
        assert_eq!(db.receive_ledger_snap_for_test("t")?, before, "stale settle writes nothing");
    }

    // Current generation: the retained sequence settles and its intent is written.
    let (reply, current_reply) = oneshot::channel();
    runtime.settle_retained_for_test(generation, turn, 1, reply).await?;
    current_reply.await??;
    let account = runtime.state.accounts.get("settle-arm").ok_or("account missing")?;
    let after = account.client.account_db()?.receive_ledger_snap_for_test("t")?;
    assert_eq!(after.work, 0, "retained work is gone after terminal settle");
    assert_eq!(after.intents, vec![1, 2], "terminal settle writes the seq1 intent");
    assert!(
        !after.receipts.iter().any(|(seq, disposition)| *seq == 1 && disposition == "held"),
        "seq1 is no longer held"
    );

    runtime.state.accounts.clear();
    Ok(())
}

fn runtime_with_pending(
    mut account: LocalBusAccountState,
    id: &str,
    root: &std::path::Path,
) -> (AccountRuntime, u64) {
    let handle = ConnectionHandle::start_with(
        account.gateway_config.clone(),
        None,
        crate::bus::runtime_limits::RuntimeTimeouts::held_for_test(),
        std::sync::Arc::new(Pending),
        None,
    );
    let generation = handle.generation();
    account.connection = Some(handle);
    let (events, mut batches) = mpsc::channel::<EventBatch>(8);
    tokio::task::spawn_local(async move {
        while let Some(batch) = batches.recv().await {
            let _ = batch.accepted.send(());
        }
    });
    let (connection_sender, connection_work) = mpsc::channel(2);
    let (_lifecycle_sender, lifecycle) = mpsc::channel(4);
    let (_preempt_sender, preempt) = watch::channel(0);
    let (_stop, shutdown) = watch::channel(false);
    let (_commands, receiver) = mpsc::channel(1);
    (
        AccountRuntime {
            timeouts: crate::bus::runtime_limits::RuntimeTimeouts::default(),
            lifecycle,
            preempt,
            connection_sender,
            connection_work,
            transfers: super::uploads::Transfers::start(),
            id: id.into(),
            state: LocalBusDaemonState {
                account_index: None,
                config: LocalBusConfig::new(root.join("bus.sock"), root),
                nodes: crate::node::NodeStore::default(),
                accounts: BTreeMap::from([(id.into(), account)]),
                active_account_id: None,
                attended_accounts: BTreeSet::new(),
                subscribers: BTreeMap::new(),
            },
            receiver,
            readers: std::sync::Arc::new(RoutingMutex::new(None)),
            events,
            shutdown,
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            courier_events: None,
            receive_gate_hook: None,
        },
        generation,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn settle_retained_paused_is_integrity() -> Result<(), SdkError> {
    tokio::task::LocalSet::new().run_until(Box::pin(settle_retained_paused_case())).await
}

async fn settle_retained_paused_case() -> Result<(), SdkError> {
    let root = crate::bus::runtime_tests::root("settle-paused");
    let account = crate::bus::runtime_tests::account(
        &root,
        "acct",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )?;
    let (before, mut turn) = {
        let db = account.client.account_db()?;
        let _ = db.activate_receive_ledger(ReceiveMigrate { target: "t", incarnation: "e" })?;
        db.set_projection_checkpoint("gateway_receive_cursor:t", "1024")?;
        stage(db, 1024, 1025)?;
        db.insert_ack_intents_for_test("t", "e", 1024)?;
        let before = db.receive_ledger_snap_for_test("t")?;
        assert_eq!(before.cursor, 1024);
        assert_eq!(before.work, 1, "seq 1025 stays staged");
        let turn = ReceiveTurn {
            target: "t".into(),
            incarnation: "e".into(),
            cursor: 1024,
            generation: 1,
            erasure_generation: db.privacy_erasure_generation()?,
        };
        (before, turn)
    };
    let (mut runtime, generation) = runtime_with_pending(account, "acct", &root);
    turn.generation = generation;
    let (reply, paused_reply) = oneshot::channel();
    runtime.settle_retained_for_test(generation, turn, 1025, reply).await?;
    let refused =
        paused_reply.await.map_err(|_| SdkError::LocalBus("settle reply dropped".into()))?;
    assert!(
        matches!(
            refused.as_ref().err(),
            Some(SdkError::Storage(StorageError::Integrity("settle retained paused")))
        ),
        "paused cover must be Integrity(settle retained paused): {refused:?}"
    );
    let account = runtime.state.accounts.get("acct").ok_or(SdkError::AccountDbNotUnlocked)?;
    assert_eq!(
        account.client.account_db()?.receive_ledger_snap_for_test("t")?,
        before,
        "paused settle writes nothing"
    );
    runtime.state.accounts.clear();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
