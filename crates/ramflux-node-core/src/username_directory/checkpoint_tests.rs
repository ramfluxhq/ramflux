// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real protected-image/private-primary transactions and deterministic clocks/fault boundaries.
use super::*;
use ramflux_protocol::username_directory as wire;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const WALL: u64 = 1_800_000_000;
fn id(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
struct Clock {
    wall: AtomicU64,
    mono: AtomicU64,
}
impl Clock {
    fn new() -> Self {
        Self { wall: AtomicU64::new(WALL), mono: AtomicU64::new(0) }
    }
}
impl CheckpointClock for Clock {
    fn now(&self) -> CheckpointTime {
        CheckpointTime {
            wall: self.wall.load(Ordering::SeqCst),
            monotonic: self.mono.load(Ordering::SeqCst),
        }
    }
}
struct Fixture {
    dir: PathBuf,
    clock: Arc<Clock>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("rf-username-checkpoint-{}", nonce()?));
        std::fs::create_dir(&dir)?;
        Ok(Self { dir, clock: Arc::new(Clock::new()) })
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    fn witness(&self) -> Result<CheckpointWitness> {
        CheckpointWitness::initialize(
            &self.path("witness"),
            "center.example",
            1,
            self.clock.clone(),
        )
    }
    fn reopen(&self) -> Result<CheckpointWitness> {
        CheckpointWitness::open(&self.path("witness"), "center.example", 1, self.clock.clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn root(epoch: u64, deleted: bool) -> wire::RootRow {
    wire::RootRow {
        epoch,
        name: None,
        node: "home.example".into(),
        discoverable: false,
        deleted,
        profile: if epoch == 0 {
            wire::ProfileRef { version: 0, epoch: 0, hash: None }
        } else {
            wire::ProfileRef { version: 2, epoch, hash: Some(id(8)) }
        },
        binding_hash: None,
        current_binding: None,
        receipt_decision: (epoch > 0).then_some(wire::ReceiptDecision { committed_at: WALL }),
        last_operation_id: (epoch > 0).then(|| id(4)),
        last_operation_hash: (epoch > 0).then(|| id(5)),
        pending_operation_id: None,
        changes: Vec::new(),
        hold_deadlines: Vec::new(),
    }
}

fn nonce() -> Result<String> {
    Ok(ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(storage)?))
}
fn clock_delta(tx: u64, time: u64) -> wire::CheckpointDelta {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&tx.to_be_bytes());
    wire::CheckpointDelta {
        kind: wire::DeltaKind::Clock,
        tx_id: ramflux_protocol::encode_base64url(bytes),
        writer_incarnation: id(1),
        clock_floor: time,
        operation: None,
        rows: vec![],
    }
}
fn reserve(tx: u64) -> Result<(String, wire::CheckpointDelta)> {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let root_id = ramflux_crypto::identity_root_commitment(&signer.verifying_key());
    let mut operation_id = [0; 32];
    operation_id[..8].copy_from_slice(&tx.to_be_bytes());
    let operation_id = ramflux_protocol::encode_base64url(operation_id);
    let profile = wire::ProfileRef { version: 2, epoch: 1, hash: Some(id(8)) };
    let op = ramflux_crypto::username_directory::sign_operation(
        &signer,
        wire::UsernameOperationBody {
            action: wire::Action::ProfileUpdate,
            operation_id: operation_id.clone(),
            principal_commitment: root_id.clone(),
            expected_epoch: 0,
            next_epoch: 1,
            expected_profile: root(0, false).profile,
            profile,
            old_name: None,
            binding: None,
            discoverable: false,
            issued_at: WALL - 10,
            expires_at: WALL + 290,
        },
    )?;
    let hash = ramflux_crypto::username_directory::operation_hash(&op)?;
    let mut root = root(0, false);
    root.pending_operation_id = Some(operation_id.clone());
    let mut delta = clock_delta(tx, WALL);
    delta.kind = wire::DeltaKind::Reserve;
    delta.operation = Some(op.clone());
    delta.rows = vec![
        wire::Replacement::Root { key: root_id.clone(), old: None, new: Some(root) },
        wire::Replacement::Operation {
            key: wire::OperationKey { root: root_id.clone(), operation_id: operation_id.clone() },
            old: None,
            new: Some(wire::OperationRow {
                operation: op,
                operation_hash: hash.clone(),
                state: wire::ReceiptState::Reserved,
                reserved_at: WALL,
                reservation_expires_at: WALL + 120,
                finished_at: None,
                retain_until: None,
            }),
        },
        wire::Replacement::OpOwner {
            key: operation_id.clone(),
            old: None,
            new: Some(wire::OperationOwnerRow { root: root_id.clone(), operation_hash: hash }),
        },
        wire::Replacement::Due {
            key: wire::DueKey::Operation {
                at: WALL + 120,
                root: root_id.clone(),
                operation_id,
                phase: wire::DuePhase::Reservation,
            },
            old: None,
            new: Some(wire::DueRow { count: 1 }),
        },
    ];
    for metric in
        [wire::Metric::RootSlots, wire::Metric::PendingOperations, wire::Metric::OperationDetails]
    {
        for key in [
            wire::CounterKey::Global { metric },
            wire::CounterKey::Home { home: "home.example".into(), metric },
        ] {
            delta.rows.push(wire::Replacement::Counter {
                key,
                old: None,
                new: Some(wire::CounterRow { value: 1 }),
            });
        }
    }
    delta.rows.sort_by_key(|r| r.order_key().unwrap_or_default());
    Ok((root_id, delta))
}
#[test]
fn username_checkpoint_barrier_and_rollback_recovery() -> TestResult {
    username_checkpoint_barrier_and_rollback_recovery_store_apply_reopen()?;
    username_checkpoint_barrier_and_rollback_recovery_delta_cas_and_chain_negatives()?;
    username_checkpoint_barrier_and_rollback_recovery_redo_compaction_saturation()?;
    Ok(())
}
fn username_checkpoint_barrier_and_rollback_recovery_store_apply_reopen() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let genesis = witness.head();
    let (root_id, delta) = reserve(1)?;
    let checkpoint = witness.append(&genesis, delta.clone(), &root_id, false)?;
    assert_eq!(checkpoint.lsn, 1);
    assert_eq!(checkpoint.previous_digest, genesis.digest);
    assert_eq!(
        witness.head().digest,
        ramflux_crypto::username_directory::checkpoint_hash(&checkpoint)?
    );
    let image = witness.image_page(None, 128)?.rows;
    assert_eq!(image.len(), delta.rows.len());
    let head = witness.head();
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert_eq!(witness.head(), head);
    assert_eq!(witness.image_page(None, 128)?.rows, image);
    assert_eq!(witness.transaction(&delta.tx_id)?, Some(checkpoint));
    assert_eq!(witness.compact(1)?, 1);
    assert!(witness.transaction(&delta.tx_id)?.is_none());
    drop(witness);
    let witness = fixture.reopen()?;
    assert_eq!(witness.head(), head);
    assert_eq!(witness.image_page(None, 128)?.rows, image);
    Ok(())
}
fn username_checkpoint_barrier_and_rollback_recovery_delta_cas_and_chain_negatives() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let genesis = witness.head();
    let (root_id, delta) = reserve(1)?;
    for field in 0..7 {
        let mut wrong = genesis.clone();
        match field {
            0 => wrong.center_id = "other.example".into(),
            1 => wrong.generation += 1,
            2 => wrong.lsn += 1,
            3 => wrong.digest = id(9),
            4 => wrong.clock_floor += 1,
            5 => wrong.codec_version += 1,
            _ => wrong.policy = "unknown".into(),
        }
        assert!(
            matches!(
                witness.append(&wrong, delta.clone(), &root_id, false),
                Err(CheckpointError::Refused("head_cas"))
            ),
            "head field {field}"
        );
    }
    // Remove each image relationship independently, retaining a well-formed wire delta.
    for table in ["root", "operation", "op_owner", "due", "counter"] {
        let mut bad = delta.clone();
        bad.rows.retain(|r| r.order_key().is_ok_and(|k| k.0 != table));
        assert!(witness.append(&genesis, bad, &root_id, false).is_err(), "missing {table}");
        assert_eq!(witness.head(), genesis);
        assert_eq!(witness.image_page(None, 128)?.rows, Vec::new());
    }
    let mut bad = delta.clone();
    bad.clock_floor += 1;
    assert!(matches!(
        witness.append(&genesis, bad, &root_id, false),
        Err(CheckpointError::Refused("commit_clock"))
    ));
    witness.append(&genesis, delta, &root_id, false)?;
    let head = witness.head();
    let (_, replacement) = reserve(2)?;
    assert!(
        matches!(
            witness.append(&head, replacement, &root_id, false),
            Err(CheckpointError::Refused("old_image"))
        ),
        "old-row CAS must reject replacement of existing authority"
    );
    assert_eq!(witness.head(), head);
    let mut replay = clock_delta(1, WALL);
    replay.tx_id = reserve(1)?.1.tx_id;
    assert!(matches!(
        witness.append(&head, replay, &root_id, false),
        Err(CheckpointError::Refused("tx_id"))
    ));
    fixture.clock.wall.store(WALL - 1, Ordering::SeqCst);
    assert!(matches!(
        witness.append(&head, clock_delta(3, WALL - 1), &root_id, false),
        Err(CheckpointError::Refused("clock"))
    ));
    Ok(())
}
fn username_checkpoint_barrier_and_rollback_recovery_redo_compaction_saturation() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let root_id = id(77);
    for tx in 0..64 {
        let head = witness.head();
        witness.append(&head, clock_delta(tx, WALL), &root_id, false)?;
    }
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(65, WALL), &root_id, false),
        Err(CheckpointError::Refused("redo_root"))
    ));
    assert_eq!(witness.compact(64)?, 64);
    assert_eq!(witness.head(), head);
    witness.append(&head, clock_delta(65, WALL), &root_id, false)?;
    // Populate the physical redo boundary in one fixture transaction; no timing/stress loop.
    {
        let tx = witness.db.begin_write().map_err(storage)?;
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        let frame = wire::encode(&wire::Checkpoint {
            center_id: head.center_id.clone(),
            generation: 1,
            lsn: 1,
            previous_digest: id(0),
            delta: clock_delta(999, WALL),
        })?;
        for lsn in 1000..17367 {
            redo.insert(lsn, frame.as_slice()).map_err(storage)?;
        }
        drop(redo);
        tx.commit().map_err(storage)?;
    }
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(66, WALL), &id(88), false),
        Err(CheckpointError::Refused("redo_global"))
    ));
    for tx in 70..86 {
        let head = witness.head();
        witness.append(&head, clock_delta(tx, WALL), &id(88), true)?;
    }
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(87, WALL), &id(88), true),
        Err(CheckpointError::Refused("redo_global"))
    ));
    drop(witness);
    let witness = fixture.reopen()?;
    assert_eq!(witness.head(), head);
    Ok(())
}
