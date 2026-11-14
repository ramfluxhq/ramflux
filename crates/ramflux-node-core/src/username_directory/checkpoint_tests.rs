// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real typed-store transactions, exact CAS rejection and deterministic clock/bound tests.
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
    clock: Arc<Clock>,
    dir: ramflux_test_support::TestPath,
}
impl Fixture {
    fn new() -> Result<Self> {
        let dir = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("rf-username-checkpoint-{}", nonce()?));
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
    username_checkpoint_reopen_clock_refusals()?;
    username_checkpoint_tampered_head_refused()?;
    username_checkpoint_noncanonical_head_refused()?;
    username_checkpoint_missing_marker_refused()?;
    username_checkpoint_second_live_open_refused()?;
    username_checkpoint_compaction_cap_and_retry()?;
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
    let first = witness.image_page(None, 1)?;
    let rest = witness.image_page(first.next.as_deref(), 128)?;
    assert_eq!([first.rows, rest.rows].concat(), image);
    assert!(matches!(fixture.witness(), Err(CheckpointError::Refused("already_initialized"))));
    let head = witness.head();
    drop(witness);
    assert!(matches!(
        CheckpointWitness::open(
            &fixture.path("missing"),
            "center.example",
            1,
            fixture.clock.clone()
        ),
        Err(CheckpointError::Refused("missing_witness"))
    ));
    for (center, generation) in [("other.example", 1), ("center.example", 2)] {
        assert!(matches!(
            CheckpointWitness::open(
                &fixture.path("witness"),
                center,
                generation,
                fixture.clock.clone()
            ),
            Err(CheckpointError::Refused("identity"))
        ));
    }
    let mut witness = fixture.reopen()?;
    assert_eq!(witness.head(), head);
    assert_eq!(witness.image_page(None, 128)?.rows, image);
    assert_eq!(witness.transaction(&delta.tx_id)?, Some(checkpoint.clone()));
    assert_eq!(witness.compact(1)?, 1);
    assert_eq!(witness.transaction(&delta.tx_id)?, Some(checkpoint));
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
    for limit in [0, 129] {
        assert!(matches!(
            witness.image_page(None, limit),
            Err(CheckpointError::Refused("page_limit"))
        ));
    }
    assert!(matches!(witness.compact(1), Err(CheckpointError::Refused("compact_head"))));
    assert!(matches!(witness.transaction("short"), Err(CheckpointError::Refused("id"))));
    assert!(matches!(
        witness.append(&genesis, delta.clone(), "short", false),
        Err(CheckpointError::Refused("id"))
    ));
    let mut bad = delta.clone();
    bad.kind = wire::DeltaKind::Clock;
    assert!(matches!(
        witness.append(&genesis, bad, &root_id, false),
        Err(CheckpointError::Codec(wire::CodecError::Field("operation")))
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
    fixture.clock.wall.store(ramflux_protocol::MAX_SAFE_JSON_INTEGER + 1, Ordering::SeqCst);
    assert!(matches!(
        witness.append(&head, clock_delta(3, WALL), &root_id, false),
        Err(CheckpointError::Refused("clock"))
    ));
    fixture.clock.wall.store(WALL, Ordering::SeqCst);
    fixture.clock.mono.store(10, Ordering::SeqCst);
    witness.append(&head, clock_delta(3, WALL), &root_id, false)?;
    let head = witness.head();
    fixture.clock.mono.store(9, Ordering::SeqCst);
    assert!(matches!(
        witness.append(&head, clock_delta(4, WALL), &root_id, false),
        Err(CheckpointError::Refused("clock"))
    ));
    fixture.clock.mono.store(10, Ordering::SeqCst);
    // Exhaustion is a durable head boundary, not a loop to reach the safe-integer limit.
    let mut exhausted = head;
    exhausted.lsn = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
    {
        let tx = witness.db.begin_write().map_err(storage)?;
        put_head(&tx, &exhausted)?;
        tx.commit().map_err(storage)?;
    }
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert!(matches!(
        witness.append(&exhausted, clock_delta(4, WALL), &root_id, false),
        Err(CheckpointError::Refused("lsn_exhausted"))
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
    fixture.clock.wall.store(WALL + 86_400, Ordering::SeqCst);
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

#[test]
fn username_checkpoint_reopen_clock_refusals() -> TestResult {
    let fixture = Fixture::new()?;
    let witness = fixture.witness()?;
    let head = witness.head();
    drop(witness);
    for wall in [WALL - 1, ramflux_protocol::MAX_SAFE_JSON_INTEGER + 1] {
        fixture.clock.wall.store(wall, Ordering::SeqCst);
        assert!(
            matches!(fixture.reopen(), Err(CheckpointError::Refused("clock"))),
            "reopen wall {wall}"
        );
    }
    fixture.clock.wall.store(WALL, Ordering::SeqCst);
    assert_eq!(fixture.reopen()?.head(), head);
    Ok(())
}
#[test]
fn username_checkpoint_tampered_head_refused() -> TestResult {
    let max = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
    for (field, value, error) in [
        ("codec_version", serde_json::json!(2), StoredError::Refused("schema")),
        ("policy", serde_json::json!("wrong-policy"), StoredError::Refused("schema")),
        ("clock_floor", serde_json::json!(max + 1), StoredError::Refused("clock")),
        ("digest", serde_json::json!("!"), StoredError::Refused("id")),
        ("center_id", serde_json::json!("Wrong!"), StoredError::Codec("node")),
        ("generation", serde_json::json!(0), StoredError::Codec("generation")),
        ("lsn", serde_json::json!(max + 1), StoredError::Codec("lsn")),
        ("center_id", serde_json::json!("foreign.example"), StoredError::Refused("identity")),
        ("generation", serde_json::json!(2), StoredError::Refused("identity")),
        ("digest", serde_json::json!(id(1)), StoredError::Codec("lsn")),
    ] {
        let fixture = Fixture::new()?;
        let witness = fixture.witness()?;
        let mut head = serde_json::to_value(witness.head())?;
        head[field] = value;
        let tx = witness.db.begin_write().map_err(storage)?;
        // Raw corruption deliberately bypasses the product's canonical/number validator.
        tx.open_table(META)
            .map_err(storage)?
            .insert("head", serde_json::to_vec(&head)?.as_slice())
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        drop(witness);
        assert_stored_error(fixture.reopen(), error)?;
    }
    Ok(())
}
#[derive(Clone, Copy)]
enum StoredError {
    Refused(&'static str),
    Codec(&'static str),
}
fn assert_stored_error(result: Result<CheckpointWitness>, expected: StoredError) -> TestResult {
    match (result, expected) {
        (Err(CheckpointError::Refused(actual)), StoredError::Refused(expected)) => {
            assert_eq!(actual, expected);
        }
        (
            Err(CheckpointError::Codec(wire::CodecError::Field(actual))),
            StoredError::Codec(expected),
        ) => assert_eq!(actual, expected),
        (Err(other), _) => return Err(format!("unexpected stored-field error: {other}").into()),
        (Ok(_), _) => return Err("corrupt stored field was accepted".into()),
    }
    Ok(())
}
#[test]
fn username_checkpoint_noncanonical_head_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let witness = fixture.witness()?;
    let mut bytes = vec![b' '];
    bytes.extend(canonical(&witness.head())?);
    {
        let tx = witness.db.begin_write().map_err(storage)?;
        tx.open_table(META).map_err(storage)?.insert("head", bytes.as_slice()).map_err(storage)?;
        tx.commit().map_err(storage)?;
    }
    drop(witness);
    assert!(matches!(fixture.reopen(), Err(CheckpointError::Refused("head_canonical"))));
    Ok(())
}
#[test]
fn username_checkpoint_missing_marker_refused() -> TestResult {
    for key in ["initialized", "head"] {
        let fixture = Fixture::new()?;
        let witness = fixture.witness()?;
        let tx = witness.db.begin_write().map_err(storage)?;
        tx.open_table(META).map_err(storage)?.remove(key).map_err(storage)?;
        tx.commit().map_err(storage)?;
        drop(witness);
        assert_stored_error(fixture.reopen(), StoredError::Refused("uninitialized"))?;
    }
    Ok(())
}
#[test]
fn username_checkpoint_second_live_open_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let witness = fixture.witness()?;
    match fixture.reopen() {
        Err(CheckpointError::Storage(message)) => {
            assert_eq!(message, "Database already open. Cannot acquire lock.");
        }
        Err(other) => return Err(format!("unexpected live-open refusal: {other}").into()),
        Ok(_) => return Err("second live witness open was accepted".into()),
    }
    let head = witness.head();
    drop(witness);
    assert_eq!(fixture.reopen()?.head(), head);
    Ok(())
}
#[test]
fn username_checkpoint_compaction_cap_and_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let mut original = None;
    for n in 0..129 {
        let checkpoint = witness.append(
            &witness.head(),
            clock_delta(n, WALL),
            &id(u8::try_from(n / 64)?),
            false,
        )?;
        if n == 0 {
            original = Some(checkpoint);
        }
    }
    let original = original.ok_or("original result")?;
    let head = witness.head();
    fixture.clock.wall.store(WALL - 1, Ordering::SeqCst);
    assert!(matches!(witness.compact(129), Err(CheckpointError::Refused("clock"))));
    fixture.clock.wall.store(WALL, Ordering::SeqCst);
    assert_eq!(witness.compact(129)?, 128, "bounded compaction must reach128");
    {
        use redb::{ReadableDatabase, ReadableTableMetadata};
        let tx = witness.db.begin_read().map_err(storage)?;
        assert_eq!(tx.open_table(REDO).map_err(storage)?.len().map_err(storage)?, 1);
        assert_eq!(tx.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?, 128);
    }
    assert_eq!(witness.transaction(&original.delta.tx_id)?, Some(original.clone()));
    assert!(matches!(
        witness.append(&head, original.delta.clone(), &id(0), false),
        Err(CheckpointError::Refused("tx_id"))
    ));
    assert_eq!(witness.head(), head);
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert_eq!(witness.transaction(&original.delta.tx_id)?, Some(original.clone()));
    assert_eq!(witness.compact(129)?, 1);
    // Witness time wins over an older caller reading, including across a second boundary.
    fixture.clock.wall.store(WALL + 1, Ordering::SeqCst);
    let checkpoint = witness.append(&witness.head(), clock_delta(200, WALL - 99), &id(4), false)?;
    assert_eq!(checkpoint.delta.clock_floor, WALL + 1);
    assert_eq!(witness.head().clock_floor, WALL + 1);
    fixture.clock.wall.store(WALL + 86_399, Ordering::SeqCst);
    assert_eq!(witness.transaction(&original.delta.tx_id)?, Some(original.clone()));
    fixture.clock.wall.store(WALL + 86_400, Ordering::SeqCst);
    witness.append(&witness.head(), clock_delta(201, WALL), &id(4), false)?;
    assert!(witness.transaction(&original.delta.tx_id)?.is_none());
    username_checkpoint_retained_result_capacity()?;
    Ok(())
}

fn username_checkpoint_retained_result_capacity() -> TestResult {
    let fixture = Fixture::new()?;
    let witness = fixture.witness()?;
    let mut head = witness.head();
    // Seed a complete valid retained chain in one transaction at the physical boundary.
    {
        let tx = witness.db.begin_write().map_err(storage)?;
        let mut results = tx.open_table(COMPACTED).map_err(storage)?;
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        for lsn in 1..=16368 {
            let checkpoint = wire::Checkpoint {
                center_id: head.center_id.clone(),
                generation: head.generation,
                lsn,
                previous_digest: head.digest.clone(),
                delta: clock_delta(lsn, WALL),
            };
            results.insert(lsn, wire::encode(&checkpoint)?.as_slice()).map_err(storage)?;
            ids.insert(checkpoint.delta.tx_id.as_str(), lsn).map_err(storage)?;
            head.lsn = lsn;
            head.digest = ramflux_crypto::username_directory::checkpoint_hash(&checkpoint)?;
        }
        drop(ids);
        drop(results);
        put_head(&tx, &head)?;
        tx.commit().map_err(storage)?;
    }
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert!(matches!(
        witness.append(&witness.head(), clock_delta(20000, WALL), &id(3), false),
        Err(CheckpointError::Refused("result_global"))
    ));
    for n in 20000..20016 {
        witness.append(&witness.head(), clock_delta(n, WALL), &id(3), true)?;
    }
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(20016, WALL), &id(3), true),
        Err(CheckpointError::Refused("result_global"))
    ));
    assert_eq!(witness.head(), head);
    Ok(())
}

#[test]
fn username_checkpoint_retained_root_cap() -> TestResult {
    use redb::{ReadableDatabase, ReadableTableMetadata};
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let owner = id(77);
    for tx_id in 0..64 {
        witness.append(&witness.head(), clock_delta(tx_id, WALL), &owner, false)?;
    }
    assert_eq!(witness.compact(64)?, 64);
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(65, WALL), &owner, false),
        Err(CheckpointError::Refused("redo_root"))
    ));
    assert_eq!(witness.head(), head);
    {
        let tx = witness.db.begin_read().map_err(storage)?;
        assert_eq!(tx.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?, 64);
        let meta = tx.open_table(META).map_err(storage)?;
        for lsn in 1..=64 {
            assert_eq!(
                serde_json::from_slice::<String>(
                    meta.get(format!("redo_owner:{lsn}").as_str())
                        .map_err(storage)?
                        .ok_or("owner missing")?
                        .value()
                )?,
                owner
            );
        }
    }
    witness.append(&head, clock_delta(66, WALL), &id(78), false)?;
    drop(witness);
    let mut witness = fixture.reopen()?;
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(65, WALL), &owner, false),
        Err(CheckpointError::Refused("redo_root"))
    ));
    assert_eq!(witness.head(), head);
    Ok(())
}
// Root 1 and 2 fill the first 128 expired slots; root 3 must still prune its own expired results.
fn expired_quota_progress(reopen_first: bool) -> TestResult {
    use redb::{ReadableDatabase, ReadableTableMetadata};
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    for n in 0..192 {
        let head = witness.head();
        witness.append(&head, clock_delta(n, WALL), &id(u8::try_from(n / 64 + 1)?), false)?;
    }
    assert_eq!(witness.compact(192)?, 128);
    assert_eq!(witness.compact(192)?, 64);
    let owner = id(3);
    let head = witness.head();
    assert!(matches!(
        witness.append(&head, clock_delta(192, WALL), &owner, false),
        Err(CheckpointError::Refused("redo_root"))
    ));
    assert_eq!(witness.head(), head);
    fixture.clock.wall.store(WALL + 86_400, Ordering::SeqCst);
    let mut witness = if reopen_first {
        drop(witness);
        fixture.reopen()?
    } else {
        witness
    };
    if reopen_first {
        // A compaction pass with nothing to compact still prunes expired results, bounded to 128.
        assert_eq!(witness.compact(192)?, 0);
        let tables = witness.db.begin_read().map_err(storage)?;
        assert_eq!(tables.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?, 64);
    }
    let head = witness.head();
    witness.append(&head, clock_delta(192, WALL + 86_400), &owner, false)?;
    assert_eq!(witness.head().lsn, 193);
    assert!(witness.transaction(&clock_delta(0, WALL).tx_id)?.is_none());
    let tables = witness.db.begin_read().map_err(storage)?;
    assert_eq!(tables.open_table(REDO).map_err(storage)?.len().map_err(storage)?, 1);
    assert_eq!(tables.open_table(COMPACTED).map_err(storage)?.len().map_err(storage)?, 0);
    drop(tables);
    drop(witness);
    let witness = fixture.reopen()?;
    assert_eq!(witness.head().lsn, 193);
    Ok(())
}

#[test]
fn username_checkpoint_expired_quota_progress() -> TestResult {
    expired_quota_progress(false)?;
    expired_quota_progress(true)
}

#[test]
fn username_checkpoint_caller_batch_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let head = witness.head();
    let mut delta = clock_delta(1, WALL);
    delta.rows = vec![wire::Replacement::Batch {
        key: id(9),
        old: None,
        new: Some(wire::BatchRow {
            batch_id: id(9),
            root: id(3),
            request_hash: id(4),
            abort_tx_id: id(5),
            lsn_n1: 1,
            lsn_n2: 2,
            retain_until: WALL + 86_400,
            result: wire::BatchResult {
                abort_digest: id(6),
                delete_digest: id(7),
                clock_floor: WALL,
            },
        }),
    }];
    assert!(matches!(
        witness.append(&head, delta.clone(), &id(3), false),
        Err(CheckpointError::Codec(wire::CodecError::Field("batch")))
    ));
    assert!(matches!(cell(&delta.rows[0]), Err(CheckpointError::Refused("batch"))));
    assert_eq!(witness.head(), head);
    Ok(())
}

#[test]
fn username_checkpoint_expiry_clock_floor_durable() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let original = witness.append(&witness.head(), clock_delta(500, WALL), &id(3), false)?;
    let head = witness.head();
    fixture.clock.wall.store(WALL + 86400, Ordering::SeqCst);
    assert_eq!(witness.compact(head.lsn)?, 1);
    assert!(witness.transaction(&original.delta.tx_id)?.is_none());
    fixture.clock.wall.store(WALL, Ordering::SeqCst);
    assert!(matches!(
        witness.append(&head, original.delta.clone(), &id(3), false),
        Err(CheckpointError::Refused("clock"))
    ));
    assert!(matches!(witness.compact(head.lsn), Err(CheckpointError::Refused("clock"))));
    drop(witness);
    assert_stored_error(fixture.reopen(), StoredError::Refused("clock"))?;
    fixture.clock.wall.store(WALL + 86400, Ordering::SeqCst);
    let witness = fixture.reopen()?;
    assert_eq!(witness.head(), head);
    assert!(witness.transaction(&original.delta.tx_id)?.is_none());
    Ok(())
}
#[test]
fn username_checkpoint_compaction_clock_bounds() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.clock.mono.store(1, Ordering::SeqCst);
    let mut witness = fixture.witness()?;
    witness.append(&witness.head(), clock_delta(600, WALL), &id(3), false)?;
    let head = witness.head();
    fixture.clock.mono.store(0, Ordering::SeqCst);
    assert!(matches!(witness.compact(head.lsn), Err(CheckpointError::Refused("clock"))));
    fixture.clock.mono.store(1, Ordering::SeqCst);
    fixture.clock.wall.store(ramflux_protocol::MAX_SAFE_JSON_INTEGER + 1, Ordering::SeqCst);
    assert!(matches!(witness.compact(head.lsn), Err(CheckpointError::Refused("clock"))));
    assert_eq!(witness.head(), head);
    fixture.clock.wall.store(WALL, Ordering::SeqCst);
    assert_eq!(witness.compact(head.lsn)?, 1);
    Ok(())
}
#[test]
fn username_checkpoint_clock_boundaries_and_markers() -> TestResult {
    username_checkpoint_generation_and_center_boundaries()?;
    let max = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
    for wall in [0, max] {
        let fixture = Fixture::new()?;
        fixture.clock.wall.store(wall, Ordering::SeqCst);
        let mut witness = fixture.witness()?;
        let record = witness.append(&witness.head(), clock_delta(700, wall), &id(3), false)?;
        assert_eq!(record.delta.clock_floor, wall);
        assert_eq!(witness.compact(record.lsn)?, 1);
        let head = witness.head();
        drop(witness);
        assert_eq!(fixture.reopen()?.head(), head);
    }
    for (value, error) in [
        (None, "clock_marker"),
        (Some(b"null".to_vec()), "clock"),
        (Some((max + 1).to_string().into_bytes()), "clock"),
        (Some((WALL - 1).to_string().into_bytes()), "clock"),
        (Some(format!(" {WALL}").into_bytes()), "clock_canonical"),
    ] {
        let fixture = Fixture::new()?;
        let witness = fixture.witness()?;
        let tx = witness.db.begin_write().map_err(storage)?;
        {
            let mut meta = tx.open_table(META).map_err(storage)?;
            if let Some(bytes) = value {
                meta.insert("safe_clock", bytes.as_slice()).map_err(storage)?;
            } else {
                meta.remove("safe_clock").map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)?;
        drop(witness);
        assert_stored_error(fixture.reopen(), StoredError::Refused(error))?;
    }
    let fixture = Fixture::new()?;
    let witness = fixture.witness()?;
    let tx = witness.db.begin_write().map_err(storage)?;
    tx.open_table(META)
        .map_err(storage)?
        .insert("initialized", b"0".as_slice())
        .map_err(storage)?;
    tx.commit().map_err(storage)?;
    drop(witness);
    assert_stored_error(fixture.reopen(), StoredError::Refused("uninitialized"))?;
    Ok(())
}

fn username_checkpoint_generation_and_center_boundaries() -> TestResult {
    let max = ramflux_protocol::MAX_SAFE_JSON_INTEGER;
    let center = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)].join(".");
    assert_eq!(center.len(), 253);
    let fixture = Fixture::new()?;
    let mut witness = CheckpointWitness::initialize(
        &fixture.path("maximum"),
        &center,
        max,
        fixture.clock.clone(),
    )?;
    witness.append(&witness.head(), clock_delta(800, WALL), &id(3), false)?;
    let mut maximal = witness.head();
    maximal.lsn = max;
    maximal.validate()?;
    let head = witness.head();
    drop(witness);
    assert_eq!(
        CheckpointWitness::open(&fixture.path("maximum"), &center, max, fixture.clock.clone())?
            .head(),
        head
    );
    Ok(())
}
