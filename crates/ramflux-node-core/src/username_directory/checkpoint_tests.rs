// SPDX-License-Identifier: BSD-3-Clause
// Copyright (third) 2026 Span Brain

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
    fn advance(&self, ms: u64) {
        self.mono.fetch_add(ms, Ordering::SeqCst);
        self.wall.fetch_add(ms / 1000, Ordering::SeqCst);
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
struct Observer {
    fail: Option<&'static str>,
    events: std::sync::Mutex<Vec<&'static str>>,
}
impl Observer {
    fn new(fail: Option<&'static str>) -> Self {
        Self { fail, events: std::sync::Mutex::new(Vec::new()) }
    }
}
impl CheckpointObserver for Observer {
    fn boundary(&self, name: &'static str) -> Result<()> {
        self.events.lock().map_err(storage)?.push(name);
        require(self.fail != Some(name), "injected_fault")
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
        {
            let mut witness = CheckpointWitness::initialize(
                &self.path("witness"),
                "center.example",
                1,
                self.clock.clone(),
            )?;
            witness.configure_center_key(
                ed25519_dalek::SigningKey::from_bytes(&[29; 32]).verifying_key(),
            )?;
            Ok(witness)
        }
    }
    fn reopen(&self) -> Result<CheckpointWitness> {
        let mut witness = CheckpointWitness::open(
            &self.path("witness"),
            "center.example",
            1,
            self.clock.clone(),
        )?;
        witness.configure_center_key(
            ed25519_dalek::SigningKey::from_bytes(&[29; 32]).verifying_key(),
        )?;
        Ok(witness)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn admitted(witness: &mut CheckpointWitness, lease: &WriterLease, root: &str) -> Result<String> {
    witness.admit_mutation(
        lease,
        MutationAdmission { root: root.into(), home: "home.example".into(), control: false },
    )
}
fn clock_delta(incarnation: &str, tx: u8, time: u64) -> wire::CheckpointDelta {
    wire::CheckpointDelta {
        kind: wire::DeltaKind::Clock,
        tx_id: id(tx),
        writer_incarnation: incarnation.into(),
        clock_floor: time,
        operation: None,
        rows: Vec::new(),
    }
}
fn append_clock(
    witness: &mut CheckpointWitness,
    lease: &WriterLease,
    tx: u8,
) -> Result<wire::Checkpoint> {
    let admission = admitted(witness, lease, &id(77))?;
    let head = witness.head();
    witness.append(lease, &admission, &head, |stamp| {
        Ok(clock_delta(&lease.incarnation, tx, stamp.wall))
    })
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
#[test]
fn username_checkpoint_barrier_and_rollback_recovery() -> TestResult {
    for boundary in ["before_image", "after_image", "before_witness_fsync", "after_witness_fsync"] {
        let fixture = Fixture::new()?;
        let mut witness = fixture.witness()?;
        let genesis = witness.head();
        let lease = witness.acquire(&id(1))?;
        let primary = CheckpointPrimary::create(&fixture.path("primary"), &genesis)?;
        primary.reconcile(&mut witness, &lease)?;
        let observer = Arc::new(Observer::new(Some(boundary)));
        witness.set_observer(observer.clone());
        assert!(matches!(
            append_clock(&mut witness, &lease, 10),
            Err(CheckpointError::Refused("injected_fault"))
        ));
        let committed = boundary == "after_witness_fsync";
        assert_eq!(witness.head().lsn, u64::from(committed));
        drop(primary);
        drop(witness);
        let mut witness = fixture.reopen()?;
        assert_eq!(witness.head().lsn, u64::from(committed));
        assert_eq!(witness.transaction(&id(10))?.is_some(), committed);
        assert!(matches!(witness.ready(&lease), Err(CheckpointError::Refused("lease"))));
        let lease = witness.acquire(&id(2))?;
        let primary = CheckpointPrimary::open(&fixture.path("primary"))?;
        if committed {
            assert!(matches!(
                primary.reconcile(&mut witness, &lease),
                Err(CheckpointError::Refused("primary_behind"))
            ));
            primary.replay_transaction(&mut witness, &lease, &id(10), &Observer::new(None))?;
        } else {
            primary.reconcile(&mut witness, &lease)?;
        }
        witness.ready(&lease)?;
    }
    for boundary in ["before_primary_image", "before_primary_fsync", "after_primary_fsync"] {
        let fixture = Fixture::new()?;
        let mut witness = fixture.witness()?;
        let lease = witness.acquire(&id(1))?;
        let primary = CheckpointPrimary::create(&fixture.path("primary"), &witness.head())?;
        primary.reconcile(&mut witness, &lease)?;
        let checkpoint = append_clock(&mut witness, &lease, 11)?;
        assert!(matches!(
            primary.apply(&mut witness, &lease, &checkpoint, &Observer::new(Some(boundary))),
            Err(CheckpointError::Refused("injected_fault"))
        ));
        assert!(matches!(witness.ready(&lease), Err(CheckpointError::Refused("primary_applied"))));
        drop(primary);
        let primary = CheckpointPrimary::open(&fixture.path("primary"))?;
        if boundary == "after_primary_fsync" {
            primary.reconcile(&mut witness, &lease)?;
        } else {
            primary.apply(&mut witness, &lease, &checkpoint, &Observer::new(None))?;
        }
        witness.ready(&lease)?;
    }
    Ok(())
}
#[test]
fn username_checkpoint_closed_heads_leases_and_cas() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let genesis = witness.head();
    let first = witness.acquire(&id(1))?;
    assert!(matches!(witness.ready(&first), Err(CheckpointError::Refused("primary_applied"))));
    assert!(matches!(witness.acquire(&id(2)), Err(CheckpointError::Refused("lease_busy"))));
    let primary = CheckpointPrimary::create(&fixture.path("first"), &genesis)?;
    primary.reconcile(&mut witness, &first)?;
    for field in 0..3 {
        let mut wrong = first.clone();
        match field {
            0 => wrong.generation += 1,
            1 => wrong.witness_boot = id(9),
            _ => wrong.incarnation = id(9),
        }
        assert!(matches!(witness.renew(&wrong), Err(CheckpointError::Refused("lease"))));
    }
    for field in 0..7 {
        let mut wrong = genesis.clone();
        match field {
            0 => wrong.center_id = "other.example".into(),
            1 => wrong.generation = 2,
            2 => wrong.lsn = 1,
            3 => wrong.digest = id(9),
            4 => wrong.clock_floor += 1,
            5 => wrong.codec_version = 2,
            _ => wrong.policy = "unknown".into(),
        }
        assert!(matches!(
            witness.primary_applied(&first, &wrong),
            Err(CheckpointError::Refused("primary_head"))
        ));
    }
    let checkpoint = append_clock(&mut witness, &first, 12)?;
    assert!(matches!(witness.ready(&first), Err(CheckpointError::Refused("primary_applied"))));
    primary.apply(&mut witness, &first, &checkpoint, &Observer::new(None))?;
    let job = admitted(&mut witness, &first, &id(77))?;
    assert!(matches!(
        witness.append(&first, &job, &genesis, |s| Ok(clock_delta(&first.incarnation, 13, s.wall))),
        Err(CheckpointError::Refused("head_cas"))
    ));
    fixture.clock.advance(10_000);
    assert!(matches!(witness.ready(&first), Err(CheckpointError::Refused("lease"))));
    let second = witness.acquire(&id(2))?;
    assert!(matches!(
        witness.primary_applied(&first, &witness.head()),
        Err(CheckpointError::Refused("lease"))
    ));
    let replacement = CheckpointPrimary::rebuild(&fixture.path("second"), &mut witness, &second)?;
    witness.ready(&second)?;
    assert!(matches!(
        primary.apply(&mut witness, &first, &checkpoint, &Observer::new(None)),
        Err(CheckpointError::Refused("lease"))
    ));
    drop(replacement);
    let old_boot = witness.witness_boot().to_owned();
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert_ne!(old_boot, witness.witness_boot());
    assert!(matches!(witness.renew(&second), Err(CheckpointError::Refused("lease"))));
    assert!(
        CheckpointWitness::initialize(
            &fixture.path("witness"),
            "center.example",
            1,
            fixture.clock.clone()
        )
        .is_err()
    );
    assert!(
        CheckpointWitness::open(
            &fixture.path("absent"),
            "center.example",
            1,
            fixture.clock.clone()
        )
        .is_err()
    );
    assert!(
        CheckpointWitness::open(
            &fixture.path("witness"),
            "other.example",
            1,
            fixture.clock.clone()
        )
        .is_err()
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct RevisionSettings {
    epoch: u64,
    delete: bool,
    named: bool,
}
fn revision_operation(
    signer: &ed25519_dalek::SigningKey,
    old: &wire::RootRow,
    root_id: &str,
    profile: &wire::ProfileRef,
    binding: Option<&wire::UsernameBinding>,
    settings: RevisionSettings,
) -> Result<wire::UsernameOperation> {
    let RevisionSettings { epoch, delete, named } = settings;
    ramflux_crypto::username_directory::sign_operation(
        signer,
        wire::UsernameOperationBody {
            action: if delete {
                wire::Action::Delete
            } else if named && old.epoch == 0 {
                wire::Action::Claim
            } else {
                wire::Action::ProfileUpdate
            },
            operation_id: id(u8::try_from(epoch + 30).map_err(storage)?),
            principal_commitment: root_id.to_owned(),
            expected_epoch: old.epoch,
            next_epoch: epoch,
            expected_profile: old.profile.clone(),
            profile: profile.clone(),
            old_name: old.name.clone(),
            binding: binding.cloned(),
            discoverable: named && !delete,
            issued_at: WALL - 10,
            expires_at: WALL + 290,
        },
    )
    .map_err(CheckpointError::from)
}
fn publish_revision_named(
    witness: &mut CheckpointWitness,
    primary: &CheckpointPrimary,
    lease: &WriterLease,
    previous: Option<wire::RootRow>,
    settings: RevisionSettings,
) -> Result<wire::RootRow> {
    let RevisionSettings { epoch, delete, named } = settings;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let root_id = ramflux_crypto::identity_root_commitment(&signer.verifying_key());
    let mut old = previous.unwrap_or_else(|| root(0, false));
    let profile = if delete {
        old.profile.clone()
    } else {
        wire::ProfileRef {
            version: 2,
            epoch,
            hash: Some(id(u8::try_from(epoch + 10).map_err(storage)?)),
        }
    };
    let binding = revision_binding(&signer, &root_id, settings)?;
    let operation =
        revision_operation(&signer, &old, &root_id, &profile, binding.as_ref(), settings)?;
    let hash = ramflux_crypto::username_directory::operation_hash(&operation)?;
    let mut reserved = old.clone();
    reserved.pending_operation_id = Some(operation.body.operation_id.clone());
    let detail = wire::OperationRow {
        operation: operation.clone(),
        operation_hash: hash.clone(),
        state: wire::ReceiptState::Reserved,
        reserved_at: WALL,
        reservation_expires_at: WALL + 120,
        finished_at: None,
        retain_until: None,
    };
    let key = wire::OperationKey {
        root: root_id.clone(),
        operation_id: operation.body.operation_id.clone(),
    };
    let mut rows = vec![
        wire::Replacement::Root {
            key: root_id.clone(),
            old: (old.epoch > 0).then_some(old.clone()),
            new: Some(reserved.clone()),
        },
        wire::Replacement::Operation { key: key.clone(), old: None, new: Some(detail.clone()) },
    ];
    rows.sort_by_key(|r| r.order_key().unwrap_or_default());
    let job = admitted(witness, lease, &root_id)?;
    let expected = witness.head();
    let checkpoint = witness.append(lease, &job, &expected, |stamp| {
        Ok(wire::CheckpointDelta {
            kind: wire::DeltaKind::Reserve,
            tx_id: id(u8::try_from(epoch + 60).map_err(storage)?),
            writer_incarnation: lease.incarnation.clone(),
            clock_floor: stamp.wall,
            operation: Some(operation.clone()),
            rows,
        })
    })?;
    primary.apply(witness, lease, &checkpoint, &Observer::new(None))?;
    old.name = binding.as_ref().map(|second| second.body.name.clone());
    old.binding_hash =
        binding.as_ref().map(ramflux_crypto::username_directory::binding_hash).transpose()?;
    old.current_binding = binding;
    old.discoverable = named && !delete;
    old.epoch = epoch;
    old.profile = profile;
    old.deleted = delete;
    old.last_operation_id = Some(operation.body.operation_id.clone());
    old.last_operation_hash = Some(hash);
    old.receipt_decision = Some(wire::ReceiptDecision { committed_at: WALL });
    let mut terminal = detail.clone();
    terminal.state = wire::ReceiptState::Committed;
    terminal.finished_at = Some(WALL);
    terminal.retain_until = Some(WALL + 86400);
    let mut rows = vec![
        wire::Replacement::Root {
            key: root_id.clone(),
            old: Some(reserved),
            new: Some(old.clone()),
        },
        wire::Replacement::Operation { key, old: Some(detail), new: Some(terminal) },
    ];
    rows.sort_by_key(|r| r.order_key().unwrap_or_default());
    let job = admitted(witness, lease, &root_id)?;
    let expected = witness.head();
    let checkpoint = witness.append(lease, &job, &expected, |stamp| {
        Ok(wire::CheckpointDelta {
            kind: wire::DeltaKind::Commit,
            tx_id: id(u8::try_from(epoch + 90).map_err(storage)?),
            writer_incarnation: lease.incarnation.clone(),
            clock_floor: stamp.wall,
            operation: Some(operation),
            rows,
        })
    })?;
    primary.apply(witness, lease, &checkpoint, &Observer::new(None))?;
    Ok(old)
}
#[test]
fn username_checkpoint_profile_delete_rollback_image_rebuild() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let lease = witness.acquire(&id(1))?;
    let primary = CheckpointPrimary::create(&fixture.path("primary"), &witness.head())?;
    primary.reconcile(&mut witness, &lease)?;
    let first = publish_revision(&mut witness, &primary, &lease, None, 1, false)?;
    drop(primary);
    std::fs::copy(fixture.path("primary"), fixture.path("rollback"))?;
    let primary = CheckpointPrimary::open(&fixture.path("primary"))?;
    let updated = publish_revision(&mut witness, &primary, &lease, Some(first), 2, false)?;
    let deleted = publish_revision(&mut witness, &primary, &lease, Some(updated), 3, true)?;
    let head = witness.head();
    assert_eq!(head.lsn, 6);
    assert_eq!(witness.compact(&lease, head.lsn)?, 6);
    assert!(witness.transaction(&id(93))?.is_none());
    drop(primary);
    drop(witness);
    std::fs::copy(fixture.path("rollback"), fixture.path("primary"))?;
    let primary = CheckpointPrimary::open(&fixture.path("primary"))?;
    let mut witness = fixture.reopen()?;
    let lease = witness.acquire(&id(2))?;
    assert!(matches!(
        primary.reconcile(&mut witness, &lease),
        Err(CheckpointError::Refused("primary_behind"))
    ));
    assert!(matches!(witness.ready(&lease), Err(CheckpointError::Refused("primary_applied"))));
    let recovered = CheckpointPrimary::rebuild(&fixture.path("recovered"), &mut witness, &lease)?;
    assert_eq!(recovered.head()?, head);
    witness.ready(&lease)?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let root_id = ramflux_crypto::identity_root_commitment(&signer.verifying_key());
    let key = wire::Replacement::Root { key: root_id, old: None, new: Some(deleted.clone()) };
    let saved = recovered.image_cell(&key)?.ok_or("missing recovered root")?;
    let expected = canonical(&key)?;
    assert_eq!(saved, expected);
    assert_eq!(deleted.epoch, 3);
    assert_eq!(deleted.profile.epoch, 2);
    assert!(deleted.deleted);
    assert!(matches!(
        primary.reconcile(&mut witness, &lease),
        Err(CheckpointError::Refused("primary_behind"))
    ));
    for limit in [0, 129] {
        assert!(matches!(
            witness.image_page(None, limit),
            Err(CheckpointError::Refused("page_limit"))
        ));
    }
    Ok(())
}
#[test]
fn username_checkpoint_queue_deadline_clock_and_redo_limits() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let lease = witness.acquire(&id(1))?;
    let head = witness.head();
    let primary = CheckpointPrimary::create(&fixture.path("primary"), &head)?;
    primary.reconcile(&mut witness, &lease)?;
    assert!(matches!(
        witness.admit_mutation(
            &lease,
            MutationAdmission { root: "bad".into(), home: "home.example".into(), control: false }
        ),
        Err(CheckpointError::Refused("id"))
    ));
    let first = admitted(&mut witness, &lease, &id(70))?;
    assert!(matches!(
        admitted(&mut witness, &lease, &id(70)),
        Err(CheckpointError::Refused("queue_root"))
    ));
    for n in 71..74 {
        admitted(&mut witness, &lease, &id(n))?;
    }
    assert!(matches!(
        admitted(&mut witness, &lease, &id(74)),
        Err(CheckpointError::Refused("queue_home"))
    ));
    fixture.clock.advance(5000);
    assert!(matches!(
        witness.append(&lease, &first, &head, |s| Ok(clock_delta(&lease.incarnation, 100, s.wall))),
        Err(CheckpointError::Refused("deadline"))
    ));
    for field in ["writer", "time"] {
        let job = admitted(&mut witness, &lease, &id(74))?;
        let expected = witness.head();
        let result = witness.append(&lease, &job, &expected, |s| {
            let mut delta = clock_delta(&lease.incarnation, 100, s.wall);
            if field == "writer" {
                delta.writer_incarnation = id(9);
            } else {
                delta.clock_floor -= 1;
            }
            Ok(delta)
        });
        assert!(
            matches!(result,Err(CheckpointError::Refused(rule)) if rule==if field=="writer" {"writer_incarnation"} else {"commit_clock"})
        );
    }
    witness.renew(&lease)?;
    for n in 1..=64_u8 {
        let checkpoint = append_clock(&mut witness, &lease, n)?;
        primary.apply(&mut witness, &lease, &checkpoint, &Observer::new(None))?;
    }
    assert!(matches!(
        append_clock(&mut witness, &lease, 65),
        Err(CheckpointError::Refused("redo_root"))
    ));
    let head = witness.head();
    assert_eq!(witness.compact(&lease, head.lsn)?, 64);
    let checkpoint = append_clock(&mut witness, &lease, 65)?;
    primary.apply(&mut witness, &lease, &checkpoint, &Observer::new(None))?;
    fixture.clock.wall.store(WALL - 1, Ordering::SeqCst);
    assert!(matches!(witness.ready(&lease), Err(CheckpointError::Refused("clock"))));
    fixture.clock.wall.store(WALL + 5, Ordering::SeqCst);
    assert!(matches!(witness.renew(&lease), Err(CheckpointError::Refused("lease"))));
    Ok(())
}

fn publish_revision(
    witness: &mut CheckpointWitness,
    primary: &CheckpointPrimary,
    lease: &WriterLease,
    previous: Option<wire::RootRow>,
    epoch: u64,
    delete: bool,
) -> Result<wire::RootRow> {
    publish_revision_named(
        witness,
        primary,
        lease,
        previous,
        RevisionSettings { epoch, delete, named: false },
    )
}

fn resolve_context(root_id: &str, call: u8) -> ContextRequest {
    ContextRequest {
        call_id: id(call),
        session: id(44),
        caller_root: id(45),
        root: root_id.into(),
        home: "caller.example".into(),
        kind: ContextKind::Resolve { name: "alice2".into(), nonce: id(46) },
    }
}
fn candidate(
    witness: &CheckpointWitness,
    lease: &WriterLease,
    request: &ContextRequest,
    root: &wire::RootRow,
) -> Result<wire::ServeCandidate> {
    let center = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
    let response = ramflux_crypto::username_directory::sign_resolve(
        &center,
        "center.example",
        wire::DirectoryResolveBody {
            center_id: "center.example".into(),
            name: "alice2".into(),
            node: root.node.clone(),
            principal_commitment: request.root.clone(),
            epoch: root.epoch,
            binding_hash: root.binding_hash.clone().ok_or(CheckpointError::Refused("binding"))?,
            profile: root.profile.clone(),
            request_nonce: id(46),
            issued_at: WALL,
            expires_at: WALL + 60,
        },
    )?;
    let head = witness.head();
    Ok(wire::ServeCandidate::Resolve {
        generation: head.generation,
        witness_boot: witness.witness_boot().into(),
        writer_incarnation: lease.incarnation.clone(),
        primary_lsn: head.lsn,
        primary_digest: head.digest,
        call_id: request.call_id.clone(),
        response,
    })
}
#[test]
fn username_checkpoint_publication_fields_partial_write_and_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let first = witness.acquire(&id(1))?;
    let primary = CheckpointPrimary::create(&fixture.path("primary"), &witness.head())?;
    primary.reconcile(&mut witness, &first)?;
    let current = publish_revision_named(
        &mut witness,
        &primary,
        &first,
        None,
        RevisionSettings { epoch: 1, delete: false, named: true },
    )?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let root_id = ramflux_crypto::identity_root_commitment(&signer.verifying_key());
    let request = resolve_context(&root_id, 50);
    witness.admit_context(&first, request.clone())?;
    assert!(matches!(
        witness.admit_context(&first, request.clone()),
        Err(CheckpointError::Refused("call_id"))
    ));
    let valid = candidate(&witness, &first, &request, &current)?;
    assert_candidate_mutations(&mut witness, &first, &valid)?;
    witness.enqueue_candidate(&first, valid.clone())?;
    assert!(matches!(
        witness.enqueue_candidate(&first, valid),
        Err(CheckpointError::Refused("candidate_duplicate"))
    ));
    assert!(
        !witness.publish_step(&first, &request.call_id, |_| Err(
            std::io::ErrorKind::WouldBlock.into()
        ))?
    );
    let mut bytes = Vec::new();
    assert!(!witness.publish_step(&first, &request.call_id, |part| {
        bytes.extend_from_slice(&part[..1]);
        Ok(1)
    })?);
    fixture.clock.advance(10_000);
    let mut wrote = false;
    assert!(matches!(
        witness.publish_step(&first, &request.call_id, |part| {
            wrote = true;
            Ok(part.len())
        }),
        Err(CheckpointError::Refused("lease"))
    ));
    assert!(!wrote);
    assert_eq!(bytes.len(), 1);
    let second = witness.acquire(&id(2))?;
    primary.reconcile(&mut witness, &second)?;
    let request = resolve_context(&root_id, 51);
    witness.admit_context(&second, request.clone())?;
    let valid = candidate(&witness, &second, &request, &current)?;
    witness.enqueue_candidate(&second, valid)?;
    assert!(witness.publish_step(&second, &request.call_id, |part| Ok(part.len()))?);
    assert!(matches!(
        witness.publish_step(&second, &request.call_id, |part| Ok(part.len())),
        Err(CheckpointError::Refused("context"))
    ));
    let request = resolve_context(&root_id, 52);
    witness.admit_context(&second, request.clone())?;
    let valid = candidate(&witness, &second, &request, &current)?;
    witness.enqueue_candidate(&second, valid)?;
    drop(witness);
    let mut witness = fixture.reopen()?;
    assert!(matches!(
        witness.publish_step(&second, &request.call_id, |part| Ok(part.len())),
        Err(CheckpointError::Refused("lease"))
    ));
    let third = witness.acquire(&id(3))?;
    primary.reconcile(&mut witness, &third)?;
    assert!(matches!(
        witness.publish_step(&third, &request.call_id, |part| Ok(part.len())),
        Err(CheckpointError::Refused("context"))
    ));
    Ok(())
}

#[test]
fn username_checkpoint_context_caps_and_metadata_negatives() -> TestResult {
    let fixture = Fixture::new()?;
    let mut witness = fixture.witness()?;
    let lease = witness.acquire(&id(1))?;
    let primary = CheckpointPrimary::create(&fixture.path("primary"), &witness.head())?;
    primary.reconcile(&mut witness, &lease)?;
    let current = publish_revision_named(
        &mut witness,
        &primary,
        &lease,
        None,
        RevisionSettings { epoch: 1, delete: false, named: true },
    )?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let root_id = ramflux_crypto::identity_root_commitment(&signer.verifying_key());
    assert_bad_heads(&witness.head());
    for n in 0..64_u8 {
        let mut request = resolve_context(&root_id, n + 100);
        request.caller_root = id(n / 4 + 100);
        request.home = format!("home{}.example", n / 16);
        witness.admit_context(&lease, request)?;
    }
    let mut request = resolve_context(&root_id, 200);
    request.home = "fresh.example".into();
    request.caller_root = id(240);
    assert!(matches!(
        witness.admit_context(&lease, request),
        Err(CheckpointError::Refused("context_global"))
    ));
    for n in 0..64_u8 {
        witness.close_context(&id(n + 100));
    }
    for n in 0..4 {
        witness.admit_context(&lease, resolve_context(&root_id, n + 100))?;
    }
    assert!(matches!(
        witness.admit_context(&lease, resolve_context(&root_id, 200)),
        Err(CheckpointError::Refused("context_root"))
    ));
    for n in 0..4 {
        witness.close_context(&id(n + 100));
    }
    for n in 0..16 {
        let mut request = resolve_context(&root_id, n + 100);
        request.caller_root = id(n + 100);
        witness.admit_context(&lease, request)?;
    }
    let mut request = resolve_context(&root_id, 200);
    request.caller_root = id(240);
    assert!(matches!(
        witness.admit_context(&lease, request),
        Err(CheckpointError::Refused("context_home"))
    ));
    for n in 0..16 {
        witness.close_context(&id(n + 100));
    }
    let request = resolve_context(&root_id, 200);
    witness.admit_context(&lease, request.clone())?;
    let original = request.clone();
    for field in 0..6 {
        let mut wrong = original.clone();
        match field {
            0 => wrong.session = id(99),
            1 => wrong.caller_root = id(99),
            2 => wrong.root = id(99),
            3 => wrong.home = "other.example".into(),
            4 => wrong.kind = ContextKind::Resolve { name: "alice3".into(), nonce: id(46) },
            _ => wrong.kind = ContextKind::Resolve { name: "alice2".into(), nonce: id(99) },
        }
        assert!(matches!(
            witness.admit_context(&lease, wrong),
            Err(CheckpointError::Refused("call_id"))
        ));
    }
    let mut bad = serde_json::to_value(candidate(&witness, &lease, &request, &current)?)?;
    bad["response"]["signature"] =
        serde_json::json!(ramflux_protocol::encode_base64url([0_u8; 64]));
    assert!(matches!(
        witness.enqueue_candidate(&lease, serde_json::from_value(bad)?),
        Err(CheckpointError::Crypto(ramflux_crypto::username_directory::Error::Crypto(
            ramflux_crypto::CryptoError::VerifyFailed
        )))
    ));
    witness.close_context(&request.call_id);
    Ok(())
}

fn assert_bad_heads(valid: &CheckpointHead) {
    for field in 0..7 {
        let mut head = valid.clone();
        let expected = match field {
            0 => {
                head.center_id = String::new();
                "node"
            }
            1 => {
                head.generation = 0;
                "generation"
            }
            2 => {
                head.lsn = u64::MAX;
                "lsn"
            }
            3 => {
                head.digest = "bad".into();
                "id"
            }
            4 => {
                head.clock_floor = u64::MAX;
                "clock"
            }
            5 => {
                head.codec_version = 0;
                "schema"
            }
            _ => {
                head.policy = "unknown".into();
                "schema"
            }
        };
        let result = head.validate();
        assert!(
            matches!(result,Err(CheckpointError::Refused(rule)) if rule==expected)
                || matches!(result,Err(CheckpointError::Codec(wire::CodecError::Field(rule))) if rule==expected),
            "head {field}: {result:?}"
        );
    }
}

fn revision_binding(
    signer: &ed25519_dalek::SigningKey,
    root_id: &str,
    settings: RevisionSettings,
) -> Result<Option<wire::UsernameBinding>> {
    if !settings.named || settings.delete {
        return Ok(None);
    }
    Ok(Some(ramflux_crypto::username_directory::sign_binding(
        signer,
        wire::UsernameBindingBody {
            name: "alice2".into(),
            node: "home.example".into(),
            principal_commitment: root_id.into(),
            epoch: settings.epoch,
        },
    )?))
}

fn assert_candidate_mutations(
    witness: &mut CheckpointWitness,
    lease: &WriterLease,
    valid: &wire::ServeCandidate,
) -> TestResult {
    let original = serde_json::to_value(valid)?;
    let mutations = [
        ("/generation", serde_json::json!(2), "candidate_generation"),
        ("/witness_boot", serde_json::json!(id(99)), "candidate_boot"),
        ("/writer_incarnation", serde_json::json!(id(99)), "candidate_writer"),
        ("/primary_lsn", serde_json::json!(3), "candidate_head"),
        ("/primary_digest", serde_json::json!(id(99)), "candidate_head"),
        ("/call_id", serde_json::json!(id(99)), "context"),
        ("/response/body/name", serde_json::json!("alice3"), "request_correlation"),
        ("/response/body/request_nonce", serde_json::json!(id(99)), "request_correlation"),
        ("/response/body/center_id", serde_json::json!("other.example"), "response_owner"),
        ("/response/body/principal_commitment", serde_json::json!(id(99)), "response_owner"),
        ("/response/body/node", serde_json::json!("other.example"), "response_owner"),
        ("/response/body/epoch", serde_json::json!(2), "response_tuple"),
        ("/response/body/binding_hash", serde_json::json!(id(99)), "response_tuple"),
        ("/response/body/profile/hash", serde_json::json!(id(99)), "response_tuple"),
        ("/response/body/issued_at", serde_json::json!(WALL + 1), "response_time"),
    ];
    for (path, value, expected) in mutations {
        let mut bad = original.clone();
        *bad.pointer_mut(path).ok_or("missing candidate field")? = value;
        let result = witness.enqueue_candidate(lease, serde_json::from_value(bad)?);
        assert!(
            matches!(result,Err(CheckpointError::Refused(rule)) if rule==expected),
            "{path}: {result:?}"
        );
    }

    Ok(())
}
