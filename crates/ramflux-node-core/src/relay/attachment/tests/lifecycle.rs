// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! ATTACH-LARGE-01 §4 integration: a real ledger and `LocalAttachmentBackend` share one
//! redb file. Terminal object ids are never reused and the terminal budget stays charged.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::super::backend::{AttachmentBackend, BackendError, BackendSegment};
use super::super::terminal::TERMINAL;
use super::super::*;
use super::root;
use crate::RelayRedbStore;
use ramflux_protocol::large_attachment::{ContentManifest, VerifiedContentManifest};
use redb::ReadableTableMetadata;
use std::{fs, io::Cursor, path::PathBuf};

const OWNER: &str = "owner-anchor";
const NAMESPACE: [u8; 32] = [3; 32];

struct Case {
    native: VerifiedContentManifest,
    ciphertext: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

/// Frozen r4 vector cases 0 and 1: single-segment payloads with distinct object ids.
fn case(index: usize) -> Case {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let c = &vectors["cases"][index];
    let mc = hex(c["content_manifest_unsigned_hex"].as_str().unwrap());
    let mut signed = u32::try_from(mc.len()).unwrap().to_be_bytes().to_vec();
    signed.extend(mc);
    signed.extend_from_slice(&64_u32.to_be_bytes());
    signed.extend(hex(c["content_signature_hex"].as_str().unwrap()));
    Case {
        native: ContentManifest::decode_signed(&signed).unwrap(),
        ciphertext: hex(c["segments"][0]["ciphertext_hex"].as_str().unwrap()),
    }
}

struct Rig {
    // Field order drops the ledger and backend before the store.
    ledger: AttachmentLedger,
    backend: backend::LocalAttachmentBackend,
    _store: RelayRedbStore,
}

/// A unique directory per test, so parallel tests never share a database.
fn unique() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    root().join(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_string())
}

fn files(dir: &std::path::Path) -> PathBuf {
    dir.join("files")
}

fn open(dir: &std::path::Path, policy: AttachmentPolicy) -> Result<Rig, AttachmentLedgerError> {
    let store = RelayRedbStore::open(dir.join("relay.redb")).unwrap();
    let backend = store.local_attachment_backend(NAMESPACE, files(dir)).unwrap();
    let ledger = store.attachment_ledger(policy)?;
    Ok(Rig { ledger, backend, _store: store })
}

fn owner() -> AttachmentOwner {
    AttachmentOwner::from_authenticated_session(OWNER).unwrap()
}

fn other(n: u64) -> AttachmentOwner {
    AttachmentOwner::from_authenticated_session(&format!("other-{n}")).unwrap()
}

fn request(case: &Case, upload: u8) -> AttachmentReservationRequest {
    AttachmentReservationRequest {
        upload_id: [upload; 32],
        object_id: case.native.manifest().object_id,
        layout: case.native.manifest().layout,
    }
}

/// Ledger-only rows for a second owner, so counters and sums are not trivially one owner's.
fn bystander(rig: &Rig, n: u64) {
    let mut id = [0xB0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let request = AttachmentReservationRequest {
        upload_id: id,
        object_id: id,
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    };
    rig.ledger.reserve(&other(n), request, 100).unwrap();
}

/// reserve -> bind -> backend write/prepare/publish -> commit, using only the row's generation.
fn stage(rig: &Rig, case: &Case, upload: u8, now: u64) -> BackendSegment {
    let o = owner();
    let row = rig.ledger.reserve(&o, request(case, upload), now).unwrap();
    assert_eq!(row.pending_generation, 1);
    let spec = BackendSegment::from_manifest(&case.native, row.pending_generation, 0).unwrap();
    rig.ledger.bind(&o, &[upload; 32], &case.native, now).unwrap();
    rig.backend.write_chunk(&spec, 0, &mut Cursor::new(&case.ciphertext)).unwrap();
    let receipt = rig.backend.publish(rig.backend.prepare(&spec).unwrap()).unwrap();
    let committed =
        rig.ledger.commit(&o, &[upload; 32], receipt.segment().generation(), now).unwrap();
    assert_eq!(committed.committed_generation, Some(1));
    assert_eq!(rig.ledger.committed(&o, &[upload; 32], now).unwrap().pending_generation, 1);
    spec
}

/// Expiry, debt, backend tombstone and ledger compaction: the terminal transition.
fn retire(rig: &Rig, spec: &BackendSegment, upload: u8, expires_at: u64) {
    let jobs = rig.ledger.gc_due(expires_at, 64).unwrap();
    assert!(jobs.iter().any(|j| j.upload_id == [upload; 32]));
    rig.ledger
        .reclaim(&owner(), &[upload; 32], |_| {
            rig.backend
                .delete_with(spec, |_| Ok(()))
                .map_err(|e| AttachmentLedgerError::Store(e.to_string()))
        })
        .unwrap();
}

fn prune_everything(rig: &Rig) {
    // Far beyond every identity-fence horizon; each turn prunes at most 64 fences.
    while rig.ledger.gc_due(u64::MAX / 2, 64).unwrap().len() == 64 {}
    for _ in 0..4 {
        rig.ledger.gc_due(u64::MAX / 2, 64).unwrap();
    }
}

/// `(RECORDS, OBJECTS, TOTALS, terminal rows, terminal_owners, terminal_slots_global)`.
fn shape(rig: &Rig) -> (u64, u64, u64, u64, u64, u64) {
    let tx = rig.ledger.db.begin_read().unwrap();
    let config = tx.open_table(super::super::grants::CONFIG).unwrap();
    let get = |name: &str| -> u64 {
        serde_json::from_slice(config.get(name).unwrap().unwrap().value()).unwrap()
    };
    (
        tx.open_table(RECORDS).unwrap().len().unwrap(),
        tx.open_table(OBJECTS).unwrap().len().unwrap(),
        tx.open_table(TOTALS).unwrap().len().unwrap(),
        tx.open_table(TERMINAL).unwrap().len().unwrap(),
        get("terminal_owners"),
        get("terminal_slots_global"),
    )
}

fn assert_refused_everywhere(rig: &Rig, case: &Case, spec: &BackendSegment) {
    let mut again = request(case, 0xE1);
    again.upload_id = [0xE1; 32];
    assert!(matches!(
        rig.ledger.reserve(&owner(), again, 1_000),
        Err(AttachmentLedgerError::State)
    ));
    assert!(matches!(
        rig.ledger.reserve(&other(1), again, 1_000),
        Err(AttachmentLedgerError::State)
    ));
    assert!(matches!(rig.backend.prepare(spec), Err(BackendError::Retired)));
    assert!(matches!(
        rig.backend.write_chunk(spec, 0, &mut Cursor::new(&case.ciphertext)),
        Err(BackendError::Retired)
    ));
    let mut sink = Vec::new();
    assert!(matches!(
        rig.backend.read_range(spec, 0, spec.length(), &mut sink),
        Err(BackendError::Retired)
    ));
    assert_eq!(sink, Vec::<u8>::new());
}

#[test]
fn large_terminal_object_id_never_reused_and_fresh_id_commits() {
    let dir = unique();
    fs::create_dir_all(&dir).unwrap();
    let old = case(0);
    let fresh = case(1);
    let spec_old;
    let before_retire;
    {
        let rig = open(&dir, AttachmentPolicy::default()).unwrap();
        bystander(&rig, 1);
        spec_old = stage(&rig, &old, 1, 100);
        before_retire = shape(&rig);
        assert_eq!(
            (before_retire.2, before_retire.3, before_retire.4, before_retire.5),
            (2, 0, 2, 2)
        );
        retire(&rig, &spec_old, 1, 100 + 604_800);
        // The slot stays charged through the whole cycle; only the terminal row appears.
        let after = shape(&rig);
        assert_eq!((after.0, after.1, after.2, after.3, after.4, after.5), (1, 1, 2, 1, 2, 2));
        assert_refused_everywhere(&rig, &old, &spec_old);
        // Identity prune and GC at any clock never remove the terminal row.
        prune_everything(&rig);
        assert_eq!(rig.ledger.usage(&owner()).unwrap().fences, 0);
        assert_refused_everywhere(&rig, &old, &spec_old);
        assert_eq!(shape(&rig).3, 1);
    }
    // Ledger and backend restart: the tombstone and the recount survive.
    let rig = open(&dir, AttachmentPolicy::default()).unwrap();
    assert_eq!(shape(&rig), (1, 1, 2, 1, 2, 2));
    assert_refused_everywhere(&rig, &old, &spec_old);

    // A fresh object id (a fresh encryption in practice) reserves and commits normally.
    let spec_fresh = stage(&rig, &fresh, 2, 2_000);
    assert_ne!(rig.backend.storage_key(&spec_fresh), rig.backend.storage_key(&spec_old));
    let mut out = Vec::new();
    rig.backend.read_range(&spec_fresh, 0, spec_fresh.length(), &mut out).unwrap();
    assert_eq!(out, fresh.ciphertext);

    // Generations come from the row. A client-chosen one is refused by every owner.
    assert!(matches!(
        rig.ledger.commit(&owner(), &[2; 32], 2, 2_001),
        Err(AttachmentLedgerError::Conflict)
    ));
    assert!(matches!(
        BackendSegment::from_manifest(&fresh.native, 0, 0),
        Err(BackendError::Bounds)
    ));
    let wrong_generation = BackendSegment::from_manifest(&fresh.native, 2, 0).unwrap();
    assert!(matches!(rig.backend.prepare(&wrong_generation), Err(BackendError::Conflict)));
    assert!(matches!(
        rig.backend.write_chunk(&wrong_generation, 0, &mut Cursor::new(&fresh.ciphertext)),
        Err(BackendError::Conflict)
    ));
    // Retiring the fresh id charges nothing new and leaves two permanent terminal rows.
    retire(&rig, &spec_fresh, 2, 2_000 + 604_800);
    prune_everything(&rig);
    assert_eq!(shape(&rig), (1, 1, 2, 2, 2, 3));
    assert_refused_everywhere(&rig, &fresh, &spec_fresh);
    assert_refused_everywhere(&rig, &old, &spec_old);
    drop(rig);
    // Recount holds on reopen (count == counter, sum of slots == global).
    let rig = open(&dir, AttachmentPolicy::default()).unwrap();
    assert_eq!(shape(&rig).5, 3);
}

#[test]
fn existing_owner_completes_cycle_at_owner_saturation() {
    let dir = unique();
    fs::create_dir_all(&dir).unwrap();
    let policy = AttachmentPolicy { max_terminal_owners: 2, ..Default::default() };
    let (a, b) = (case(0), case(1));
    {
        let rig = open(&dir, policy).unwrap();
        bystander(&rig, 1);
        let spec_a = stage(&rig, &a, 1, 100);
        assert_eq!(shape(&rig).2, 2);
        // A new owner is refused without any mutation.
        let saturated = shape(&rig);
        let mut id = [0xC0; 32];
        id[0] = 9;
        let newcomer = AttachmentReservationRequest {
            upload_id: id,
            object_id: id,
            layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
        };
        assert!(matches!(
            rig.ledger.reserve(&other(2), newcomer, 100),
            Err(AttachmentLedgerError::TerminalOwnerCapacity)
        ));
        assert_eq!(shape(&rig), saturated);
        // The existing owner still runs reserve -> commit -> retire -> cleanup.
        let spec_b = stage(&rig, &b, 2, 200);
        retire(&rig, &spec_a, 1, 100 + 604_800);
        retire(&rig, &spec_b, 2, 200 + 604_800);
        prune_everything(&rig);
        assert_eq!(shape(&rig), (1, 1, 2, 2, 2, 3));
    }
    let rig = open(&dir, policy).unwrap();
    assert_eq!(shape(&rig), (1, 1, 2, 2, 2, 3));
}

#[test]
fn lowered_cap_reopen_lets_existing_owners_finish_with_real_backend() {
    let dir = unique();
    fs::create_dir_all(&dir).unwrap();
    let (a, b) = (case(0), case(1));
    let spec_a;
    {
        let rig = open(&dir, AttachmentPolicy::default()).unwrap();
        bystander(&rig, 1);
        bystander(&rig, 2);
        spec_a = stage(&rig, &a, 1, 100);
    }
    // Owners lowered below the three present; per-owner lowered to 2 (the real owner holds 1).
    let lowered = AttachmentPolicy {
        max_terminal_owners: 1,
        max_terminal_objects_per_owner: 2,
        ..Default::default()
    };
    let rig = open(&dir, lowered).unwrap();
    let before = shape(&rig);
    assert_eq!((before.2, before.4), (3, 3));
    let mut id = [0xD0; 32];
    id[0] = 7;
    let newcomer = AttachmentReservationRequest {
        upload_id: id,
        object_id: id,
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    };
    assert!(matches!(
        rig.ledger.reserve(&other(9), newcomer, 150),
        Err(AttachmentLedgerError::TerminalOwnerCapacity)
    ));
    assert_eq!(shape(&rig), before);
    // The existing owner has headroom for one more object and runs the full cycle.
    let spec_b = stage(&rig, &b, 2, 200);
    assert!(matches!(
        rig.ledger.reserve(&owner(), request(&case(6), 3), 201),
        Err(AttachmentLedgerError::TerminalEvidenceCapacity)
    ));
    retire(&rig, &spec_a, 1, 100 + 604_800);
    retire(&rig, &spec_b, 2, 200 + 604_800);
    prune_everything(&rig);
    assert_eq!(rig.ledger.usage(&owner()).unwrap().terminal_slots, 2);
    drop(rig);
    drop(open(&dir, lowered).unwrap());
}

#[test]
fn corrupted_terminal_counter_or_sum_fails_closed_with_real_backend() {
    for case_index in 0..2 {
        let dir = unique();
        fs::create_dir_all(&dir).unwrap();
        {
            let rig = open(&dir, AttachmentPolicy::default()).unwrap();
            bystander(&rig, 1);
            stage(&rig, &case(0), 1, 100);
            let tx = rig.ledger.db.begin_write().unwrap();
            {
                let mut config = tx.open_table(super::super::grants::CONFIG).unwrap();
                let name = ["terminal_owners", "terminal_slots_global"][case_index];
                config.insert(name, b"7".as_slice()).unwrap();
            }
            tx.commit().unwrap();
        }
        assert!(matches!(
            open(&dir, AttachmentPolicy::default()).err(),
            Some(AttachmentLedgerError::State)
        ));
    }
}
