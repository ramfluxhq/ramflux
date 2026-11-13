// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::terminal::{TERMINAL, recount};
use super::tests::{fixture, memory_ledger, root};
use super::*;
use crate::RelayRedbStore;
use redb::ReadableTableMetadata;
use std::{fs, path::Path};

fn owner(n: u64) -> AttachmentOwner {
    AttachmentOwner::from_authenticated_session(&format!("owner-{n}")).unwrap()
}

fn req(n: u64) -> AttachmentReservationRequest {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut object = id;
    object[31] = 0xAA;
    AttachmentReservationRequest {
        upload_id: id,
        object_id: object,
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    }
}

fn with(f: impl FnOnce(&mut AttachmentPolicy)) -> AttachmentPolicy {
    let mut policy = AttachmentPolicy::default();
    f(&mut policy);
    policy
}

/// Abandons and reclaims one pending reservation, which is its terminal transition.
fn retire(ledger: &AttachmentLedger, o: &AttachmentOwner, n: u64) {
    ledger.abandon_pending(o, &req(n).upload_id).unwrap();
    ledger.reclaim(o, &req(n).upload_id, |_| Ok(())).unwrap();
}

/// `(RECORDS, OBJECTS, TOTALS, terminal rows, terminal_owners, terminal_slots_global)`.
fn shape(ledger: &AttachmentLedger) -> (u64, u64, u64, u64, u64, u64) {
    let tx = ledger.db.begin_read().unwrap();
    let config = tx.open_table(super::grants::CONFIG).unwrap();
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

fn open(
    path: &Path,
    policy: AttachmentPolicy,
) -> (RelayRedbStore, Result<AttachmentLedger, AttachmentLedgerError>) {
    let store = RelayRedbStore::open(path).unwrap();
    let ledger = store.attachment_ledger(policy);
    (store, ledger)
}

fn tamper(ledger: &AttachmentLedger, f: impl FnOnce(&redb::WriteTransaction)) {
    let tx = ledger.db.begin_write().unwrap();
    f(&tx);
    tx.commit().unwrap();
}

#[test]
fn large_payload_generation_pending_then_committed_once() {
    let temp = root();
    let dir = temp.path().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("relay.redb");
    let native = fixture();
    let anchor = native.manifest().owner.account_anchor.clone();
    let o = AttachmentOwner::from_authenticated_session(&anchor).unwrap();
    let request = AttachmentReservationRequest {
        upload_id: [9; 32],
        object_id: native.manifest().object_id,
        layout: native.manifest().layout,
    };
    {
        let (_store, ledger) = open(&path, AttachmentPolicy::default());
        let ledger = ledger.unwrap();
        let first = ledger.reserve(&o, request, 100).unwrap();
        assert_eq!((first.pending_generation, first.committed_generation), (1, None));
        // A replayed reserve returns the same value and does not charge again.
        assert_eq!(ledger.reserve(&o, request, 101).unwrap().pending_generation, 1);
        assert_eq!(ledger.usage(&o).unwrap().terminal_slots, 1);
        ledger.bind(&o, &request.upload_id, &native, 102).unwrap();
    }
    // Restart between reserve and commit keeps the pending value.
    let (_store, ledger) = open(&path, AttachmentPolicy::default());
    let ledger = ledger.unwrap();
    assert_eq!(ledger.reservation(&o, &request.upload_id).unwrap().pending_generation, 1);
    // A mismatched backend generation is a Conflict and commits nothing.
    for wrong in [0, 2, u64::MAX] {
        assert!(matches!(
            ledger.commit(&o, &request.upload_id, wrong, 103),
            Err(AttachmentLedgerError::Conflict)
        ));
    }
    let after_mismatch = ledger.reservation(&o, &request.upload_id).unwrap();
    assert_eq!(after_mismatch.state, AttachmentReservationState::Pending);
    assert_eq!(after_mismatch.committed_generation, None);
    assert!(matches!(
        ledger.committed(&o, &request.upload_id, 103),
        Err(AttachmentLedgerError::State)
    ));
    let done = ledger.commit(&o, &request.upload_id, 1, 104).unwrap();
    assert_eq!(done.committed_generation, Some(1));
    // A duplicate commit with an equal value is idempotent; a different one is a Conflict.
    assert_eq!(ledger.commit(&o, &request.upload_id, 1, 105).unwrap().expires_at, done.expires_at);
    assert!(matches!(
        ledger.commit(&o, &request.upload_id, 2, 105),
        Err(AttachmentLedgerError::Conflict)
    ));
    assert_eq!(
        ledger.committed(&o, &request.upload_id, 105).unwrap().committed_generation,
        Some(1)
    );

    // Legacy-zero rows are refused at commit and at read admission.
    let legacy = req(77);
    ledger.reserve(&owner(1), legacy, 100).unwrap();
    rewrite(&ledger, &owner(1), &legacy.upload_id, |row| row["pending_generation"] = 0.into());
    assert!(matches!(
        ledger.commit(&owner(1), &legacy.upload_id, 1, 101),
        Err(AttachmentLedgerError::State)
    ));
    assert!(matches!(
        ledger.commit(&owner(1), &legacy.upload_id, 0, 101),
        Err(AttachmentLedgerError::State)
    ));
    rewrite(&ledger, &o, &request.upload_id, |row| {
        row["pending_generation"] = 0.into();
        row["committed_generation"] = serde_json::Value::Null;
    });
    assert!(matches!(
        ledger.committed(&o, &request.upload_id, 105),
        Err(AttachmentLedgerError::State)
    ));
}

fn rewrite(
    ledger: &AttachmentLedger,
    o: &AttachmentOwner,
    id: &[u8; 32],
    f: impl FnOnce(&mut serde_json::Value),
) {
    tamper(ledger, |tx| {
        let mut rows = tx.open_table(RECORDS).unwrap();
        let k = key(o, id);
        let mut row: serde_json::Value =
            serde_json::from_slice(rows.get(k.as_slice()).unwrap().unwrap().value()).unwrap();
        f(&mut row);
        rows.insert(k.as_slice(), serde_json::to_vec(&row).unwrap().as_slice()).unwrap();
    });
}

#[test]
fn reserve_of_a_terminal_object_id_is_refused_forever() {
    let ledger = memory_ledger(AttachmentPolicy::default());
    let o = owner(1);
    ledger.reserve(&o, req(1), 100).unwrap();
    retire(&ledger, &o, 1);
    let mut again = req(1);
    again.upload_id = [0xEE; 32];
    // Any owner, any clock, even after the time-bounded identity fence is pruned.
    for (who, now) in [(owner(1), 101), (owner(2), 101), (owner(1), 10_000_000)] {
        while ledger.gc_due(now, 64).unwrap().len() == 64 {}
        assert!(matches!(ledger.reserve(&who, again, now), Err(AttachmentLedgerError::State)));
    }
    assert_eq!(ledger.usage(&o).unwrap().fences, 0);
    let row = {
        let tx = ledger.db.begin_read().unwrap();
        let table = tx.open_table(TERMINAL).unwrap();
        table.get(req(1).object_id.as_slice()).unwrap().unwrap().value().to_vec()
    };
    assert_eq!(row.len(), 40);
    assert_eq!(row[..32], *blake3::hash(b"owner-1").as_bytes());
}

#[test]
fn terminal_budget_is_charged_at_admission_and_never_refunded() {
    let ledger = memory_ledger(with(|p| {
        p.max_terminal_objects_per_owner = 2;
        p.max_terminal_objects_global = 3;
    }));
    let (a, b, c) = (owner(1), owner(2), owner(3));
    ledger.reserve(&a, req(1), 100).unwrap();
    ledger.reserve(&a, req(1), 100).unwrap(); // idempotent replay is not charged
    assert_eq!(ledger.usage(&a).unwrap().terminal_slots, 1);
    ledger.reserve(&a, req(2), 100).unwrap();
    // Owner at its budget while another owner's rows are present; the other owner reserves.
    ledger.reserve(&b, req(3), 100).unwrap();
    assert!(matches!(
        ledger.reserve(&a, req(4), 100),
        Err(AttachmentLedgerError::TerminalEvidenceCapacity)
    ));
    // Global saturation refuses every owner, new or existing.
    for who in [&a, &b, &c] {
        assert!(matches!(
            ledger.reserve(who, req(5), 100),
            Err(AttachmentLedgerError::TerminalEvidenceCapacity)
        ));
    }
    assert_eq!(shape(&ledger), (3, 3, 2, 0, 2, 3));
    // Retirement and expiry at saturation still succeed and write terminal rows.
    retire(&ledger, &a, 1);
    let native_free = shape(&ledger);
    assert_eq!((native_free.3, native_free.5), (1, 3)); // no refund
    assert!(matches!(
        ledger.reserve(&c, req(6), 100),
        Err(AttachmentLedgerError::TerminalEvidenceCapacity)
    ));
    ledger.gc_due(100 + 3600, 64).unwrap();
    for n in [2, 3] {
        let who = if n == 3 { &b } else { &a };
        ledger.reclaim(who, &req(n).upload_id, |_| Ok(())).unwrap();
    }
    assert_eq!(shape(&ledger), (0, 0, 2, 3, 2, 3));
    assert_eq!(ledger.usage(&a).unwrap().terminal_slots, 2);
}

#[test]
fn terminal_counters_survive_restart_and_prune() {
    let temp = root();
    let dir = temp.path().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("relay.redb");
    let before;
    {
        let (_store, ledger) = open(&path, AttachmentPolicy::default());
        let ledger = ledger.unwrap();
        for n in 1..=3 {
            ledger.reserve(&owner(n), req(n), 100).unwrap();
        }
        retire(&ledger, &owner(1), 1);
        ledger.gc_due(100 + 86_400 + 305, 64).unwrap();
        assert_eq!(ledger.usage(&owner(1)).unwrap().fences, 0);
        before = shape(&ledger);
        assert_eq!((before.2, before.3, before.4, before.5), (3, 1, 3, 3));
    }
    let (_store, ledger) = open(&path, AttachmentPolicy::default());
    let ledger = ledger.unwrap();
    assert_eq!(shape(&ledger), before);
    // Sum of owner slots equals the global counter after prune and restart.
    let tx = ledger.db.begin_read().unwrap();
    let sum: u64 = tx
        .open_table(TOTALS)
        .unwrap()
        .iter()
        .unwrap()
        .map(|e| {
            serde_json::from_slice::<AttachmentQuota>(e.unwrap().1.value()).unwrap().terminal_slots
        })
        .sum();
    assert_eq!(sum, before.5);
}

#[test]
fn terminal_owner_boundary_is_inclusive_and_mutation_free() {
    let ledger = memory_ledger(AttachmentPolicy::default());
    for n in 1..=65_536 {
        ledger.reserve(&owner(n), req(n), 100).unwrap();
    }
    let full = shape(&ledger);
    assert_eq!((full.2, full.4), (65_536, 65_536));
    assert!(matches!(
        ledger.reserve(&owner(65_537), req(65_537), 100),
        Err(AttachmentLedgerError::TerminalOwnerCapacity)
    ));
    assert_eq!(shape(&ledger), full);
    // An existing owner still reserves, commits, retires and cleans up at saturation.
    ledger.reserve(&owner(1), req(70_000), 100).unwrap();
    retire(&ledger, &owner(1), 70_000);
    retire(&ledger, &owner(2), 2);
    let tail = shape(&ledger);
    assert_eq!((tail.2, tail.4, tail.5), (65_536, 65_536, 65_537));
    ledger.gc_due(100 + 86_400 + 305, 64).unwrap();
    recount(&ledger.db).unwrap();
}

#[test]
fn lowered_cap_reopen_keeps_existing_owners_working() {
    let temp = root();
    let dir = temp.path().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("relay.redb");
    {
        let (_store, ledger) = open(&path, AttachmentPolicy::default());
        let ledger = ledger.unwrap();
        for n in 1..=3 {
            ledger.reserve(&owner(1), req(n), 100).unwrap(); // owner 1 holds 3 slots
        }
        ledger.reserve(&owner(2), req(10), 100).unwrap();
        ledger.reserve(&owner(3), req(11), 100).unwrap();
    }
    let lowered = with(|p| {
        p.max_terminal_owners = 2;
        p.max_terminal_objects_per_owner = 2;
    });
    let (_store, ledger) = open(&path, lowered);
    let ledger = ledger.unwrap(); // usage above the lowered settings is valid
    assert!(matches!(
        ledger.reserve(&owner(1), req(4), 100),
        Err(AttachmentLedgerError::TerminalEvidenceCapacity)
    ));
    ledger.reserve(&owner(2), req(12), 100).unwrap();
    let before = shape(&ledger);
    assert!(matches!(
        ledger.reserve(&owner(4), req(13), 100),
        Err(AttachmentLedgerError::TerminalOwnerCapacity)
    ));
    assert_eq!(shape(&ledger), before);
    // Existing owners retire, clean up and prune despite exceeding the lowered caps.
    retire(&ledger, &owner(1), 1);
    retire(&ledger, &owner(3), 11);
    ledger.gc_due(100 + 86_400 + 305, 64).unwrap();
    recount(&ledger.db).unwrap();
    assert_eq!(ledger.usage(&owner(1)).unwrap().terminal_slots, 3);
}

#[test]
fn corrupt_terminal_counters_fail_closed_on_reopen() {
    for case in 0..5 {
        let temp = root();
        let dir = temp.path().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay.redb");
        {
            let (_store, ledger) = open(&path, AttachmentPolicy::default());
            let ledger = ledger.unwrap();
            ledger.reserve(&owner(1), req(1), 100).unwrap();
            ledger.reserve(&owner(2), req(2), 100).unwrap();
            let set = |name: &str, value: u64| {
                tamper(&ledger, |tx| {
                    let mut config = tx.open_table(super::grants::CONFIG).unwrap();
                    config.insert(name, serde_json::to_vec(&value).unwrap().as_slice()).unwrap();
                });
            };
            match case {
                0 => set("terminal_owners", 3),
                1 => set("terminal_owners", 1),
                2 => set("terminal_slots_global", 3),
                3 => set("terminal_slots_global", 1),
                _ => tamper(&ledger, |tx| {
                    let mut totals = tx.open_table(TOTALS).unwrap();
                    let mut quota: AttachmentQuota =
                        serde_json::from_slice(totals.get("owner-1").unwrap().unwrap().value())
                            .unwrap();
                    quota.terminal_slots = (1 << 22) + 1;
                    totals
                        .insert("owner-1", serde_json::to_vec(&quota).unwrap().as_slice())
                        .unwrap();
                }),
            }
        }
        let (store, ledger) = open(&path, AttachmentPolicy::default());
        assert!(matches!(ledger, Err(AttachmentLedgerError::State)), "case {case}");
        drop(store);
        // Nothing is silently repaired by a second open.
        let (_store2, again) = open(&path, AttachmentPolicy::default());
        assert!(matches!(again, Err(AttachmentLedgerError::State)), "case {case} repaired");
    }
}

#[test]
fn terminal_encoding_size_oracle_and_policy_ranges() {
    let anchor = "a".repeat(256);
    let quota = AttachmentQuota {
        used: u64::MAX,
        reserved: u64::MAX,
        records: u64::MAX,
        fences: u64::MAX,
        terminal_slots: u64::MAX,
    };
    assert!(anchor.len() + encode(&quota).unwrap().len() <= 512 - 96);
    assert_eq!(encode(&quota).unwrap().len(), 160);
    let row = 32 + (blake3::hash(b"x").as_bytes().len() + 8);
    assert_eq!(row, 72);
    assert!(row <= 192 - 96);
    for name in ["terminal_slots_global", "terminal_owners"] {
        assert!(name.len() + encode(&u64::MAX).unwrap().len() <= 192 - 96);
    }
    // Hard maxima: zero and one past the maximum are refused, the maximum is accepted.
    for (set, max) in [
        (
            (|p: &mut AttachmentPolicy, v| p.max_terminal_objects_per_owner = v)
                as fn(&mut AttachmentPolicy, u64),
            1_u64 << 22,
        ),
        (|p, v| p.max_terminal_objects_global = v, 1 << 26),
        (|p, v| p.max_terminal_owners = v, 1 << 20),
    ] {
        for (value, ok) in [(0, false), (1, true), (max, true), (max + 1, false)] {
            let policy = with(|p| set(p, value));
            if ok {
                policy.validate().unwrap();
            } else {
                assert!(
                    matches!(policy.validate(), Err(AttachmentLedgerError::Invalid)),
                    "value {value}"
                );
            }
        }
    }
}
