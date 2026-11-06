// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::storage::*;
use super::tests::{authority, path, proof};
use super::*;
use crate::{
    RelayRedbStore,
    relay::attachment::{AttachmentPolicy, grants::fixture::RetirementFixture},
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
fn insert_rows(tx: &redb::WriteTransaction, count: u64, expires: u64) {
    let mut rows = tx.open_table(NONCES).unwrap();
    for n in 0..count {
        let mut key = [9; 96];
        key[..8].copy_from_slice(&n.to_be_bytes());
        rows.insert(key.as_slice(), expires).unwrap();
    }
}
fn startup_clock(registry: &ScopedGrantRegistry) -> u64 {
    registry
        .ledger
        .db
        .begin_read()
        .unwrap()
        .open_table(META)
        .unwrap()
        .get("clock")
        .unwrap()
        .unwrap()
        .value()
}
#[test]
fn replay_rebuild_keeps_store_open_over_budget_and_prunes_expired_first() {
    let path = path("rebuild-budget");
    let now = crate::now_unix_seconds();
    let f = RetirementFixture::new_at(&path, now);
    let grant = f.grant.clone();
    drop(f);
    // A previous version's above-limit ledger must be pruned before rebuilding.
    let db = redb::Database::open(&path).unwrap();
    let tx = db.begin_write().unwrap();
    insert_rows(&tx, 16385, now - 5);
    assert_eq!(tx.open_table(NONCES).unwrap().len().unwrap(), 16385);
    tx.commit().unwrap();
    drop(db);
    let store = RelayRedbStore::open(&path).unwrap();
    let registry = store
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap()
        .scoped_grants(authority())
        .unwrap();
    let now = startup_clock(&registry);
    assert_eq!(
        registry.ledger.db.begin_read().unwrap().open_table(NONCES).unwrap().len().unwrap(),
        0
    );
    assert!(
        matches!(
            registry.admit_operation_after_authentication(&grant, 1, &proof(now - 6, 4), now - 6),
            Err(AttachmentReplayError::ClockUncertain)
        ),
        "startup expiry must atomically retain its clock fence"
    );
    drop(registry.admit_operation_after_authentication(&grant, 1, &proof(now, 1), now).unwrap());
    // Three live rows isolate each guard without repeating full-capacity scans.
    // The owned replay regression separately fills both real default capacities.
    let tx = registry.ledger.db.begin_write().unwrap();
    insert_rows(&tx, 2, now + 3600);
    rebuild(&tx, now, Limits::default()).unwrap();
    tx.commit().unwrap();
    let small_bytes = ROOT_CHARGE + 4 * ROW_CHARGE;
    let tx = registry.ledger.db.begin_write().unwrap();
    consume(
        &tx,
        "node-a",
        &grant.grant().grantee,
        &proof(now, 2),
        now,
        Limits { bytes: small_bytes, ..Limits::default() },
    )
    .unwrap();
    tx.abort().unwrap();
    for limits in [
        Limits { entries: 1, ..Limits::default() },
        Limits { bytes: ROOT_CHARGE, ..Limits::default() },
        Limits { charge: 1024, bytes: small_bytes, ..Limits::default() },
        Limits { charge: u64::MAX, ..Limits::default() },
    ] {
        let tx = registry.ledger.db.begin_write().unwrap();
        rebuild(&tx, now, limits).unwrap();
        assert!(matches!(
            consume(&tx, "node-a", &grant.grant().grantee, &proof(now, 2), now, limits),
            Err(AttachmentReplayError::ReplayProtectionCapacity)
        ));
        assert_eq!(tx.open_table(NONCES).unwrap().len().unwrap(), 3);
        tx.commit().unwrap();
    }
    drop(registry);
    drop(store);
    let store = RelayRedbStore::open(&path).unwrap();
    let registry = store
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap()
        .scoped_grants(authority())
        .unwrap();
    let now = startup_clock(&registry);
    drop(registry.admit_operation_after_authentication(&grant, 1, &proof(now, 3), now).unwrap());
    drop(registry);
    drop(store);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn replay_rebuild_preserves_malformed_evidence_and_refuses_new_admissions() {
    for (name, key, end) in [
        ("length", vec![7; 95], crate::now_unix_seconds() + 3600),
        ("overflow", vec![7; 96], u64::MAX),
    ] {
        let path = path(name);
        let mut now = crate::now_unix_seconds();
        let f = RetirementFixture::new_at(&path, now);
        let grant = f.grant.clone();
        drop(f);
        let db = redb::Database::open(&path).unwrap();
        let tx = db.begin_write().unwrap();
        tx.open_table(NONCES).unwrap().insert(key.as_slice(), end).unwrap();
        tx.commit().unwrap();
        drop(db);
        let store = RelayRedbStore::open(&path).unwrap();
        let registry = store
            .attachment_ledger(AttachmentPolicy::default())
            .unwrap()
            .scoped_grants(authority())
            .unwrap();
        now = startup_clock(&registry);
        assert!(matches!(
            registry.admit_operation_after_authentication(&grant, 1, &proof(now, 1), now),
            Err(AttachmentReplayError::ReplayProtectionCapacity)
        ));
        let tx = registry.ledger.db.begin_read().unwrap();
        assert_eq!(
            tx.open_table(NONCES).unwrap().get(key.as_slice()).unwrap().unwrap().value(),
            end
        );
        drop(tx);
        drop(registry);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
