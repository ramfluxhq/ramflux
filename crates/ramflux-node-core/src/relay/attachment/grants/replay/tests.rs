// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::storage::*;
use super::*;
use crate::RelayRedbStore;
use crate::relay::attachment::grants::fixture::RetirementFixture;
use crate::relay::attachment::grants::test_support::{auth, signed};
use crate::relay::attachment::{AttachmentAuthority, AttachmentPolicy};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::sync::{Arc, Barrier};
fn path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rf-replay-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}
fn proof(now: u64, n: u8) -> AttachmentReplayProof {
    AttachmentReplayProof { nonce: [n; 32], issued_at: now, expires_at: now + 30 }
}
fn authority() -> AttachmentAuthority {
    AttachmentAuthority {
        source: "node-a".into(),
        generation: 4,
        signing_public_key: ed25519_dalek::SigningKey::from_bytes(&[77; 32])
            .verifying_key()
            .to_bytes(),
    }
}
#[test]
fn large_pop_nonce_is_consumed_once_across_verifiers_and_restart() {
    let path = path("once");
    let f = RetirementFixture::new(&path);
    let now = f.now;
    let p = proof(now, 1);
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let registry = f
            .store
            .attachment_ledger(AttachmentPolicy::default())
            .unwrap()
            .scoped_grants(authority())
            .unwrap();
        let grant = f.grant.clone();
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            registry.admit_operation_after_authentication(&grant, 1, &p, now).map(drop)
        }));
    }
    barrier.wait();
    let results = tasks.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|r| matches!(r, Err(AttachmentReplayError::Replay))).count(),
        1
    );
    let grant = f.grant.clone();
    drop(f);
    // Independent durable-row oracle, and a deliberately stale derived budget/index.
    let db = redb::Database::open(&path).unwrap();
    let tx = db.begin_write().unwrap();
    assert_eq!(tx.open_table(NONCES).unwrap().len().unwrap(), 1);
    tx.open_table(META).unwrap().insert("bytes", 0).unwrap();
    tx.open_table(META).unwrap().insert("rows", 999).unwrap();
    tx.delete_table(EXPIRY).unwrap();
    tx.delete_table(PRINCIPALS).unwrap();
    tx.commit().unwrap();
    drop(db);
    let store = RelayRedbStore::open(&path).unwrap();
    let registry = store
        .attachment_ledger(AttachmentPolicy::default())
        .unwrap()
        .scoped_grants(authority())
        .unwrap();
    assert!(matches!(
        registry.admit_operation_after_authentication(&grant, 1, &p, now),
        Err(AttachmentReplayError::Replay)
    ));
    let tx = registry.ledger.db.begin_read().unwrap();
    assert_eq!(tx.open_table(META).unwrap().get("rows").unwrap().unwrap().value(), 1);
    assert_eq!(
        tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value(),
        ROOT_CHARGE + ROW_CHARGE
    );
    assert_eq!(tx.open_table(EXPIRY).unwrap().len().unwrap(), 1);
    assert_eq!(tx.open_table(PRINCIPALS).unwrap().len().unwrap(), 1);
    drop(tx);
    assert_eq!(registry.gc_consumed_proofs(now + 34, 64).unwrap(), 0);
    assert_eq!(registry.gc_consumed_proofs(now + 35, 64).unwrap(), 1);
    assert!(
        matches!(
            registry.admit_operation_after_authentication(&grant, 1, &p, now + 31),
            Err(AttachmentReplayError::Expired)
        ),
        "within-tolerance rollback must use durable effective time"
    );
    assert!(matches!(
        registry.admit_operation_after_authentication(&grant, 1, &proof(now + 20, 2), now + 20),
        Err(AttachmentReplayError::ClockUncertain)
    ));
    drop(registry);
    drop(store);
    std::fs::remove_file(path).unwrap();
    assert_replay_budgets_and_indexed_gc_keep_unrelated_principals_live();
}
#[test]
fn replay_proof_fields_and_cross_field_rules_refuse_without_consumption() {
    let path = path("fields");
    let f = RetirementFixture::new(&path);
    let now = f.now;
    let good = proof(now, 1);
    for bad in [
        AttachmentReplayProof { issued_at: now + 6, ..good },
        AttachmentReplayProof { expires_at: now, ..good },
        AttachmentReplayProof { expires_at: now - 1, ..good },
        AttachmentReplayProof { expires_at: now + 31, ..good },
        AttachmentReplayProof { issued_at: u64::MAX - 10, expires_at: u64::MAX, ..good },
    ] {
        assert!(matches!(
            f.registry.admit_operation_after_authentication(&f.grant, 1, &bad, now),
            Err(AttachmentReplayError::Invalid)
        ));
    }
    assert!(matches!(
        f.registry.admit_operation_after_authentication(
            &f.grant,
            1,
            &AttachmentReplayProof { issued_at: now - 35, expires_at: now - 5, ..good },
            now
        ),
        Err(AttachmentReplayError::Expired)
    ));
    for right in [0, 3, 32, u32::MAX] {
        assert!(matches!(
            f.registry.admit_operation_after_authentication(&f.grant, right, &good, now),
            Err(AttachmentReplayError::Ledger(AttachmentLedgerError::Conflict))
        ));
    }
    for limit in [0, 65] {
        assert!(matches!(
            f.registry.gc_consumed_proofs(now, limit),
            Err(AttachmentReplayError::Invalid)
        ));
    }
    assert_eq!(
        f.registry.ledger.db.begin_read().unwrap().open_table(NONCES).unwrap().len().unwrap(),
        0
    );
    let aborted: Result<super::super::GrantPublicationLease, AttachmentReplayError> =
        f.registry.lease_with_admission(&f.grant, 1, now, |tx| {
            consume(tx, "node-a", &f.grant.grant().grantee, &good, now, Limits::default())?;
            Err(AttachmentReplayError::Invalid)
        });
    assert!(matches!(aborted, Err(AttachmentReplayError::Invalid)));
    assert_eq!(
        f.registry.ledger.db.begin_read().unwrap().open_table(NONCES).unwrap().len().unwrap(),
        0
    );
    // A failed admission must not burn the otherwise valid nonce.
    drop(f.registry.admit_operation_after_authentication(&f.grant, 1, &good, now).unwrap());
    assert!(
        matches!(
            f.registry.admit_operation_after_authentication(&f.grant, 2, &good, now),
            Err(AttachmentReplayError::Replay)
        ),
        "another method cannot reopen a nonce namespace"
    );
    for changed in [
        AttachmentReplayProof { issued_at: now + 1, ..good },
        AttachmentReplayProof { expires_at: now + 29, ..good },
    ] {
        assert!(
            matches!(
                f.registry.admit_operation_after_authentication(&f.grant, 1, &changed, now + 1),
                Err(AttachmentReplayError::Replay)
            ),
            "changing one signed timestamp cannot reopen a consumed nonce"
        );
    }
    let g = f.grant.grant().grantee.clone();
    let digest = principal("node-a", &g);
    let mut routing = g.clone();
    routing.home_node_id = "new-home".into();
    assert_eq!(digest, principal("node-a", &routing));
    for field in 0..4 {
        let mut changed = g.clone();
        match field {
            0 => changed.account_anchor.push('x'),
            1 => changed.device_id.push('x'),
            2 => changed.device_epoch += 1,
            _ => changed.signing_public_key[0] ^= 1,
        }
        assert_ne!(digest, principal("node-a", &changed));
    }
    assert_ne!(digest, principal("other-source", &g));
    // Grant/token rotation and home routing cannot create a new nonce namespace.
    let mut rotated = f.grant.grant().clone();
    rotated.grant_id = [180; 32];
    rotated.rights = 1;
    rotated.grantee.home_node_id = "new-home".into();
    let rotated = signed(&rotated);
    f.registry
        .register(
            &[21; 32],
            &f.native,
            &rotated,
            &auth(&f.native, &rotated, now).context(),
            &ed25519_dalek::SigningKey::from_bytes(&[77; 32]),
        )
        .unwrap();
    assert!(matches!(
        f.registry.admit_operation_after_authentication(&rotated, 2, &good, now),
        Err(AttachmentReplayError::Ledger(AttachmentLedgerError::Conflict))
    ));
    assert!(matches!(
        f.registry.admit_operation_after_authentication(&rotated, 1, &good, now),
        Err(AttachmentReplayError::Replay)
    ));
    for field in 0..4 {
        let mut bad = f.grant.grant().clone();
        match field {
            0 => bad.grantee.account_anchor.push('x'),
            1 => bad.grantee.device_id.push('x'),
            2 => bad.grantee.device_epoch += 1,
            _ => bad.grantee.signing_public_key[0] ^= 1,
        }
        let bad = signed(&bad);
        assert!(matches!(
            f.registry.admit_operation_after_authentication(&bad, 1, &proof(now, 2), now),
            Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
        ));
    }
    // Retired grant state is checked before nonce admission; no backend lease escapes.
    f.retire(&f.request()).unwrap();
    let p = proof(now, 2);
    assert!(matches!(
        f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now),
        Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
    ));
    assert_eq!(
        f.registry.ledger.db.begin_read().unwrap().open_table(NONCES).unwrap().len().unwrap(),
        1
    );
    drop(f);
    std::fs::remove_file(path).unwrap();
}
fn assert_replay_budgets_and_indexed_gc_keep_unrelated_principals_live() {
    let path = path("capacity");
    let f = RetirementFixture::new(&path);
    let now = f.now;
    let requester = f.grant.grant().grantee.clone();
    let tx = f.registry.ledger.db.begin_write().unwrap();
    // Real unrelated nonce, expiry and principal rows, not an unrelated-table distraction.
    for n in 0..256u64 {
        let mut other = requester.clone();
        other.account_anchor = format!("other-{n}");
        let p = proof(now, 0);
        consume(&tx, "node-a", &other, &p, now, Limits::default()).unwrap();
    }
    for n in 0..1024u64 {
        let mut p = proof(now, 0);
        p.nonce[..8].copy_from_slice(&n.to_be_bytes());
        consume(&tx, "node-a", &requester, &p, now, Limits::default()).unwrap();
    }
    tx.commit().unwrap();
    let p = proof(now, 255);
    let tx = f.registry.ledger.db.begin_write().unwrap();
    let before = tx.open_table(NONCES).unwrap().len().unwrap();
    let bytes = tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value();
    let mut healthy = requester.clone();
    healthy.account_anchor = "healthy".into();
    for limits in
        [Limits { entries: before, ..Limits::default() }, Limits { bytes, ..Limits::default() }]
    {
        assert!(matches!(
            consume(&tx, "node-a", &healthy, &p, now, limits),
            Err(AttachmentReplayError::ReplayProtectionCapacity)
        ));
    }
    assert!(matches!(
        consume(&tx, "node-a", &requester, &p, now, Limits::default()),
        Err(AttachmentReplayError::ReplayProtectionCapacity)
    ));
    assert_eq!(tx.open_table(NONCES).unwrap().len().unwrap(), before);
    consume(&tx, "node-a", &healthy, &p, now, Limits::default()).unwrap();
    // Independent redb allocated live-page accounting stays below the charged reservation.
    let mut actual = 0;
    for stats in [
        tx.open_table(NONCES).unwrap().stats().unwrap(),
        tx.open_table(EXPIRY).unwrap().stats().unwrap(),
        tx.open_table(PRINCIPALS).unwrap().stats().unwrap(),
        tx.open_table(META).unwrap().stats().unwrap(),
    ] {
        actual += stats.stored_bytes() + stats.metadata_bytes() + stats.fragmented_bytes();
    }
    let charged = tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value();
    assert!(actual <= charged, "actual={actual},charged={charged}");
    tx.commit().unwrap();
    assert_eq!(f.registry.gc_consumed_proofs(now + 35, 64).unwrap(), 64);
    assert_eq!(
        f.registry.ledger.db.begin_read().unwrap().open_table(NONCES).unwrap().len().unwrap(),
        before + 1 - 64
    );
    drop(f);
    std::fs::remove_file(path).unwrap();
}
