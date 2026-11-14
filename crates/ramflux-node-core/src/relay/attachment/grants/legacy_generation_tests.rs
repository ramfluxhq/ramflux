// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! A payload without a bound generation (no authoritative generation) is refused by every admission
//! and authority reader of the payload row, before any grant, nonce or lease exists.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::fixture::RetirementFixture;
use super::test_support::*;
use super::*;
use crate::RelayRedbStore;
use crate::relay::test_support::V3_AUDIENCE_NODE;
use redb::ReadableTableMetadata;
use std::fs;

fn dir(name: &str) -> ramflux_test_support::TestPath {
    let dir = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-legacy-gen-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn proof(now: u64, n: u8) -> AttachmentReplayProof {
    AttachmentReplayProof { nonce: [n; 32], issued_at: now, expires_at: now + 30 }
}

/// One field at a time from the valid state (1, Some(1)): each operand of
/// `require_bound_generation` has its own row.
const CASES: [(u64, Option<u64>); 4] = [(0, Some(0)), (1, None), (1, Some(2)), (0, None)];

#[test]
fn registration_and_committed_refuse_each_unbound_generation_shape() {
    let mut bad = Vec::new();
    for (pending, committed) in CASES {
        let now = 1_700_000_001;
        let (native, grant) = fixtures();
        let dir = dir("register");
        let store = RelayRedbStore::open(dir.join("db")).unwrap();
        let ledger = store.attachment_ledger(super::super::AttachmentPolicy::default()).unwrap();
        let owner =
            AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
                .unwrap();
        let upload = [21; 32];
        ledger
            .reserve(
                &owner,
                super::super::AttachmentReservationRequest {
                    upload_id: upload,
                    object_id: native.manifest().object_id,
                    layout: native.manifest().layout,
                },
                now - 1,
            )
            .unwrap();
        ledger.bind(&owner, &upload, &native, now - 1).unwrap();
        ledger.commit(&owner, &upload, 1, now - 1).unwrap();
        let tx = ledger.db.begin_write().unwrap();
        {
            let mut rows = tx.open_table(RECORDS).unwrap();
            let k = key(&owner, &upload);
            let mut row: serde_json::Value = {
                let v = rows.get(k.as_slice()).unwrap().unwrap();
                serde_json::from_slice(v.value()).unwrap()
            };
            row["pending_generation"] = pending.into();
            row["committed_generation"] = committed.map_or(serde_json::Value::Null, Into::into);
            rows.insert(k.as_slice(), serde_json::to_vec(&row).unwrap().as_slice()).unwrap();
        }
        tx.commit().unwrap();
        let case = format!("({pending}, {committed:?})");
        if !matches!(ledger.committed(&owner, &upload, now), Err(AttachmentLedgerError::State)) {
            bad.push(format!("committed {case}"));
        }
        let signer = SigningKey::from_bytes(&[77; 32]);
        let registry = ledger
            .scoped_grants(AttachmentAuthority {
                source: V3_AUDIENCE_NODE.into(),
                generation: 4,
                signing_public_key: signer.verifying_key().to_bytes(),
            })
            .unwrap();
        let proof = auth(&native, &grant, now);
        if !matches!(
            registry.register(&upload, &native, &grant, &proof.context(), &signer),
            Err(AttachmentLedgerError::State)
        ) {
            bad.push(format!("register {case}"));
        }
        let tx = ledger.db.begin_read().unwrap();
        if tx.open_table(GRANTS).unwrap().len().unwrap() != 0 {
            bad.push(format!("grants row {case}"));
        }
    }
    assert!(bad.is_empty(), "unbound shapes admitted: {bad:?}");
}

#[test]
fn current_and_nonce_admission_refuse_each_unbound_generation_shape_without_consuming() {
    let mut bad = Vec::new();
    for (pending, committed) in CASES {
        let dir = dir("admit");
        let f = RetirementFixture::new(&dir.join("db"));
        let (now, p) = (f.now, proof(f.now, 7));
        let case = format!("({pending}, {committed:?})");
        let before = bad.len();
        f.set_generations(pending, committed);
        if !matches!(f.registry.current(&f.grant, now), Err(AttachmentLedgerError::State)) {
            bad.push(format!("current {case}"));
        }
        if !matches!(
            f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now),
            Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
        ) {
            bad.push(format!("public admission {case}"));
        }
        // The nonce-consuming transaction on its own, bypassing the current-grant read.
        let tx = f.registry.ledger.db.begin_write().unwrap();
        if !matches!(
            f.registry.admit_in(&tx, &f.grant, &p, now),
            Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
        ) {
            bad.push(format!("admit_in {case}"));
        }
        drop(tx);
        if bad.len() > before {
            continue;
        }
        // Back to the valid (1, Some(1)): the same proof was never consumed.
        f.set_generations(1, Some(1));
        drop(f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now).unwrap());
        assert!(matches!(
            f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now),
            Err(AttachmentReplayError::Replay)
        ));
    }
    assert!(bad.is_empty(), "unbound shapes admitted: {bad:?}");
}
