// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! A legacy-zero payload (no authoritative generation) is refused by every admission
//! and authority reader of the payload row, before any grant, nonce or lease exists.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::fixture::RetirementFixture;
use super::test_support::*;
use super::*;
use crate::RelayRedbStore;
use crate::relay::test_support::V3_AUDIENCE_NODE;
use redb::ReadableTableMetadata;
use std::fs;

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
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

#[test]
fn registration_refuses_a_legacy_zero_payload() {
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
    {
        let tx = ledger.db.begin_write().unwrap();
        {
            let mut rows = tx.open_table(RECORDS).unwrap();
            let k = key(&owner, &upload);
            let mut row: serde_json::Value = {
                let v = rows.get(k.as_slice()).unwrap().unwrap();
                serde_json::from_slice(v.value()).unwrap()
            };
            row["pending_generation"] = 0.into();
            row["committed_generation"] = serde_json::Value::Null;
            rows.insert(k.as_slice(), serde_json::to_vec(&row).unwrap().as_slice()).unwrap();
        }
        tx.commit().unwrap();
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
    assert!(matches!(
        registry.register(&upload, &native, &grant, &proof.context(), &signer),
        Err(AttachmentLedgerError::State)
    ));
    let tx = ledger.db.begin_read().unwrap();
    assert_eq!(tx.open_table(GRANTS).unwrap().len().unwrap(), 0);
}

#[test]
fn current_and_nonce_admission_refuse_a_legacy_zero_payload_without_consuming() {
    let dir = dir("admit");
    let f = RetirementFixture::new(&dir.join("db"));
    let (now, p) = (f.now, proof(f.now, 7));
    f.set_legacy_zero(true);
    // Current-grant read (lease precondition).
    assert!(matches!(f.registry.current(&f.grant, now), Err(AttachmentLedgerError::State)));
    // Public admission: refused with the exact ledger error.
    assert!(matches!(
        f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now),
        Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
    ));
    // The nonce-consuming transaction on its own, bypassing the earlier current-grant read.
    let tx = f.registry.ledger.db.begin_write().unwrap();
    assert!(matches!(
        f.registry.admit_in(&tx, &f.grant, &p, now),
        Err(AttachmentReplayError::Ledger(AttachmentLedgerError::State))
    ));
    drop(tx);
    // Restoring the generation lets the very same proof through: nothing was consumed.
    f.set_legacy_zero(false);
    drop(f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now).unwrap());
    assert!(matches!(
        f.registry.admit_operation_after_authentication(&f.grant, 1, &p, now),
        Err(AttachmentReplayError::Replay)
    ));
}
