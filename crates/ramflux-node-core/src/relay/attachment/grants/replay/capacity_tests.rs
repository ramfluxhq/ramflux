// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::storage::*;
use super::tests::{authority, proof};
use super::*;
use crate::relay::attachment::grants::test_support::{auth, fixtures, signed};
use crate::relay::attachment::{
    AttachmentLedger, AttachmentOwner, AttachmentPolicy, AttachmentReservationRequest,
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::sync::Arc;

#[test]
fn replay_default_entry_and_byte_caps_are_reachable_through_public_admission() {
    let db = redb::Database::builder()
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .unwrap();
    let tx = db.begin_write().unwrap();
    crate::relay::attachment::install(&tx).unwrap();
    tx.commit().unwrap();
    let ledger = AttachmentLedger::new(Arc::new(db), AttachmentPolicy::default()).unwrap();
    let (native, grant) = fixtures();
    let now = 1_700_000_001;
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    let upload = [21; 32];
    ledger
        .reserve(
            &owner,
            AttachmentReservationRequest {
                upload_id: upload,
                object_id: native.manifest().object_id,
                layout: native.manifest().layout,
            },
            now - 1,
        )
        .unwrap();
    ledger.bind(&owner, &upload, &native, now - 1).unwrap();
    ledger.commit(&owner, &upload, now - 1).unwrap();
    let registry = ledger.scoped_grants(authority()).unwrap();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    let mut grants = Vec::new();
    // Sixteen independent qualified principals fill all public default capacities.
    for principal in 0..17_u8 {
        let mut g = grant.grant().clone();
        g.grant_id = [principal; 32];
        g.grantee.account_anchor = format!("principal-{principal}");
        let g = signed(&g);
        registry
            .register(&upload, &native, &g, &auth(&native, &g, now).context(), &signer)
            .unwrap();
        grants.push(g);
    }
    for g in &grants[..16] {
        for nonce in 0..1024_u64 {
            let mut p = proof(now, 0);
            p.nonce[..8].copy_from_slice(&nonce.to_be_bytes());
            drop(registry.admit_operation_after_authentication(g, 1, &p, now).unwrap());
        }
    }
    let tx = ledger.db.begin_read().unwrap();
    let rows = tx.open_table(NONCES).unwrap().len().unwrap();
    let charged = tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value();
    assert_eq!(rows, Limits::default().entries);
    assert_eq!(charged, Limits::default().bytes);
    let mut actual = 0_u64;
    for stats in [
        tx.open_table(NONCES).unwrap().stats().unwrap(),
        tx.open_table(EXPIRY).unwrap().stats().unwrap(),
        tx.open_table(PRINCIPALS).unwrap().stats().unwrap(),
        tx.open_table(META).unwrap().stats().unwrap(),
    ] {
        actual += stats.stored_bytes() + stats.metadata_bytes() + stats.fragmented_bytes();
    }
    assert!(actual <= charged, "actual={actual}, charged={charged}, rows={rows}");
    println!(
        "replay capacity: rows={rows}, actual={actual}, charged={charged}, per_row={}",
        actual.div_ceil(rows)
    );
    drop(tx);
    assert!(matches!(
        registry.admit_operation_after_authentication(&grants[16], 1, &proof(now, 255), now),
        Err(AttachmentReplayError::ReplayProtectionCapacity)
    ));
}
