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

/// Fills the default entry and byte caps with the worst-case principal distribution
/// (one nonce per distinct qualified principal, so every row also owns a principal
/// counter). Filling uses the storage admission with per-batch commits on a
/// file-backed redb, because one owner can register at most 1024 grants and the
/// public path cannot reach 10k distinct principals from one owner. The on-disk
/// size and the next public admission are then checked against the real caps.
pub(super) fn assert_default_capacity_worst_case_principals_on_disk() {
    let path = super::tests::path("worst-capacity");
    let db = redb::Database::create(&path).unwrap();
    let tx = db.begin_write().unwrap();
    crate::relay::attachment::install(&tx, 1_700_000_001).unwrap();
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
    let entries = Limits::default().entries;
    let requester = grant.grant().grantee.clone();
    // Worst layout: principals arrive in digest (key) order, so every table appends
    // sequentially and leaves the densest-fragmenting B-tree pages behind.
    let mut principals: Vec<(String, [u8; 64])> = (0..entries)
        .map(|n| {
            let mut other = requester.clone();
            other.account_anchor = format!("principal-{n}");
            (other.account_anchor.clone(), principal("node-a", &other))
        })
        .collect();
    principals.sort_by_key(|(_, digest)| *digest);
    // One committed transaction per admission, as the production path does.
    for (anchor, _) in principals {
        let tx = ledger.db.begin_write().unwrap();
        let mut other = requester.clone();
        other.account_anchor = anchor;
        consume(&tx, "node-a", &other, &proof(now, 0), now, Limits::default()).unwrap();
        tx.commit().unwrap();
    }
    let tx = ledger.db.begin_read().unwrap();
    assert_eq!(tx.open_table(NONCES).unwrap().len().unwrap(), entries);
    assert_eq!(tx.open_table(PRINCIPALS).unwrap().len().unwrap(), entries);
    let charged = tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value();
    let mut live = 0_u64;
    for stats in [
        tx.open_table(NONCES).unwrap().stats().unwrap(),
        tx.open_table(EXPIRY).unwrap().stats().unwrap(),
        tx.open_table(PRINCIPALS).unwrap().stats().unwrap(),
        tx.open_table(META).unwrap().stats().unwrap(),
    ] {
        live += stats.stored_bytes() + stats.metadata_bytes() + stats.fragmented_bytes();
    }
    drop(tx);
    // The cap is ledger storage (live redb pages, annex section 9). File length is
    // reported only: copy-on-write slack in the file is not bounded by the charge.
    let on_disk = std::fs::metadata(&path).unwrap().len();
    println!(
        "replay capacity worst case: rows={entries} live={live} on_disk={on_disk} charged={charged} cap={CAP_BYTES}"
    );
    assert!(charged <= CAP_BYTES, "charged={charged}");
    assert!(live <= CAP_BYTES, "live={live}");
    // Public admission of a fresh principal is refused with the exact capacity error.
    let signer = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    let mut probe = grant.grant().clone();
    probe.grant_id = [0xee; 32];
    probe.grantee.account_anchor = "public-probe".into();
    let probe = signed(&probe);
    registry
        .register(&upload, &native, &probe, &auth(&native, &probe, now).context(), &signer)
        .unwrap();
    assert!(matches!(
        registry.admit_operation_after_authentication(&probe, 1, &proof(now, 255), now),
        Err(AttachmentReplayError::ReplayProtectionCapacity)
    ));
    drop(registry);
    drop(ledger);
    std::fs::remove_file(path).unwrap();
}
