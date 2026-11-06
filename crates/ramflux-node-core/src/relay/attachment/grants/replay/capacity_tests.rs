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
use ramflux_protocol::large_attachment::QualifiedOwner;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::sync::Arc;

/// Live-page budget: 16 KiB root plus 16384 rows at 672 B, independent of the constants.
const LIVE_BUDGET: u64 = 11_026_432;
/// Distinct principals available to each fill. Both modes stop at their refusal first.
const FILL_PRINCIPALS: usize = 24_576;
const NOW: u64 = 1_700_000_001;
const UPLOAD: [u8; 32] = [21; 32];

/// Creates a file-backed ledger with one committed attachment that grants can bind to.
fn open_committed_ledger(name: &str) -> (std::path::PathBuf, AttachmentLedger) {
    let path = super::tests::path(name);
    let db = redb::Database::create(&path).unwrap();
    let tx = db.begin_write().unwrap();
    crate::relay::attachment::install(&tx, NOW).unwrap();
    tx.commit().unwrap();
    let ledger = AttachmentLedger::new(Arc::new(db), AttachmentPolicy::default()).unwrap();
    let (native, _grant) = fixtures();
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    ledger
        .reserve(
            &owner,
            AttachmentReservationRequest {
                upload_id: UPLOAD,
                object_id: native.manifest().object_id,
                layout: native.manifest().layout,
            },
            NOW - 1,
        )
        .unwrap();
    ledger.bind(&owner, &UPLOAD, &native, NOW - 1).unwrap();
    ledger.commit(&owner, &UPLOAD, 1, NOW - 1).unwrap();
    (path, ledger)
}

/// Admits distinct principals in digest (key) order, the worst B-tree layout, one
/// committed transaction per admission, until the first refusal. Returns the number
/// admitted and the refusal, if any.
fn fill_worst_case(
    ledger: &AttachmentLedger,
    requester: &QualifiedOwner,
    limits: Limits,
) -> (u64, Option<AttachmentReplayError>) {
    let mut others: Vec<(String, [u8; 64])> = (0..FILL_PRINCIPALS)
        .map(|n| {
            let mut other = requester.clone();
            other.account_anchor = format!("principal-{n}");
            (other.account_anchor.clone(), principal("node-a", &other))
        })
        .collect();
    others.sort_by_key(|(_, digest)| *digest);
    let mut admitted = 0_u64;
    for (anchor, _) in others {
        let mut other = requester.clone();
        other.account_anchor = anchor;
        let tx = ledger.db.begin_write().unwrap();
        match consume(&tx, "node-a", &other, &proof(NOW, 0), NOW, limits) {
            Ok(()) => {
                tx.commit().unwrap();
                admitted += 1;
            }
            Err(error) => return (admitted, Some(error)),
        }
    }
    (admitted, None)
}

/// Sums live redb pages across the replay tables, the quantity the annex budget covers.
fn live_bytes(ledger: &AttachmentLedger) -> u64 {
    let tx = ledger.db.begin_read().unwrap();
    let mut live = 0_u64;
    for stats in [
        tx.open_table(NONCES).unwrap().stats().unwrap(),
        tx.open_table(EXPIRY).unwrap().stats().unwrap(),
        tx.open_table(PRINCIPALS).unwrap().stats().unwrap(),
        tx.open_table(META).unwrap().stats().unwrap(),
    ] {
        live += stats.stored_bytes() + stats.metadata_bytes() + stats.fragmented_bytes();
    }
    live
}

fn charged_bytes(ledger: &AttachmentLedger) -> u64 {
    let tx = ledger.db.begin_read().unwrap();
    tx.open_table(META).unwrap().get("bytes").unwrap().unwrap().value()
}

/// Default caps: exactly 16384 worst-case rows fit, and the next public admission is refused.
pub(super) fn assert_default_capacity_worst_case_principals_on_disk() {
    assert_eq!(CAP_BYTES, LIVE_BUDGET);
    assert_eq!(DEFAULT_ENTRIES, 16_384);
    let (path, ledger) = open_committed_ledger("worst-capacity");
    let (native, grant) = fixtures();
    let registry = ledger.scoped_grants(authority()).unwrap();
    let requester = grant.grant().grantee.clone();
    let (admitted, refusal) = fill_worst_case(&ledger, &requester, Limits::default());
    assert_eq!(admitted, DEFAULT_ENTRIES);
    assert!(matches!(refusal, Some(AttachmentReplayError::ReplayProtectionCapacity)));
    let live = live_bytes(&ledger);
    let charged = charged_bytes(&ledger);
    let on_disk = std::fs::metadata(&path).unwrap().len();
    println!(
        "replay default worst case: rows={admitted} live={live} on_disk={on_disk} charged={charged} budget={LIVE_BUDGET}"
    );
    // The budget is ledger storage (live redb pages, annex section 9). File length is
    // reported only: copy-on-write slack is not bounded by the charge.
    assert!(charged <= LIVE_BUDGET, "charged={charged}");
    assert!(live <= LIVE_BUDGET, "live={live}");
    // Public admission of a fresh principal is refused with the exact capacity error.
    let signer = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    let mut probe = grant.grant().clone();
    probe.grant_id = [0xee; 32];
    probe.grantee.account_anchor = "public-probe".into();
    let probe = signed(&probe);
    registry
        .register(&UPLOAD, &native, &probe, &auth(&native, &probe, NOW).context(), &signer)
        .unwrap();
    assert!(matches!(
        registry.admit_operation_after_authentication(&probe, 1, &proof(NOW, 255), NOW),
        Err(AttachmentReplayError::ReplayProtectionCapacity)
    ));
    drop(registry);
    drop(ledger);
    std::fs::remove_file(path).unwrap();
}

/// Byte-cap-binding mode: the entry cap is set above any reachable count, so only the
/// live-page byte check can refuse. Fills until refusal and asserts the live pages stay
/// within the budget. Lowering `charge` below the measured row cost admits more rows and
/// must fail the live-page assertion (`BtF`).
pub(super) fn assert_byte_cap_binding_worst_case_principals_on_disk() {
    let (path, ledger) = open_committed_ledger("worst-byte-cap");
    let (_native, grant) = fixtures();
    let requester = grant.grant().grantee.clone();
    let limits =
        Limits { entries: u64::MAX, bytes: LIVE_BUDGET, principal: 1024, charge: ROW_CHARGE };
    let (admitted, refusal) = fill_worst_case(&ledger, &requester, limits);
    assert!(matches!(refusal, Some(AttachmentReplayError::ReplayProtectionCapacity)));
    let live = live_bytes(&ledger);
    let charged = charged_bytes(&ledger);
    println!(
        "replay byte-cap worst case: rows={admitted} live={live} charged={charged} budget={LIVE_BUDGET}"
    );
    assert!(live <= LIVE_BUDGET, "live={live} admitted={admitted}");
    assert!(charged <= LIVE_BUDGET, "charged={charged}");
    // The refusal came from the byte check: the next charge would exceed the budget.
    assert_eq!(admitted, DEFAULT_ENTRIES);
    assert!(charged + ROW_CHARGE > LIVE_BUDGET);
    drop(ledger);
    std::fs::remove_file(path).unwrap();
}
