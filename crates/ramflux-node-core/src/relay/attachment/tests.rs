// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;

mod lifecycle;

use crate::RelayRedbStore;
use ramflux_protocol::large_attachment::ContentManifest;
use redb::ReadableTableMetadata;
use std::fs;
pub(super) fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("rf-native-ledger-")
        .tempdir()
        .expect("test: create ledger directory")
}
pub(super) fn fixture() -> ramflux_protocol::large_attachment::VerifiedContentManifest {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let case = &vectors["cases"][0];
    let read = |name: &str| {
        case[name]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mc = read("content_manifest_unsigned_hex");
    let mut signed = Vec::new();
    signed.extend_from_slice(&u32::try_from(mc.len()).unwrap().to_be_bytes());
    signed.extend(mc);
    signed.extend_from_slice(&64_u32.to_be_bytes());
    signed.extend(read("content_signature_hex"));
    ContentManifest::decode_signed(&signed).unwrap()
}
fn request(id: u8) -> AttachmentReservationRequest {
    AttachmentReservationRequest {
        upload_id: [id; 32],
        object_id: [id.wrapping_add(16); 32],
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    }
}
fn occupied(ledger: &AttachmentLedger, owner: &str) -> u64 {
    let tx = ledger.db.begin_read().unwrap();
    let table = tx.open_table(RECORDS).unwrap();
    table
        .iter()
        .unwrap()
        .map(|item| {
            let (_, bytes) = item.unwrap();
            serde_json::from_slice::<serde_json::Value>(bytes.value()).unwrap()
        })
        .filter(|row| row["owner"] == owner && row["state"] != "released")
        .map(|row| row["size"].as_u64().unwrap())
        .sum()
}
#[test]
fn large_account_quota_includes_concurrent_reservations() {
    let temp = root();
    let root = temp.path().to_path_buf();
    fs::create_dir_all(&root).unwrap();
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let policy = AttachmentPolicy { quota_bytes: 48, ..Default::default() };
    let ledger = store.attachment_ledger(policy).unwrap();
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    let empty = ledger.usage(&owner).unwrap();
    assert_eq!((empty.used, empty.reserved, empty.records, empty.fences), (0, 0, 0, 0));
    let native = fixture();
    let mut first = request(1);
    first.object_id = native.manifest().object_id;
    ledger.reserve(&owner, first, 100).unwrap();
    ledger.reserve(&owner, first, 100).unwrap();
    assert_eq!(occupied(&ledger, "owner-anchor"), 16);
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads = (2..10)
        .map(|id| {
            let ledger = ledger.clone();
            let owner = owner.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                (id, ledger.reserve(&owner, request(id), 100))
            })
        })
        .collect::<Vec<_>>();
    let results = threads.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|(_, r)| r.is_ok()).count(), 2);
    assert!(
        results
            .iter()
            .filter(|(_, r)| r.is_err())
            .all(|(_, r)| matches!(r, Err(AttachmentLedgerError::AccountQuotaExceeded { .. })))
    );
    assert_eq!(occupied(&ledger, "owner-anchor"), 48);
    ledger.bind(&owner, &first.upload_id, &native, 100).unwrap();
    ledger.commit(&owner, &first.upload_id, 1, 101).unwrap();
    ledger.commit(&owner, &first.upload_id, 1, 102).unwrap();
    ledger.bind(&owner, &first.upload_id, &native, 103).unwrap();
    assert_eq!(
        (ledger.usage(&owner).unwrap().used, ledger.usage(&owner).unwrap().reserved),
        (16, 32)
    );
    let other = AttachmentOwner::from_authenticated_session("another-owner").unwrap();
    assert!(ledger.bind(&other, &first.upload_id, &native, 103).is_err());
    ledger.reserve(&other, request(30), 103).unwrap();
    assert_eq!(occupied(&ledger, "another-owner"), 16);
    let successful = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
    ledger.abandon_pending(&owner, &[successful; 32]).unwrap();
    let debris = root.join("partial");
    fs::write(&debris, [7; 16]).unwrap();
    assert!(
        ledger
            .reclaim(&owner, &[successful; 32], |_| Err(AttachmentLedgerError::Io(
                std::io::Error::other("backend failed")
            )))
            .is_err()
    );
    assert!(debris.exists());
    assert_eq!(occupied(&ledger, "owner-anchor"), 48);
    ledger
        .reclaim(&owner, &[successful; 32], |record| {
            assert_eq!(record.size, fs::metadata(&debris)?.len());
            fs::remove_file(&debris)?;
            fs::File::open(&root)?.sync_all()?;
            Ok(())
        })
        .unwrap();
    assert!(!debris.exists());
    assert_eq!(occupied(&ledger, "owner-anchor"), 32);
    ledger.reclaim(&owner, &[successful; 32], |_| Err(AttachmentLedgerError::State)).unwrap();
    let mut changed = first;
    changed.layout.plaintext_length = 1;
    assert!(ledger.reserve(&owner, changed, 104).is_err());
    assert!(ledger.bind(&owner, &[10; 32], &native, 104).is_err());
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(policy).unwrap();
    assert_eq!(occupied(&ledger, "owner-anchor"), 32);
    assert_eq!(ledger.usage(&owner).unwrap().used, 16);
    assert!(ledger.commit(&owner, &[successful; 32], 1, 105).is_err());
    drop(ledger);
    drop(store);
}
#[test]
fn large_retention_defaults_and_operator_override_survive_restart() {
    let policy = AttachmentPolicy::default();
    assert_eq!(policy.quota_bytes, 20 * 1024 * 1024 * 1024);
    assert_eq!(policy.retention_seconds, 604_800);
    assert_eq!(policy.pending_lease_seconds, 3600);
    assert_eq!(policy.pending_max_seconds, 86_400);
    let temp = root();
    let root = temp.path().to_path_buf();
    fs::create_dir_all(&root).unwrap();
    let native = fixture();
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(policy).unwrap();
    let mut req = request(1);
    req.object_id = native.manifest().object_id;
    ledger.reserve(&owner, req, 100).unwrap();
    ledger.bind(&owner, &req.upload_id, &native, 100).unwrap();
    assert_eq!(
        ledger.commit(&owner, &req.upload_id, 1, 200).unwrap().expires_at,
        Some(200 + 604_800)
    );
    assert_eq!(
        ledger.committed(&owner, &req.upload_id, 400).unwrap().expires_at,
        Some(200 + 604_800)
    );
    assert!(ledger.abandon_pending(&owner, &req.upload_id).is_err()); // local cancel/ACK cannot erase a committed file.
    let mut pending = request(2);
    pending.object_id = [50; 32];
    ledger.reserve(&owner, pending, 100).unwrap();
    assert_eq!(ledger.renew_lease(&owner, &pending.upload_id, 3599).unwrap().lease_until, 7199);
    assert!(ledger.renew_lease(&owner, &pending.upload_id, 7200).is_err());
    let bounded = request(5);
    ledger.reserve(&owner, bounded, 100).unwrap();
    let mut lease = ledger.reservation(&owner, &bounded.upload_id).unwrap();
    for _ in 0..30 {
        if lease.lease_until == 86_500 {
            break;
        }
        lease = ledger.renew_lease(&owner, &bounded.upload_id, lease.lease_until - 1).unwrap();
    }
    assert_eq!(lease.lease_until, 86_500);
    assert!(ledger.renew_lease(&owner, &bounded.upload_id, 86_500).is_err());
    ledger.abandon_pending(&owner, &bounded.upload_id).unwrap();
    ledger.reclaim(&owner, &bounded.upload_id, |_| Ok(())).unwrap();
    assert_eq!(ledger.gc_due(7200, 1).unwrap().len(), 1);
    assert_eq!(ledger.usage(&owner).unwrap().reserved, 16);
    drop(ledger);
    drop(store);
    let override_policy = AttachmentPolicy {
        retention_seconds: 14 * 86_400,
        quota_bytes: 30 * 1024 * 1024 * 1024,
        ..policy
    };
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(override_policy).unwrap();
    assert_eq!(
        ledger.committed(&owner, &req.upload_id, 8000).unwrap().expires_at,
        Some(200 + 604_800)
    );
    assert_eq!(ledger.cleanup_page(&owner, None, 64).unwrap().len(), 1);
    ledger.reclaim(&owner, &pending.upload_id, |_| Ok(())).unwrap();
    let foreign = AttachmentOwner::from_authenticated_session("foreign-owner").unwrap();
    let mut foreign_request = request(3);
    foreign_request.object_id = native.manifest().object_id;
    ledger.reserve(&foreign, foreign_request, 8000).unwrap();
    let before = ledger.usage(&foreign).unwrap().reserved;
    assert!(matches!(
        ledger.bind(&foreign, &foreign_request.upload_id, &native, 8000),
        Err(AttachmentLedgerError::Conflict)
    ));
    assert_eq!(ledger.usage(&foreign).unwrap().reserved, before);
    drop(ledger);
    drop(store);
    let second_root = root.join("override");
    fs::create_dir_all(&second_root).unwrap();
    let store = RelayRedbStore::open(second_root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(override_policy).unwrap();
    ledger.reserve(&owner, req, 100).unwrap();
    ledger.bind(&owner, &req.upload_id, &native, 100).unwrap();
    assert_eq!(
        ledger.commit(&owner, &req.upload_id, 1, 200).unwrap().expires_at,
        Some(200 + 14 * 86_400)
    );
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(second_root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(AttachmentPolicy { quota_bytes: 8, ..policy }).unwrap();
    assert_eq!(
        ledger.committed(&owner, &req.upload_id, 200 + 8 * 86_400).unwrap().expires_at,
        Some(200 + 14 * 86_400)
    );
    assert!(matches!(
        ledger.reserve(&owner, request(4), 1000),
        Err(AttachmentLedgerError::AccountQuotaExceeded { .. })
    ));
    assert!(ledger.gc_due(200 + 14 * 86_400 - 1, 64).unwrap().is_empty());
    assert!(matches!(
        ledger.committed(&owner, &req.upload_id, 200 + 14 * 86_400),
        Err(AttachmentLedgerError::Expired)
    ));
    assert_eq!(ledger.gc_due(200 + 14 * 86_400, 64).unwrap().len(), 1);
    assert!(matches!(
        ledger.committed(&owner, &req.upload_id, 200 + 14 * 86_400),
        Err(AttachmentLedgerError::Expired)
    ));
    assert_eq!(ledger.usage(&owner).unwrap().used, 16);
    ledger.reclaim(&owner, &req.upload_id, |_| Ok(())).unwrap();
    assert_eq!(ledger.usage(&owner).unwrap().used, 0);
    assert!(ledger.reserve(&owner, req, 200 + 14 * 86_400 + 1).is_err());
    drop(ledger);
    drop(store);
}

pub(super) fn memory_ledger(policy: AttachmentPolicy) -> AttachmentLedger {
    let db = redb::Database::builder()
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .unwrap();
    let tx = db.begin_write().unwrap();
    install(&tx, crate::now_unix_seconds()).unwrap();
    tx.commit().unwrap();
    AttachmentLedger::new(Arc::new(db), policy).unwrap()
}
fn cycle_request(index: u64) -> AttachmentReservationRequest {
    let mut id = [0; 32];
    id[..8].copy_from_slice(&index.to_be_bytes());
    AttachmentReservationRequest {
        upload_id: id,
        object_id: id,
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    }
}
#[test]
fn released_records_free_live_capacity_and_compact_expiring_identity_fences() {
    let owner = AttachmentOwner::from_authenticated_session("owner").unwrap();
    let ledger = memory_ledger(AttachmentPolicy { max_records_per_owner: 1, ..Default::default() });
    let first = cycle_request(0);
    ledger.reserve(&owner, first, 100).unwrap();
    assert!(matches!(
        ledger.reserve(&owner, cycle_request(1), 100),
        Err(AttachmentLedgerError::Capacity)
    ));
    ledger.abandon_pending(&owner, &first.upload_id).unwrap();
    ledger.reclaim(&owner, &first.upload_id, |_| Ok(())).unwrap();
    assert_eq!(ledger.usage(&owner).unwrap().records, 0);
    for index in 1..=16_385 {
        let request = cycle_request(index);
        ledger.reserve(&owner, request, 100).unwrap();
        ledger.abandon_pending(&owner, &request.upload_id).unwrap();
        ledger.reclaim(&owner, &request.upload_id, |_| Ok(())).unwrap();
    }
    let tx = ledger.db.begin_read().unwrap();
    assert_eq!(tx.open_table(RECORDS).unwrap().len().unwrap(), 0);
    let fences = tx.open_table(super::identity::FENCES).unwrap();
    assert_eq!(fences.len().unwrap(), 16_386);
    assert!(fences.iter().unwrap().all(|entry| entry.unwrap().1.value().len() == 40));
    assert_eq!(ledger.usage(&owner).unwrap().records, 0);
    drop(fences);
    drop(tx);
    assert!(ledger.reserve(&owner, first, 200).is_err());
    // Fence horizon exceeds both the maximum lease and any token skew window.
    let until = 100 + 86_400 + 305;
    assert!(ledger.gc_due(until - 1, 64).unwrap().is_empty());
    assert!(ledger.reserve(&owner, first, until - 1).is_err());
    while ledger.usage(&owner).unwrap().fences != 0 {
        ledger.gc_due(until, 64).unwrap();
    }
    // The identity fence is gone, but the terminal object id is never reusable.
    assert!(matches!(ledger.reserve(&owner, first, until), Err(AttachmentLedgerError::State)));
    assert!(ledger.gc_due(until, 65).is_err());
    assert!(ledger.cleanup_page(&owner, None, 65).is_err());
}
#[test]
fn global_debt_page_recovers_cleanup_after_gc_worker_restart() {
    let temp = root();
    let root = temp.path().to_path_buf();
    fs::create_dir_all(&root).unwrap();
    let path = root.join("relay.redb");
    // Historical relay DB has the old tables but none of the native tables.
    {
        let db = redb::Database::create(&path).unwrap();
        let tx = db.begin_write().unwrap();
        let _ = tx.open_table(crate::RELAY_CACHE_TABLE).unwrap();
        let _ = tx.open_table(crate::RELAY_CHUNK_ENTRY_TABLE).unwrap();
        let _ = tx.open_table(crate::RELAY_TOMBSTONE_TABLE).unwrap();
        tx.commit().unwrap();
    }
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(AttachmentPolicy::default()).unwrap();
    let a = AttachmentOwner::from_authenticated_session("a").unwrap();
    let b = AttachmentOwner::from_authenticated_session("bb").unwrap();
    assert_eq!(ledger.usage(&a).unwrap().records, 0);
    assert_eq!(ledger.debt_page(None, 64).unwrap().jobs.len(), 0);
    ledger.reserve(&a, request(1), 100).unwrap();
    ledger.reserve(&b, request(2), 100).unwrap();
    assert_eq!(ledger.gc_due(3700, 64).unwrap().len(), 2);
    drop(ledger);
    drop(store);
    let store = RelayRedbStore::open(&path).unwrap();
    let ledger = store.attachment_ledger(AttachmentPolicy::default()).unwrap();
    let mut cursor = None;
    let mut found = 0;
    loop {
        let page = ledger.debt_page(cursor.as_deref(), 1).unwrap();
        for job in page.jobs {
            let owner = AttachmentOwner::from_authenticated_session(&job.owner).unwrap();
            assert_eq!(ledger.usage(&owner).unwrap().reserved, 16);
            ledger.reclaim(&owner, &job.upload_id, |_| Ok(())).unwrap();
            assert_eq!(ledger.usage(&owner).unwrap().reserved, 0);
            found += 1;
        }
        let Some(next) = page.next else {
            break;
        };
        cursor = Some(next);
    }
    assert_eq!(found, 2);
    assert_eq!(ledger.debt_page(None, 64).unwrap().jobs.len(), 0);
    assert!(ledger.debt_page(None, 65).is_err());
    assert!(ledger.debt_page(Some(&[1; 500]), 1).is_err());
    drop(ledger);
    drop(store);
}

#[test]
fn historical_released_records_compact_on_normal_schema_install() {
    let policy = AttachmentPolicy { max_records_per_owner: 1, ..Default::default() };
    let ledger = memory_ledger(policy);
    let owner = AttachmentOwner::from_authenticated_session("historical-owner").unwrap();
    let request = cycle_request(1);
    let mut released = ledger.reserve(&owner, request, 100).unwrap();
    released.state = AttachmentReservationState::Released;
    let tx = ledger.db.begin_write().unwrap();
    {
        tx.open_table(RECORDS)
            .unwrap()
            .insert(
                key(&owner, &request.upload_id).as_slice(),
                serde_json::to_vec(&released).unwrap().as_slice(),
            )
            .unwrap();
        tx.open_table(TOTALS)
            .unwrap()
            .insert("historical-owner", br#"{"used":0,"reserved":0,"records":1}"#.as_slice())
            .unwrap();
        let schema: TableDefinition<&str, u64> =
            TableDefinition::new("native_attachment_ledger_schema");
        tx.open_table(schema).unwrap().remove("compact_releases_v1").unwrap();
        // A ledger that predates the terminal counters: install seeds them from the rows.
        let mut config = tx.open_table(super::grants::CONFIG).unwrap();
        config.remove("terminal_owners").unwrap();
        config.remove("terminal_slots_global").unwrap();
    }
    tx.commit().unwrap();
    let tx = ledger.db.begin_write().unwrap();
    install(&tx, crate::now_unix_seconds()).unwrap();
    tx.commit().unwrap();
    let total = ledger.usage(&owner).unwrap();
    assert_eq!((total.used, total.reserved, total.records, total.fences), (0, 0, 0, 1));
    assert!(ledger.reserve(&owner, request, 101).is_err());
    let bounded = AttachmentLedger::new(
        Arc::clone(&ledger.db),
        AttachmentPolicy { max_identity_fences_per_owner: 1, ..policy },
    )
    .unwrap();
    assert!(matches!(
        bounded.reserve(&owner, cycle_request(2), 101),
        Err(AttachmentLedgerError::Capacity)
    ));
    ledger.reserve(&owner, cycle_request(2), 101).unwrap();
}

#[test]
fn distinct_identity_fences_and_cleanup_after_lowered_cap_do_not_hide_due_jobs() {
    let policy = AttachmentPolicy {
        pending_lease_seconds: 1,
        pending_max_seconds: 2,
        max_identity_fences_per_owner: 4,
        ..Default::default()
    };
    let ledger = memory_ledger(policy);
    let owner = AttachmentOwner::from_authenticated_session("distinct-owner").unwrap();
    let first = AttachmentReservationRequest {
        upload_id: [1; 32],
        object_id: [2; 32],
        layout: SegmentLayout { plaintext_length: 0, network_chunk_bytes: 524_288 },
    };
    ledger.reserve(&owner, first, 100).unwrap();
    ledger.abandon_pending(&owner, &first.upload_id).unwrap();
    let lower = AttachmentLedger::new(
        Arc::clone(&ledger.db),
        AttachmentPolicy { max_identity_fences_per_owner: 1, ..policy },
    )
    .unwrap();
    lower.reclaim(&owner, &first.upload_id, |_| Ok(())).unwrap();
    assert!(matches!(
        ledger.reserve(&owner, AttachmentReservationRequest { object_id: [3; 32], ..first }, 101),
        Err(AttachmentLedgerError::State)
    ));
    assert!(matches!(
        ledger.reserve(&owner, AttachmentReservationRequest { upload_id: [4; 32], ..first }, 101),
        Err(AttachmentLedgerError::State)
    ));
    let debt = AttachmentReservationRequest { upload_id: [5; 32], object_id: [6; 32], ..first };
    ledger.reserve(&owner, debt, 406).unwrap();
    // The fence expires at407 and the live reservation's lease also expires at407.
    let due = ledger.gc_due(407, 1).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].upload_id, debt.upload_id);
    assert_eq!(ledger.usage(&owner).unwrap().fences, 0);
    ledger.reclaim(&owner, &debt.upload_id, |_| Ok(())).unwrap();
    // Cleanup cannot become refused after lowering the cap beneath existing fences.
    let next = AttachmentReservationRequest { upload_id: [7; 32], object_id: [8; 32], ..first };
    ledger.reserve(&owner, next, 408).unwrap();
    ledger.abandon_pending(&owner, &next.upload_id).unwrap();
    lower.reclaim(&owner, &next.upload_id, |_| Ok(())).unwrap();
    assert_eq!(ledger.usage(&owner).unwrap().reserved, 0);
}
