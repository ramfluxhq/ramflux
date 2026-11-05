// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use crate::RelayRedbStore;
use ramflux_protocol::large_attachment::ContentManifest;
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "rf-native-ledger-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ))
}
fn fixture() -> ramflux_protocol::large_attachment::VerifiedContentManifest {
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
    let root = root();
    fs::create_dir_all(&root).unwrap();
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let policy = AttachmentPolicy { quota_bytes: 48, ..Default::default() };
    let ledger = store.attachment_ledger(policy).unwrap();
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
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
    ledger.commit(&owner, &first.upload_id, 101).unwrap();
    ledger.commit(&owner, &first.upload_id, 102).unwrap();
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
    assert!(ledger.commit(&owner, &[successful; 32], 105).is_err());
    drop(ledger);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn large_retention_defaults_and_operator_override_survive_restart() {
    let policy = AttachmentPolicy::default();
    assert_eq!(policy.quota_bytes, 20 * 1024 * 1024 * 1024);
    assert_eq!(policy.retention_seconds, 604_800);
    assert_eq!(policy.pending_lease_seconds, 3600);
    assert_eq!(policy.pending_max_seconds, 86_400);
    let root = root();
    fs::create_dir_all(&root).unwrap();
    let native = fixture();
    let owner = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    let store = RelayRedbStore::open(root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(policy).unwrap();
    let mut req = request(1);
    req.object_id = native.manifest().object_id;
    ledger.reserve(&owner, req, 100).unwrap();
    ledger.bind(&owner, &req.upload_id, &native, 100).unwrap();
    assert_eq!(ledger.commit(&owner, &req.upload_id, 200).unwrap().expires_at, Some(200 + 604_800));
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
    assert_eq!(ledger.cleanup_page(&owner, None, 128).unwrap().len(), 1);
    ledger.reclaim(&owner, &pending.upload_id, |_| Ok(())).unwrap();
    // Separate owner/upload generation admits the same frozen codec fixture.
    let other = AttachmentOwner::from_authenticated_session("owner-anchor").unwrap();
    let second_native = fixture();
    let mut later = request(3);
    later.object_id = second_native.manifest().object_id;
    // The original object identity is immutable, so a new upload id cannot retarget it.
    assert!(ledger.reserve(&other, later, 8000).is_err());
    drop(ledger);
    drop(store);
    let second_root = root.join("override");
    fs::create_dir_all(&second_root).unwrap();
    let store = RelayRedbStore::open(second_root.join("relay.redb")).unwrap();
    let ledger = store.attachment_ledger(override_policy).unwrap();
    ledger.reserve(&owner, req, 100).unwrap();
    ledger.bind(&owner, &req.upload_id, &native, 100).unwrap();
    assert_eq!(
        ledger.commit(&owner, &req.upload_id, 200).unwrap().expires_at,
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
    assert!(ledger.gc_due(200 + 14 * 86_400 - 1, 128).unwrap().is_empty());
    assert_eq!(ledger.gc_due(200 + 14 * 86_400, 128).unwrap().len(), 1);
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
    fs::remove_dir_all(root).unwrap();
}
