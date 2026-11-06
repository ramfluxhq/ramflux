// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::{files, retirement_tests::bind, tests::fixture, *};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::params;
use std::fs;
fn owned(db: &AccountDb) -> (VerifiedContentManifest, Vec<Vec<u8>>) {
    let (original, cipher) = fixture(0);
    let key = SigningKey::from_bytes(&[77; 32]);
    let mut m = original.manifest().clone();
    m.owner.account_anchor = db.principal_commitment.clone();
    m.owner.signing_public_key = key.verifying_key().to_bytes();
    let signature = key.sign(&m.signing_bytes().unwrap()).to_bytes();
    (
        ramflux_protocol::large_attachment::ContentManifest::decode_signed(
            &m.signed_bytes(&signature).unwrap(),
        )
        .unwrap(),
        cipher,
    )
}
#[test]
fn account_commit_and_hold_release_only_signal_bounded_segment_cleanup() {
    let (root, db) = crate::tests::test_db("large-commit-notify").unwrap();
    let mut store = db.segment_store().unwrap();
    let mut directories = Vec::new();
    for n in 0..33_u8 {
        let dir = ramflux_protocol::encode_base64url([n; 32]);
        let path = store.root.join(&dir).join("1");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("bytes"), b"cipher").unwrap();
        directories.push(dir);
    }
    let before = files::filesystem_operations();
    db.write_transaction(|| {
        for dir in &directories {db.connection.execute("INSERT INTO object_segment_resource VALUES(?1,1,NULL,'wire','manifest','commitment',NULL,NULL,NULL,1)",params![dir])?;}
        Ok::<_,StorageError>(())
    }).unwrap();
    assert_eq!(files::filesystem_operations(), before, "commit must only signal the I/O owner");
    assert!(directories.iter().all(|dir| store.root.join(dir).join("1/bytes").is_file()));
    let page = store.cleanup_retired(32).unwrap();
    assert_eq!(page.deleted, 32);
    assert!(page.more);
    assert_eq!(store.cleanup_retired(32).unwrap().deleted, 1);
    assert!(
        directories.iter().all(|dir| !store.root.join(dir).exists()),
        "empty parents must be reclaimed"
    );
    let (native, cipher) = owned(&db);
    let m = native.manifest();
    let wire = ramflux_protocol::encode_base64url(m.object_id);
    let hash = ramflux_protocol::encode_base64url(m.hash().unwrap());
    let hold = db.pre_send_object_hold(&wire, &hash).unwrap();
    store.admit_pre_send("release", 1, &native, &hold).unwrap();
    store.checkpoint("release", 1, 0, 0, &cipher[0]).unwrap();
    let path = store.location("release", 1);
    let before = files::filesystem_operations();
    hold.release().unwrap();
    assert_eq!(
        files::filesystem_operations(),
        before,
        "hold release must only signal the I/O owner"
    );
    assert!(path.is_dir());
    store.cleanup_retired(32).unwrap();
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn segment_refusals_bind_page_types_hold_authority_and_live_reference() {
    let (root, db) = crate::tests::test_db("large-refusals").unwrap();
    let (native, _) = owned(&db);
    let mut store = db.segment_store().unwrap();
    for limit in [0, 33] {
        assert!(matches!(
            store.cleanup_retired(limit),
            Err(StorageError::Integrity("segment cleanup limit"))
        ));
        let mut sweep = store.orphan_sweep().unwrap();
        assert!(matches!(
            store.discover_orphans(&mut sweep, limit),
            Err(StorageError::Integrity("segment orphan page"))
        ));
    }
    let m = native.manifest();
    let wire = ramflux_protocol::encode_base64url(m.object_id);
    let hash = ramflux_protocol::encode_base64url(m.hash().unwrap());
    let mut hold = db.pre_send_object_hold(&wire, &hash).unwrap();
    let (foreign, _) = fixture(0);
    assert!(matches!(
        store.admit_pre_send("foreign", 1, &foreign, &hold),
        Err(StorageError::AuthorizationRejected)
    ));
    hold.disarm_for_test();
    assert!(matches!(
        store.admit_pre_send("disarmed", 1, &native, &hold),
        Err(StorageError::AuthorizationRejected)
    ));
    bind(&db, &native, "one", "ref-one");
    bind(&db, &native, "two", "ref-two");
    let first = SegmentReference { selector: &wire, reference_hash: "ref-one", message_id: "one" };
    let second = SegmentReference { selector: &wire, reference_hash: "ref-two", message_id: "two" };
    store.admit_reference("bound", 1, SegmentDirection::Download, &native, &first).unwrap();
    assert!(matches!(
        store.admit_reference("bound", 1, SegmentDirection::Download, &native, &second),
        Err(StorageError::ObjectIdentityConflict)
    ));
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn orphan_sweep_skips_stray_files_and_refuses_known_bad_entries() {
    let (root, db) = crate::tests::test_db("large-orphan-refusals").unwrap();
    let store = db.segment_store().unwrap();
    fs::write(store.root.join(".DS_Store"), b"stray").unwrap();
    let parent = store.root.join(ramflux_protocol::encode_base64url([88; 32]));
    fs::create_dir(&parent).unwrap();
    fs::create_dir(parent.join("1")).unwrap();
    let mut sweep = store.orphan_sweep().unwrap();
    while store.discover_orphans(&mut sweep, 1).unwrap() {}
    store.cleanup_retired(32).unwrap();
    assert!(!parent.exists());
    let known = store.root.join(ramflux_protocol::encode_base64url([89; 32]));
    fs::write(&known, b"bad").unwrap();
    let mut sweep = store.orphan_sweep().unwrap();
    let result = loop {
        match store.discover_orphans(&mut sweep, 32) {
            Ok(true) => {}
            result => break result,
        }
    };
    assert!(matches!(result, Err(StorageError::Integrity("segment orphan directory"))));
    fs::remove_file(&known).unwrap();
    fs::create_dir(&known).unwrap();
    fs::write(known.join("1"), b"bad").unwrap();
    let mut sweep = store.orphan_sweep().unwrap();
    let result = loop {
        match store.discover_orphans(&mut sweep, 32) {
            Ok(true) => {}
            result => break result,
        }
    };
    assert!(matches!(result, Err(StorageError::Integrity("segment generation directory"))));
    fs::remove_file(known.join("1")).unwrap();
    fs::create_dir(known.join("invalid")).unwrap();
    let mut sweep = store.orphan_sweep().unwrap();
    let result = loop {
        match store.discover_orphans(&mut sweep, 32) {
            Ok(true) => {}
            result => break result,
        }
    };
    assert!(matches!(result, Err(StorageError::Integrity("segment orphan generation"))));
    drop(store);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn restored_live_reference_refuses_only_the_retained_generation_floor() {
    let (root, db) = crate::tests::test_db("large-live-floor").unwrap();
    let (native, _) = fixture(0);
    bind(&db, &native, "live", "reference");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let reference =
        SegmentReference { selector: &wire, reference_hash: "reference", message_id: "live" };
    let mut store = db.segment_store().unwrap();
    store.admit_reference("floor", 1, SegmentDirection::Download, &native, &reference).unwrap();
    let old_path = root.join("old.db");
    let old = db.write_backup_snapshot(&old_path).unwrap();
    db.write_transaction(|| {
        db.connection.execute(
            "INSERT INTO object_segment_floor VALUES(?1,1)",
            params![ramflux_protocol::encode_base64url(blake3::hash(b"floor").as_bytes())],
        )?;
        Ok::<_, StorageError>(())
    })
    .unwrap();
    let fenced_path = root.join("fenced.db");
    let fenced = db.write_backup_snapshot(&fenced_path).unwrap();
    drop(store);
    drop(db);
    let mut candidate = crate::BackupDatabase::open(&old_path, &old.key).unwrap();
    candidate.merge_backup(&fenced_path, &fenced.key, || Ok(())).unwrap();
    let index = crate::AccountIndex::open(root.join("restored")).unwrap();
    let record = index.create_account("acct", "principal").unwrap();
    let key = crate::AccountDbKey::generate().unwrap();
    candidate.copy_to(&index.root().join(record.db_relative_path), &key).unwrap();
    drop(candidate);
    let restored = AccountDb::open(&index, "acct", &key).unwrap();
    assert!(!restored.message_is_deleted("live").unwrap());
    let mut store = restored.segment_store().unwrap();
    store
        .check_reference(
            &reference,
            &wire,
            &ramflux_protocol::encode_base64url(native.manifest().hash().unwrap()),
        )
        .unwrap();
    assert!(matches!(
        store.admit_reference("floor", 1, SegmentDirection::Download, &native, &reference),
        Err(StorageError::ObjectErased)
    ));
    drop(store);
    drop(restored);
    drop(index);
    fs::remove_dir_all(root).unwrap();
}
