// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
//! Account erase removes the real nested segment layout written by the production store.
use super::{retirement_tests::bind, tests::fixture, *};
use crate::AccountIndex;

#[test]
fn account_erase_removes_real_segment_layout() {
    let (root, db) = crate::tests::test_db("erase-real-segment").unwrap();
    let (native, cipher) = fixture(0);
    bind(&db, &native, "first", "ref-first");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let reference =
        SegmentReference { selector: &wire, reference_hash: "ref-first", message_id: "first" };
    let mut store = db.segment_store().unwrap();
    store.admit_reference("first", 1, SegmentDirection::Download, &native, &reference).unwrap();
    store.checkpoint("first", 1, 0, 0, &cipher[0]).unwrap();
    let segment = store.location("first", 1).join("0.segment");
    drop(store);
    drop(db);
    let dir = root.join("accounts/acct");
    // The store canonicalizes its root (`/private/var` on macOS), so compare canonical forms.
    let tree = dir.join("ramflux_local.segments").canonicalize().unwrap();
    // Nested transfer/generation layout: segments/<hash>/<generation>/<index>.segment.
    assert!(segment.is_file() && std::fs::metadata(&segment).unwrap().len() > 0);
    assert_eq!(segment.strip_prefix(&tree).unwrap().components().count(), 3);
    let index = AccountIndex::open(&root).unwrap();
    index.erase_account_database("acct").unwrap();
    assert!(!segment.exists() && !tree.exists(), "the real segment layout must be erased");
    assert!(dir.join(".writer.lock").exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// Relative path to a description of every entry under `dir`: file bytes, directory marker or
/// symlink target. Symlinks are never followed.
fn snapshot(dir: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(
        base: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.insert(name, format!("symlink:{}", target.display()).into_bytes());
            } else if kind.is_dir() {
                out.insert(name, b"dir".to_vec());
                walk(base, &path, out);
            } else {
                out.insert(name, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

#[test]
fn account_erase_generation_top_level_symlink_refused_before_any_unlink() {
    // Every root artifact is seeded, then must be byte-identical after the refusal.
    let (root, db) = crate::tests::test_db("erase-generation-link").unwrap();
    let (native, cipher) = fixture(0);
    bind(&db, &native, "first", "ref-first");
    let wire = ramflux_protocol::encode_base64url(native.manifest().object_id);
    let reference =
        SegmentReference { selector: &wire, reference_hash: "ref-first", message_id: "first" };
    let mut store = db.segment_store().unwrap();
    store.admit_reference("first", 1, SegmentDirection::Download, &native, &reference).unwrap();
    store.checkpoint("first", 1, 0, 0, &cipher[0]).unwrap();
    drop(store);
    let dir = root.join("accounts/acct");
    let main = dir.join("ramflux_local.sqlite");
    let (wal, shm) = (dir.join("ramflux_local.sqlite-wal"), dir.join("ramflux_local.sqlite-shm"));
    let (wal_copy, shm_copy) = (std::fs::read(&wal).unwrap(), std::fs::read(&shm).unwrap());
    drop(db);
    std::fs::write(&wal, &wal_copy).unwrap();
    std::fs::write(&shm, &shm_copy).unwrap();
    let journal = dir.join("ramflux_local.sqlite-journal");
    std::fs::write(&journal, b"journal").unwrap();
    std::fs::write(dir.join(".backup-generation"), b"hint").unwrap();
    std::fs::create_dir_all(dir.join("objects")).unwrap();
    std::fs::write(dir.join("objects/o-1"), b"object-bytes").unwrap();
    for name in ["account.db", "account.db-wal", "account.segments/seg"] {
        let path = dir.join("generation_1").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"gen").unwrap();
    }
    let outside = root.join("outside_dir");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("file"), b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("generation_3")).unwrap();

    for path in [&main, &wal, &shm, &journal] {
        assert!(std::fs::metadata(path).unwrap().len() > 0, "{} seeded", path.display());
    }
    let before = snapshot(&dir);
    let outside_before = snapshot(&outside);
    assert!(before.keys().any(|name| name.ends_with(".segment")), "a real segment is seeded");
    let index = AccountIndex::open(&root).unwrap();
    let result = index.erase_account_database("acct");
    assert!(
        matches!(result, Err(crate::StorageError::Integrity("account erase symlink"))),
        "got {result:?}"
    );
    assert_eq!(snapshot(&dir), before, "the refusal must leave every root artifact unchanged");
    assert_eq!(snapshot(&outside), outside_before);
    std::fs::remove_dir_all(root).unwrap();
}
