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
    let tree = dir.join("ramflux_local.segments");
    // Nested transfer/generation layout: segments/<hash>/<generation>/<index>.segment.
    assert!(segment.is_file() && std::fs::metadata(&segment).unwrap().len() > 0);
    assert_eq!(segment.strip_prefix(&tree).unwrap().components().count(), 3);
    let index = AccountIndex::open(&root).unwrap();
    index.erase_account_database("acct").unwrap();
    assert!(!segment.exists() && !tree.exists(), "the real segment layout must be erased");
    assert!(dir.join(".writer.lock").exists());
    std::fs::remove_dir_all(root).unwrap();
}
