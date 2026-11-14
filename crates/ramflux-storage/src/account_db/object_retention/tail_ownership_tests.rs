// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary B assertions acquire provenance even when the merged physical edge already exists.
use super::{ObjectRetention, object_erasure_commitment};
use crate::{AccountDb, AccountDbKey, AccountIndex, AdoptionRow};
use rusqlite::params;
fn h(value: u8) -> String {
    ramflux_protocol::encode_base64url([value; 32])
}
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_full_tail_duplicate_local_dependency_retains_independent_b_ownership() -> TestResult {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("acct", &h(2))?;
    let key = AccountDbKey::derive("acct", b"tail-local-owner-test");
    let db = AccountDb::open(&index, "acct", &key)?;
    db.retain_object("parent", "parent-manifest", ObjectRetention::OwnDeviceTransport)?;
    db.retain_object("child", "child-manifest", ObjectRetention::Imported)?;
    db.retain_transport_dependency("parent", "parent-manifest", "child", "child-manifest")?;
    db.put_pairing_adoption(&AdoptionRow {
        account_id: "acct".into(),
        operation_id: h(20),
        record_hash: h(4),
        local_ref: ramflux_protocol::canonical_json_bytes(&ramflux_protocol::custody::DeviceRef {
            account_anchor: h(2),
            device_id: "b".into(),
            device_epoch: 1,
        })?,
        local_role: "primary".into(),
        branch_vault_ref: "vault-branch".into(),
        data_vault_ref: "vault-data".into(),
        primary_vault_ref: Some("vault-primary".into()),
        full_generation_nonce: Some(h(5)),
        full_initial_union_root: Some(h(6)),
    })?;
    for (operation, nonce) in [(h(20), h(5)), (h(21), h(7))] {
        db.connection.execute("INSERT INTO pairing_full_tail_apply(operation_id,generation_nonce,stage_digest,source_owner) VALUES(?1,?2,?3,'original-a')",
            params![operation,nonce,[9_u8;32].as_slice()])?;
    }
    let parent = object_erasure_commitment(&h(2), "parent", "parent-manifest");
    let child = object_erasure_commitment(&h(2), "child", "child-manifest");
    db.connection.execute(
        "INSERT INTO pairing_full_tail_dependency VALUES(?1,0,?2,?3)",
        params![h(20), parent, child],
    )?;
    db.retain_transport_dependency("parent", "parent-manifest", "child", "child-manifest")?;
    let owners: u64 = db.connection.query_row(
        "SELECT count(*) FROM pairing_full_tail_dependency WHERE operation_id=?1 AND parent_commitment=?2 AND child_commitment=?3",
        params![h(20),parent,child], |row| row.get(0),
    )?;
    assert_eq!(owners, 2, "test: B's duplicate assertion lost independent ownership of A's edge");
    let physical: u64 = db.connection.query_row("SELECT count(*) FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2", params![parent,child], |row| row.get(0))?;
    assert_eq!(physical, 1, "test: provenance tracking duplicated the physical dependency");
    let stale: u64 = db.connection.query_row(
        "SELECT count(*) FROM pairing_full_tail_dependency WHERE operation_id=?1 AND owner=1",
        params![h(21)],
        |row| row.get(0),
    )?;
    assert_eq!(
        stale, 0,
        "test: ordinary write acquired ownership in a different selected generation"
    );
    db.connection.call(|raw| Ok(crate::account_db::pairing::sanitize_backup(raw)))??;
    for table in ["pairing_full_tail_dependency", "pairing_full_tail_apply"] {
        let rows: u64 =
            db.connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(rows, 0, "test: local tail authority survived backup sanitization in {table}");
        assert!(
            crate::account_db::pairing::skip_merge(table),
            "test: incoming backup can import local tail ownership"
        );
    }
    Ok(())
}
