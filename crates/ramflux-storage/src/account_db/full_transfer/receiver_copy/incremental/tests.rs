// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real retained A/B union plus later independent B writes, without another base copy.
use super::*;
use crate::account_db::full_transfer::receiver_projection::tests::{input, seed};
use crate::{AccountDb, AccountDbKey, AccountIndex};
use ramflux_protocol::{custody::pairing::full_transfer::CHUNK_BYTES, encode_base64url};
use rusqlite::params;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn owned_db(anchor: &str, secret: &[u8]) -> TestResult<(tempfile::TempDir, AccountDb)> {
    let owner = tempfile::tempdir()?;
    let index = AccountIndex::open(owner.path())?;
    index.create_account("acct", anchor)?;
    let db = AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", secret))?;
    Ok((owner, db))
}

#[test]
fn pairing_full_fourth_rebase_keeps_union_owner_and_applies_only_b_changes() -> TestResult {
    let (initial, _, _) = crate::account_db::full_transfer::stage_tests::fixture()?;
    let (_aowner, a) = owned_db(&initial.grant.source_ref.account_anchor, b"incremental-source-a")?;
    let (_bowner, b) =
        owned_db(&initial.grant.destination_ref.account_anchor, b"incremental-original-b")?;
    seed(&a, 11, 8)?;
    seed(&b, 21, 9)?;
    let (record, manifest, bytes) =
        input(&a).map_err(|error| format!("test: incremental source input: {error}"))?;
    let hash = record.base_manifest_hash.clone();
    let mut stage = b.create_full_stage_for_test(record, 604_900)?;
    stage.retain_forward_manifest(&manifest, &manifest.manifest.families)?;
    for (index, chunk) in bytes.chunks(CHUNK_BYTES as usize).enumerate() {
        stage.retain_forward_chunk(&hash, index as u64, chunk)?;
    }
    let pinned = stage
        .pin_receiver_base(&hash)
        .map_err(|error| format!("test: incremental pin B: {error}"))?;
    let mut copy = pinned.copy().map_err(|error| format!("test: incremental copy B: {error}"))?;
    copy.project(&stage).map_err(|error| format!("test: incremental initial union: {error}"))?;
    let directory = copy.scratch.path.clone();
    let nonce = copy.union_encoding().ok_or("test: initial union missing")?.generation_nonce;
    let key = copy.key.fingerprint();
    let a_rows = source_rows(&copy)?;
    // Removing B's copy of a dependency removes only B's qualified contribution.
    b.connection.execute("DELETE FROM object_payload_dependency", [])?;
    seed(&b, 31, 10)?;
    b.connection.execute("INSERT INTO pairing_own_sync(operation_id,fingerprint,response_json,operation_kind) VALUES('b-local','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}','pairing_own_sync_v1')",[])?;
    b.with_full_transfer_install_fence(|| copy.rebase_current_target(&stage))
        .map_err(|error| format!("test: incremental retained B refresh: {error}"))?;
    assert_eq!(copy.scratch.path, directory, "test: fourth rebase allocated another full copy");
    assert_eq!(copy.key.fingerprint(), key, "test: fourth rebase generated another snapshot key");
    assert_eq!(
        copy.union_encoding().ok_or("test: rebased union missing")?.generation_nonce,
        nonce,
        "test: fourth rebase replaced union owner"
    );
    assert_eq!(source_rows(&copy)?, a_rows, "test: fourth rebase changed frozen A records");
    let private =
        BackupDatabase::open_full_receiver_copy(&directory.join("private.db"), &copy.key)?;
    let old_b = encode_base64url([21; 32]);
    let source = encode_base64url([11; 32]);
    assert!(
        !private.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_payload_dependency WHERE parent_commitment=?1)",
            params![old_b],
            |row| row.get::<_, bool>(0)
        )?,
        "test: B dependency deletion was lost"
    );
    assert!(
        private.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_payload_dependency WHERE parent_commitment=?1)",
            params![source],
            |row| row.get::<_, bool>(0)
        )?,
        "test: B deletion erased A contribution"
    );
    assert!(private.db.query_row("SELECT EXISTS(SELECT 1 FROM pairing_own_sync WHERE operation_id='b-local' AND response_json='{}')",[],|row|row.get::<_,bool>(0))?,"test: B-local sync receipt was lost");
    assert_eq!(
        private.db.query_row(
            "SELECT generation FROM account_erasure_generation WHERE singleton=1",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        10,
        "test: rebase lost new B maximum"
    );
    assert_eq!(
        b.connection.query_row("SELECT count(*) FROM object_erasure_fence", [], |row| row
            .get::<_, u64>(0))?,
        2,
        "test: private rebase mutated actual B"
    );
    copy.verify_materialization(&stage)?;
    Ok(())
}

fn source_rows(copy: &FullReceiverBaseCopy) -> TestResult<Vec<Vec<u8>>> {
    let db = crate::account_db::full_transfer::receiver_contributions::open(
        &copy.scratch.path.join("contributions.db"),
        &copy.key,
    )?;
    let mut query=db.prepare("SELECT record FROM full_union_record WHERE generation_nonce=?1 AND owner=?2 AND family!='sql/account_erasure_generation' ORDER BY family,key")?;
    Ok(query
        .query_map(
            params![copy.contributions.nonce.as_slice(), copy.contributions.owners[0]],
            |row| row.get(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}
