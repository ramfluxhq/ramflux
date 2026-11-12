// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local adoption receipts only. This does not verify a union or select a generation.
use super::helpers::{TestResult, adoption, h};
use rusqlite::params;

#[test]
fn pairing_full_adoption_receipt_is_paired_immutable_and_survives_authority_refresh() -> TestResult
{
    let (_root, db) = crate::tests::test_db("pair-full-adoption")?;
    let legacy = adoption("primary", Some("primary"))?;
    db.put_pairing_adoption(&legacy)?;
    assert_eq!(db.pairing_adoption()?, Some(legacy.clone()));
    let mut full = legacy.clone();
    full.full_generation_nonce = Some(h(5));
    assert!(db.put_pairing_adoption(&full).is_err(), "half receipt accepted");
    full.full_initial_union_root = Some(h(6));
    db.put_pairing_adoption(&full)?;
    db.put_pairing_adoption(&full)?;
    for change_nonce in [false, true] {
        let mut wrong = full.clone();
        wrong.record_hash = h(77);
        if change_nonce {
            wrong.full_generation_nonce = Some(h(8));
        } else {
            wrong.full_initial_union_root = Some(h(9));
        }
        assert!(
            matches!(
                db.put_pairing_adoption(&wrong),
                Err(crate::StorageError::PairingField("full_generation"))
            ),
            "replaced immutable receipt"
        );
        assert_eq!(db.pairing_adoption()?, Some(full.clone()), "refusal changed ordinary adoption");
    }
    let mut refreshed = legacy;
    refreshed.record_hash = h(10);
    refreshed.local_role = "secondary".into();
    refreshed.primary_vault_ref = None;
    db.put_pairing_adoption(&refreshed)?;
    refreshed.full_generation_nonce = full.full_generation_nonce;
    refreshed.full_initial_union_root = full.full_initial_union_root;
    assert_eq!(
        db.pairing_adoption()?,
        Some(refreshed),
        "legacy refresh dropped initial generation receipt"
    );
    assert!(
        db.connection
            .execute("UPDATE pairing_adoption SET full_generation_nonce=NULL", [])
            .is_err(),
        "SQL allowed half receipt"
    );
    Ok(())
}

#[test]
fn pairing_full_adoption_migrates_existing_rows_without_fabricating_generation_receipt()
-> TestResult {
    let (_root, db) = crate::tests::test_db("pair-full-adoption-migration")?;
    let old = super::super::schema::SCHEMA
        .lines()
        .filter(|line| {
            !line.contains("full_generation_nonce") && !line.contains("full_initial_union_root")
        })
        .collect::<Vec<_>>()
        .join("\n");
    db.connection.execute_batch("DROP TABLE pairing_adoption;")?;
    db.connection.execute_batch(&old)?;
    let row = adoption("secondary", None)?;
    db.connection.execute(
        "INSERT INTO pairing_adoption VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            row.account_id,
            row.operation_id,
            row.record_hash,
            row.local_ref,
            row.local_role,
            row.branch_vault_ref,
            row.data_vault_ref,
            row.primary_vault_ref
        ],
    )?;
    db.connection.call(|db| super::super::schema::install(db))?;
    db.connection.call(|db| super::super::schema::install(db))?;
    assert_eq!(db.pairing_adoption()?, Some(row));
    assert!(
        db.connection
            .execute("UPDATE pairing_adoption SET full_generation_nonce=?1", params![h(7)])
            .is_err(),
        "migrated SQL allowed half receipt"
    );
    Ok(())
}
