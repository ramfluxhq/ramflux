// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source cuts, independent B restrictions, actual materialization and unsafe-private refusals.
use super::*;
use crate::AccountDb;
use crate::account_db::full_transfer::receiver_copy::owner_tests::{Case, TestResult, run};
use ramflux_protocol::encode_base64url;
fn root() -> String {
    encode_base64url([71; 32])
}
fn seed_floors(a: &AccountDb, b: &AccountDb) -> TestResult {
    assert!(
        a.retain_contact_request_authority_floor(
            &root(),
            2,
            &encode_base64url([72; 32]),
            1900,
            1000
        )?,
        "test: ordinary source authority-floor writer refused fixture"
    );
    assert!(
        b.retain_contact_request_authority_floor(
            &root(),
            3,
            &encode_base64url([73; 32]),
            1800,
            1000
        )?,
        "test: ordinary target authority-floor writer refused fixture"
    );
    Ok(())
}
fn inspect_floor(private: &BackupDatabase, b: &AccountDb) -> TestResult {
    let row: (u64, String, i64) = private.db.query_row(
        "SELECT epoch,record_hash,until FROM contact_request_authority_floor WHERE root=?1",
        [root()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        row,
        (3, encode_base64url([73; 32]), 1900),
        "test: transfer lost independent B epoch/hash or source's longer denial lifetime"
    );
    assert_eq!(
        b.contact_request_authority_floor(&root(), 1000)?,
        Some((3, encode_base64url([73; 32]))),
        "test: private union mutated the live target floor"
    );
    Ok(())
}
#[test]
fn full_monotonic_contact_floor_round_trip_preserves_epoch_hash_and_lifetime() -> TestResult {
    run(Case {
        name: "contact-floor",
        seed: seed_floors,
        before: None,
        inspect: inspect_floor,
        conflict: false,
    })
}
#[test]
fn full_monotonic_contact_floor_same_epoch_fork_refuses_before_dv() -> TestResult {
    run(Case {
        name: "contact-floor-fork",
        seed: |a, b| {
            seed_floors(a, b)?;
            a.connection.execute("UPDATE contact_request_authority_floor SET epoch=3", [])?;
            Ok(())
        },
        before: None,
        inspect: inspect_floor,
        conflict: true,
    })
}
#[test]
fn full_monotonic_private_floor_not_derived_from_inputs_cannot_mint_dv() -> TestResult {
    run(Case {
        name: "contact-floor-tamper",
        seed: seed_floors,
        before: Some(|private| {
            private.db.execute("UPDATE contact_request_authority_floor SET epoch=99", [])?;
            Ok(())
        }),
        inspect: inspect_floor,
        conflict: true,
    })
}
#[test]
fn full_monotonic_private_generation_not_derived_from_inputs_cannot_mint_dv() -> TestResult {
    run(Case {
        name: "erasure-generation-tamper",
        seed: |a, b| {
            a.connection.execute("UPDATE account_erasure_generation SET generation=8", [])?;
            b.connection.execute("UPDATE account_erasure_generation SET generation=9", [])?;
            Ok(())
        },
        before: Some(|private| {
            private.db.execute("UPDATE account_erasure_generation SET generation=999", [])?;
            Ok(())
        }),
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}
