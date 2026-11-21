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
        params![root()],
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

#[test]
fn full_contact_message_fences_preserve_composite_keys_and_retention() -> TestResult {
    run(Case {
        name: "contact-message-fences",
        seed: |a, b| {
            for db in [a, b] {
                db.connection.execute(
                    "INSERT INTO contact_message_request_fence VALUES('sender','message')",
                    [],
                )?;
            }
            a.connection.execute(
                "INSERT INTO contact_message_request_fence VALUES('sender','another')",
                [],
            )?;
            a.connection.execute(
                "INSERT INTO contact_message_fence_retention VALUES('sender','message',2000)",
                [],
            )?;
            b.connection.execute(
                "INSERT INTO contact_message_fence_retention VALUES('sender','message',3000)",
                [],
            )?;
            Ok(())
        },
        before: None,
        inspect: |private, b| {
            assert_eq!(
                private.db.query_row(
                    "SELECT count(*) FROM contact_message_request_fence",
                    [],
                    |row| row.get::<_, u64>(0)
                )?,
                2,
                "test: composite keys collided or source-only denial disappeared"
            );
            assert_eq!(private.db.query_row("SELECT until FROM contact_message_fence_retention WHERE sender_identity='sender' AND message_id='message'", [], |row|row.get::<_,i64>(0))?, 3000, "test: B longer denial expired early");
            assert_eq!(
                b.connection.query_row(
                    "SELECT count(*) FROM contact_message_request_fence",
                    [],
                    |row| row.get::<_, u64>(0)
                )?,
                1,
                "test: private import touched live B"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_contact_retirement_preserves_both_directions_and_later_delay() -> TestResult {
    run(Case {
        name: "contact-retirement",
        seed: |a, b| {
            a.defer_contact_request_retirement(&root(), "inbound", 1000)?;
            a.defer_contact_request_retirement(&root(), "outbound", 2000)?;
            b.defer_contact_request_retirement(&root(), "inbound", 3000)?;
            Ok(())
        },
        before: None,
        inspect: |private, _| {
            let mut query = private.db.prepare(
                "SELECT direction,next_at FROM contact_request_retirement ORDER BY direction",
            )?;
            let values = query
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                values,
                vec![("inbound".to_owned(), 3000), ("outbound".to_owned(), 2000)],
                "test: direction keys or maximum retirement delay lost"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_contact_request_denial_keeps_block_and_indefinite_lifetime() -> TestResult {
    run(Case {
        name: "contact-denial",
        seed: |a, b| {
            a.connection.execute(
                "INSERT INTO contact_request_fence VALUES(?1,'declined',0)",
                params![root()],
            )?;
            b.connection.execute(
                "INSERT INTO contact_request_fence VALUES(?1,'blocked',5000)",
                params![root()],
            )?;
            Ok(())
        },
        before: None,
        inspect: |private, _| {
            let value = private.db.query_row(
                "SELECT state,until FROM contact_request_fence WHERE root=?1",
                params![root()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?;
            assert_eq!(
                value,
                ("blocked".to_owned(), 0),
                "test: union weakened block or permanent lifetime"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_contact_request_denial_variable_length_state_and_large_key_round_trip() -> TestResult {
    run(Case {
        name: "contact-denial-variable-state",
        seed: |a, b| {
            a.connection.execute(
                "INSERT INTO contact_request_fence VALUES(?1,'blocked',3000)",
                params![root()],
            )?;
            b.connection.execute(
                "INSERT INTO contact_request_fence VALUES(?1,'declined',2000)",
                params![root()],
            )?;
            a.connection.execute(
                "INSERT INTO contact_message_request_fence VALUES(?1,'message')",
                params!["sender".repeat(1000)],
            )?;
            Ok(())
        },
        before: None,
        inspect: |private, _| {
            let value = private.db.query_row(
                "SELECT state,until FROM contact_request_fence WHERE root=?1",
                params![root()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?;
            assert_eq!(
                value,
                ("blocked".to_owned(), 3000),
                "test: variable-length state replacement corrupted later integer"
            );
            assert_eq!(
                private.db.query_row(
                    "SELECT length(sender_identity) FROM contact_message_request_fence",
                    [],
                    |row| row.get::<_, u64>(0)
                )?,
                6000,
                "test: valid bounded key was truncated"
            );
            Ok(())
        },
        conflict: false,
    })
}

#[test]
fn full_contact_untimed_fence_cannot_acquire_other_devices_expiry() -> TestResult {
    run(Case {
        name: "contact-fence-lifetime-conflict",
        seed: |a, b| {
            for db in [a, b] {
                db.connection.execute(
                    "INSERT INTO contact_message_request_fence VALUES('sender','message')",
                    [],
                )?;
            }
            b.connection.execute(
                "INSERT INTO contact_message_fence_retention VALUES('sender','message',3000)",
                [],
            )?;
            Ok(())
        },
        before: None,
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}
