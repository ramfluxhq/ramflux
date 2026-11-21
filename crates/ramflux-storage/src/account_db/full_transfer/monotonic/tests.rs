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

fn seed_decisions(a: &AccountDb, b: &AccountDb) -> TestResult {
    // Both owners have the same closed state/stamp shape. Exercise each through the
    // actual encrypted source cut and generation verifier rather than a codec-only loop.
    for table in ["contact_request_decision", "contact_link_decision"] {
        for (id, left, left_at, right, right_at) in [
            (80, "blocked", 100, "lifted", 300),
            (81, "lifted", 400, "declined", 200),
            (82, "declined", 500, "blocked", 100),
            (83, "blocked", 100, "blocked", 600),
            (84, "lifted", 100, "lifted", 700),
        ] {
            let key = encode_base64url([id; 32]);
            let sql = format!("INSERT INTO {table} VALUES(?1,?2,?3)");
            a.connection.execute(&sql, params![key, left, left_at])?;
            b.connection.execute(&sql, params![key, right, right_at])?;
        }
    }
    Ok(())
}
fn inspect_decisions(private: &BackupDatabase, _: &AccountDb) -> TestResult {
    for (table, key_column) in
        [("contact_request_decision", "root"), ("contact_link_decision", "link_id")]
    {
        for (id, state, stamp) in [
            (80, "blocked", 100),
            (81, "declined", 200),
            (82, "blocked", 100),
            (83, "blocked", 600),
            (84, "lifted", 700),
        ] {
            let value = private.db.query_row(
                &format!("SELECT state,decided_at FROM {table} WHERE {key_column}=?1"),
                [encode_base64url([id; 32])],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )?;
            assert_eq!(
                value,
                (state.to_owned(), stamp),
                "test: {table} lifted an independent denial or fabricated its original decision stamp"
            );
        }
    }
    Ok(())
}
#[test]
fn full_contact_decision_owners_keep_denials_and_complete_original_stamps() -> TestResult {
    run(Case {
        name: "contact-decisions",
        seed: seed_decisions,
        before: None,
        inspect: inspect_decisions,
        conflict: false,
    })
}
#[test]
fn full_contact_unrelated_private_decision_cannot_mint_dv() -> TestResult {
    run(Case {
        name: "contact-decision-tamper",
        seed: seed_decisions,
        before: Some(|private| {
            private.db.execute("UPDATE contact_request_decision SET state='blocked',decided_at=99999 WHERE root=?1",[encode_base64url([84;32])])?;
            Ok(())
        }),
        inspect: inspect_decisions,
        conflict: true,
    })
}

#[test]
fn full_contact_delivery_keeps_qualified_recipient_and_material_evidence() -> TestResult {
    use crate::account_db::full_transfer::receiver_copy::owner_tests::{
        delivery_recipient, seed_delivery,
    };
    run(Case {
        name: "contact-delivery",
        seed: |a, b| {
            seed_delivery(a, "shared", 500)?;
            seed_delivery(b, "shared", 100)?;
            seed_delivery(a, "source", 200)?;
            seed_delivery(b, "target", 300)
        },
        before: None,
        inspect: |private, b| {
            let recipient = delivery_recipient()?;
            let mut query=private.db.prepare("SELECT request_id,recipient_identity,material_hash,submitted_at FROM contact_request_delivery ORDER BY request_id")?;
            let rows = query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let expected =
                [("shared", 500), ("source", 200), ("target", 300)].map(|(id, stamp)| {
                    (
                        id.to_owned(),
                        recipient.storage_key().to_owned(),
                        encode_base64url([92; 32]),
                        stamp,
                    )
                });
            assert_eq!(
                rows, expected,
                "test: delivery union changed qualified recipient/material or lost independent history"
            );
            assert!(
                b.contact_request_delivered("target", &recipient, &encode_base64url([92; 32]))?,
                "test: transfer changed B delivery reader"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_contact_delivery_same_recipient_different_material_refuses_before_dv() -> TestResult {
    use crate::account_db::full_transfer::receiver_copy::owner_tests::seed_delivery;
    run(Case {
        name: "contact-delivery-material-fork",
        seed: |a, b| {
            seed_delivery(a, "shared", 100)?;
            seed_delivery(b, "shared", 200)?;
            b.connection.execute(
                "UPDATE contact_request_delivery SET material_hash=?1",
                params![encode_base64url([93; 32])],
            )?;
            Ok(())
        },
        before: None,
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}

fn seed_friends(a: &AccountDb, b: &AccountDb) -> TestResult {
    a.establish_friend_link("source-only", "self", "peer-source")?;
    a.establish_friend_link("blocked", "self", "peer-blocked")?;
    b.establish_friend_link("blocked", "self", "peer-blocked")?;
    b.block_friend_link("blocked", 200)?;
    a.establish_friend_link("removed", "self", "peer-removed")?;
    b.establish_friend_link("removed", "self", "peer-removed")?;
    b.remove_friend_link("removed", "both", 300)?;
    // The secondary projection is currently history-only; native friendship uses the
    // ordinary APIs above. Give it its independent nullable restriction combinations.
    for db in [a, b] {
        db.connection.execute("INSERT INTO friend_projection VALUES('history','peer-history','accepted',NULL,NULL,NULL,100)",[])?;
    }
    b.connection.execute("UPDATE friend_projection SET link_state='removed',blocked_at=200,removed_at=300,updated_at=400",[])?;
    Ok(())
}
#[test]
fn full_contact_projection_owners_keep_friends_and_independent_removal_and_block() -> TestResult {
    run(Case {
        name: "contact-projections",
        seed: seed_friends,
        before: None,
        inspect: |private, b| {
            for (id, state, blocked, scope) in [
                ("source-only", "accepted", false, None),
                ("blocked", "blocked", true, None),
                ("removed", "removed", true, Some("both")),
            ] {
                let value=private.db.query_row("SELECT state,blocked,remove_scope FROM friend_link_projection WHERE link_id=?1",[id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,bool>(1)?,row.get::<_,Option<String>>(2)?)))?;
                assert_eq!(
                    value,
                    (state.to_owned(), blocked, scope.map(str::to_owned)),
                    "test: friend union lost source friendship or lifted B block/removal"
                );
            }
            let history=private.db.query_row("SELECT link_state,capability_id,blocked_at,removed_at,updated_at FROM friend_projection WHERE link_id='history'",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,i64>(4)?)))?;
            assert_eq!(
                history,
                ("removed".to_owned(), None, Some(200), Some(300), 400),
                "test: history owner revived a removal or adopted a capability"
            );
            assert!(
                b.friend_link("source-only").is_err(),
                "test: private import mutated live B contacts"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_contact_projection_same_link_with_different_endpoint_refuses_before_dv() -> TestResult {
    run(Case {
        name: "contact-endpoint-fork",
        seed: |a, b| {
            a.establish_friend_link("link", "self", "peer-a")?;
            b.establish_friend_link("link", "self", "peer-b")?;
            Ok(())
        },
        before: None,
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}
#[test]
fn full_contact_retained_decision_restricts_an_active_projection_before_dv() -> TestResult {
    run(Case {
        name: "contact-decision-projection-closure",
        seed: |a, b| {
            a.establish_friend_link("link", "self", "peer")?;
            b.connection
                .execute("INSERT INTO contact_link_decision VALUES('link','blocked',100000)", [])?;
            Ok(())
        },
        before: None,
        inspect: |private, _| {
            let value=private.db.query_row("SELECT state,blocked,capability_revoked_at FROM friend_link_projection WHERE link_id='link'",[],|row|Ok((row.get::<_,String>(0)?,row.get::<_,bool>(1)?,row.get::<_,Option<i64>>(2)?)))?;
            assert_eq!(
                value,
                ("blocked".to_owned(), true, Some(100)),
                "test: retained denial left an active transferred friendship"
            );
            Ok(())
        },
        conflict: false,
    })
}
