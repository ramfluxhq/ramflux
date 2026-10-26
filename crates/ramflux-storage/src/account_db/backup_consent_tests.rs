// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore preserves later consent and distinguishes replacement from erasure.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn account(
    label: &str,
) -> Result<(std::path::PathBuf, AccountIndex, AccountDb), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "backup-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::generate()?)?;
    Ok((root, index, db))
}
#[test]
fn r4_merging_an_older_block_or_decline_keeps_later_explicit_consent() -> TestResult {
    for (denied, legacy) in
        [("blocked", false), ("declined", false), ("blocked", true), ("declined", true)]
    {
        let (root, index, db) = account(denied)?;
        if denied == "blocked" {
            db.establish_friend_link("link", "own", "peer")?;
            db.block_friend_link("link", 10)?;
        } else {
            db.record_pending_friend_link("link", "own", "peer", 10)?;
            db.reject_friend_link("link", 10)?;
        }
        db.fence_contact_request("peer", denied, 0)?;
        db.connection.execute("INSERT INTO contact_request_projection VALUES('peer','inbound','req','bob','link',?1,x'7b7d',999,10)", rusqlite::params![denied])?;
        let archive = root.join("archive.db");
        let saved = db.write_backup_snapshot(&archive)?;
        if legacy {
            let old = BackupDatabase::open(&archive, &saved.key)?;
            old.db.execute_batch(
                "DROP TABLE contact_request_decision; DROP TABLE contact_link_decision;",
            )?;
        }
        db.clear_contact_request_fence("peer", None)?;
        db.clear_contact_request_fence("peer", Some("declined"))?;
        db.unblock_friend_link("link", 10)?;
        db.connection.execute_batch(
            "UPDATE contact_request_projection SET state='accepted',updated_at=10",
        )?;
        let target = root.join("current.db");
        let local = db.write_backup_snapshot(&target)?;
        let mut merged = BackupDatabase::open(&target, &local.key)?;
        for round in 0..2 {
            merged.merge_backup(&archive, &saved.key, || Ok(()))?;
            assert_eq!(merged.db.query_row("SELECT state FROM contact_request_projection WHERE contact_identity_commitment='peer'", [], |r|r.get::<_,String>(0))?, "accepted", "an older denial must not undo later consent");
            assert_eq!(
                merged.db.query_row(
                    "SELECT count(*) FROM contact_request_fence WHERE root='peer'",
                    [],
                    |r| r.get::<_, u64>(0)
                )?,
                0
            );
            assert_eq!(
                merged.db.query_row(
                    "SELECT state,blocked FROM friend_link_projection WHERE link_id='link'",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                )?,
                ("accepted".into(), false)
            );
            if round == 0 {
                drop(merged);
                merged = BackupDatabase::open(&target, &local.key)?;
            }
        }
        drop(merged);
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn r4_newer_restored_lifts_and_denials_win_in_both_merge_directions() -> TestResult {
    let (root, index, db) = account("ordered-consent")?;
    db.establish_friend_link("link", "own", "peer")?;
    db.block_friend_link("link", 10)?;
    db.fence_contact_request("peer", "blocked", 0)?;
    db.connection.execute_batch("INSERT INTO contact_request_projection VALUES('peer','inbound','request','bob','link','blocked',x'7b7d',999,10)")?;
    let blocked = root.join("blocked.db");
    let old = db.write_backup_snapshot(&blocked)?;
    db.unblock_friend_link("link", 10)?;
    db.clear_contact_request_fence("peer", None)?;
    db.connection.execute_batch("UPDATE contact_request_projection SET state='accepted'")?;
    let accepted = root.join("accepted.db");
    let lifted = db.write_backup_snapshot(&accepted)?;
    let mut merged = BackupDatabase::open(&blocked, &old.key)?;
    merged.merge_backup(&accepted, &lifted.key, || Ok(()))?;
    assert_eq!(
        merged.db.query_row("SELECT state FROM contact_request_projection", [], |r| r
            .get::<_, String>(0))?,
        "accepted"
    );
    assert_eq!(
        merged
            .db
            .query_row("SELECT state FROM friend_link_projection", [], |r| r.get::<_, String>(0))?,
        "accepted"
    );
    db.block_friend_link("link", 10)?;
    db.fence_contact_request("peer", "blocked", 0)?;
    db.connection.execute_batch("UPDATE contact_request_projection SET state='blocked'")?;
    let denied = root.join("new-block.db");
    let new = db.write_backup_snapshot(&denied)?;
    merged.merge_backup(&denied, &new.key, || Ok(()))?;
    assert_eq!(
        merged.db.query_row("SELECT state FROM contact_request_projection", [], |r| r
            .get::<_, String>(0))?,
        "blocked"
    );
    assert_eq!(
        merged
            .db
            .query_row("SELECT state FROM friend_link_projection", [], |r| r.get::<_, String>(0))?,
        "blocked"
    );
    drop(merged);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn merge_prefers_restrictions_on_tied_link_and_request_decisions_and_newer_otherwise() -> TestResult
{
    // (incoming denial, incoming stamp, live lift stamp, expected merged request state)
    for (denied, denied_at, lifted_at, expected) in [
        ("blocked", 7_000, 7_000, "blocked"),
        ("declined", 7_000, 7_000, "declined"),
        ("blocked", 7_001, 7_000, "blocked"),
        ("blocked", 7_000, 7_001, "accepted"),
        ("declined", 7_001, 7_000, "declined"),
        ("declined", 7_000, 7_001, "accepted"),
    ] {
        let (source_root, source_index, source) = account("tie-source")?;
        let (root, index, local) = account("tie-local")?;
        local.establish_friend_link("link", "own", "peer")?;
        if denied == "blocked" {
            source.establish_friend_link("link", "own", "peer")?;
            source.block_friend_link("link", 10)?;
        } else {
            source.record_pending_friend_link("link", "own", "peer", 10)?;
            source.reject_friend_link("link", 10)?;
        }
        source.connection.execute(
            "UPDATE contact_link_decision SET decided_at=?1 WHERE link_id='link'",
            rusqlite::params![denied_at],
        )?;
        local.connection.execute(
            "UPDATE contact_link_decision SET decided_at=?1 WHERE link_id='link'",
            rusqlite::params![lifted_at],
        )?;
        local.connection.execute_batch("UPDATE friend_link_projection SET updated_at=10")?;
        source.fence_contact_request("peer", denied, 0)?;
        source.connection.execute("INSERT INTO contact_request_projection VALUES('peer','inbound','req','bob','link',?1,x'7b7d',999,10)", rusqlite::params![denied])?;
        local.fence_contact_request("peer", denied, 0)?;
        local.clear_contact_request_fence("peer", None)?;
        local.connection.execute_batch("INSERT INTO contact_request_projection VALUES('peer','inbound','req','bob','link','accepted',x'7b7d',999,10)")?;
        // Pin the wall-clock decision stamps so a same-millisecond tie is exercised exactly.
        source.connection.execute(
            "UPDATE contact_request_decision SET decided_at=?1 WHERE root='peer'",
            rusqlite::params![denied_at],
        )?;
        local.connection.execute(
            "UPDATE contact_request_decision SET decided_at=?1 WHERE root='peer' AND state='lifted'",
            rusqlite::params![lifted_at],
        )?;
        for reverse in [false, true] {
            let (incoming, live_db) = if reverse { (&local, &source) } else { (&source, &local) };
            let archive = source_root.join(format!("archive-{reverse}.db"));
            let saved = incoming.write_backup_snapshot(&archive)?;
            let target = root.join(format!("current-{reverse}.db"));
            let live = live_db.write_backup_snapshot(&target)?;
            let mut merged = BackupDatabase::open(&target, &live.key)?;
            let case = format!("{denied}@{denied_at} vs lifted@{lifted_at}, reverse={reverse}");
            for _ in 0..2 {
                merged.merge_backup(&archive, &saved.key, || Ok(()))?;
                assert_eq!(merged.db.query_row("SELECT state FROM contact_request_projection WHERE contact_identity_commitment='peer'", [], |r|r.get::<_,String>(0))?, expected, "{case}");
                let decision = if expected == "accepted" { "lifted" } else { denied };
                assert_eq!(
                    merged.db.query_row(
                        "SELECT state FROM contact_request_decision WHERE root='peer'",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    decision,
                    "{case}"
                );
                assert_eq!(
                    merged.db.query_row(
                        "SELECT state FROM contact_link_decision WHERE link_id='link'",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    decision,
                    "{case}"
                );
                let link_state = match expected {
                    "declined" => "rejected",
                    other => other,
                };
                assert_eq!(
                    merged.db.query_row(
                        "SELECT state,blocked FROM friend_link_projection WHERE link_id='link'",
                        [],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                    )?,
                    (link_state.into(), expected == "blocked"),
                    "{case}"
                );
                let fences: u64 = merged.db.query_row(
                    "SELECT count(*) FROM contact_request_fence WHERE root='peer'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(fences, u64::from(expected != "accepted"), "{case}");
            }
        }
        drop(source);
        drop(local);
        drop(source_index);
        drop(index);
        std::fs::remove_dir_all(source_root)?;
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
#[test]
fn r4_merge_replacement_of_a_newer_held_message_does_not_create_an_erasure_fence() -> TestResult {
    let (root, index, db) = account("held-replacement")?;
    db.connection.execute_batch("INSERT INTO contact_message_request VALUES('peer','sender','message','thread',x'7b7d',2,999,2)")?;
    let archive = root.join("archive.db");
    let saved = db.write_backup_snapshot(&archive)?;
    db.connection.execute_batch("UPDATE contact_message_request SET created_at=1")?;
    let target = root.join("current.db");
    let local = db.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &local.key)?;
    merged.merge_backup(&archive, &saved.key, || Ok(()))?;
    assert_eq!(merged.db.query_row("SELECT count(*) FROM contact_message_request WHERE message_id='message' AND created_at=2", [], |r|r.get::<_,u64>(0))?, 1);
    assert_eq!(
        merged.db.query_row("SELECT count(*) FROM contact_message_request_fence", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    drop(merged);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn r4_expired_held_message_erasure_fences_are_pruned_while_recent_fences_remain() -> TestResult {
    let (root, index, db) = account("held-retention")?;
    db.connection.execute_batch("INSERT INTO contact_message_request VALUES('old','sender','expired','thread',x'7b7d',2,200,100); INSERT INTO contact_message_request VALUES('new','sender','recent','thread',x'7b7d',2,900000,800000)")?;
    db.discard_contact_messages("old")?;
    db.discard_contact_messages("new")?;
    db.prune_contact_request_fences_and_previews(800_001)?;
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM contact_message_request_fence WHERE message_id='expired'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(
        db.connection.query_row(
            "SELECT count(*) FROM contact_message_request_fence WHERE message_id='recent'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn merge_clamps_link_projection_to_restrictive_decision_despite_projection_clock_order()
-> TestResult {
    for denied in ["blocked", "declined"] {
        for (denied_at, lifted_at, expected) in
            [(7_000, 7_000, denied), (7_001, 7_000, denied), (7_000, 7_001, "lifted")]
        {
            let (root, index, source) = account("link-clock-source")?;
            let (local_root, local_index, local) = account("link-clock-local")?;
            if denied == "blocked" {
                source.establish_friend_link("link", "own", "peer")?;
                source.block_friend_link("link", 1)?;
            } else {
                source.record_pending_friend_link("link", "own", "peer", 1)?;
                source.reject_friend_link("link", 1)?;
            }
            local.establish_friend_link("link", "own", "peer")?;
            source.connection.execute(
                "UPDATE contact_link_decision SET decided_at=?1",
                rusqlite::params![denied_at],
            )?;
            local.connection.execute(
                "UPDATE contact_link_decision SET decided_at=?1",
                rusqlite::params![lifted_at],
            )?;
            // Projection clocks may order the rows opposite to their explicit decisions.
            local.connection.execute_batch("UPDATE friend_link_projection SET updated_at=100")?;
            for reverse in [false, true] {
                let (incoming, live) = if reverse { (&local, &source) } else { (&source, &local) };
                let archive = root.join(format!("incoming-{reverse}.db"));
                let saved = incoming.write_backup_snapshot(&archive)?;
                let target = local_root.join(format!("merged-{reverse}.db"));
                let snapshot = live.write_backup_snapshot(&target)?;
                let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
                for _ in 0..2 {
                    merged.merge_backup(&archive, &saved.key, || Ok(()))?;
                    let case =
                        format!("{denied}@{denied_at} vs lift@{lifted_at}, reverse={reverse}");
                    assert_eq!(
                        merged.db.query_row(
                            "SELECT state FROM contact_link_decision",
                            [],
                            |r| r.get::<_, String>(0)
                        )?,
                        expected,
                        "{case}"
                    );
                    let state = match expected {
                        "lifted" => "accepted",
                        "declined" => "rejected",
                        other => other,
                    };
                    assert_eq!(
                        merged.db.query_row(
                            "SELECT state,blocked FROM friend_link_projection",
                            [],
                            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                        )?,
                        (state.into(), expected == "blocked"),
                        "{case}"
                    );
                    if expected == "blocked" {
                        assert!(merged.db.query_row("SELECT capability_revoked_at IS NOT NULL FROM friend_link_projection", [], |r| r.get::<_, bool>(0))?, "{case}");
                    }
                }
            }
            drop(source);
            drop(local);
            drop(index);
            drop(local_index);
            std::fs::remove_dir_all(root)?;
            std::fs::remove_dir_all(local_root)?;
        }
    }
    Ok(())
}

#[test]
fn merge_preserves_removed_links_for_block_and_decline_in_both_directions() -> TestResult {
    for denied in ["blocked", "declined"] {
        let (removed_root, removed_index, removed) = account("removed-link")?;
        let (other_root, other_index, other) = account("unrelated-link")?;
        if denied == "blocked" {
            removed.establish_friend_link("removed", "own", "peer")?;
            removed.block_friend_link("removed", 11)?;
        } else {
            removed.record_pending_friend_link("removed", "peer", "own", 10)?;
            removed.reject_friend_link("removed", 11)?;
        }
        removed.remove_friend_link("removed", "both", 12)?;
        other.establish_friend_link("unrelated", "own", "other-peer")?;
        let expected = removed.connection.query_row(
            "SELECT state,remove_scope,blocked,capability_revoked_at,updated_at
             FROM friend_link_projection WHERE link_id='removed'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )?;
        assert_eq!(expected.0, "removed");
        assert_eq!(expected.2, denied == "blocked");

        for reverse in [false, true] {
            let (incoming, live) = if reverse { (&removed, &other) } else { (&other, &removed) };
            let archive = removed_root.join(format!("removed-incoming-{denied}-{reverse}.db"));
            let saved = incoming.write_backup_snapshot(&archive)?;
            let target = other_root.join(format!("removed-live-{denied}-{reverse}.db"));
            let local = live.write_backup_snapshot(&target)?;
            let mut merged = BackupDatabase::open(&target, &local.key)?;
            for round in 0..2 {
                merged.merge_backup(&archive, &saved.key, || Ok(()))?;
                let actual = merged.db.query_row(
                    "SELECT state,remove_scope,blocked,capability_revoked_at,updated_at
                     FROM friend_link_projection WHERE link_id='removed'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, Option<i64>>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )?;
                assert_eq!(actual, expected, "{denied}, reverse={reverse}, round={round}");
                assert_eq!(
                    merged.db.query_row(
                        "SELECT state FROM friend_link_projection WHERE link_id='unrelated'",
                        [],
                        |row| row.get::<_, String>(0)
                    )?,
                    "accepted",
                    "{denied}, reverse={reverse}, round={round}"
                );
            }
        }
        drop(removed);
        drop(other);
        drop(removed_index);
        drop(other_index);
        std::fs::remove_dir_all(removed_root)?;
        std::fs::remove_dir_all(other_root)?;
    }
    Ok(())
}

#[path = "backup_legacy_consent_tests.rs"]
mod legacy;
