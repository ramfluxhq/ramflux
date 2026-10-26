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
