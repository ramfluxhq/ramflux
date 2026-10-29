// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Data merge and live-chain preservation regressions against encrypted generations.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex, EventStore};
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn backup_merge_preserves_newer_restrictions_plaintext_and_live_outbound_state() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-merge-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    index.create_account("source", "root")?;
    local_index.create_account("local", "root")?;
    let source_key = AccountDbKey::generate()?;
    let local_key = AccountDbKey::generate()?;
    let source = AccountDb::open(&index, "source", &source_key)?;
    let local = AccountDb::open(&local_index, "local", &local_key)?;
    source.establish_friend_link("link", "own", "peer")?;
    local.establish_friend_link("link", "own", "peer")?;
    local.block_friend_link("link", i64::MAX - 1)?;
    source.persist_actor_state("dm-pair/active/local", &"stale")?;
    local.persist_actor_state("dm-pair/active/local", &"live")?;
    source.persist_actor_state("dm-pair/session/new", &serde_json::json!({"secret":"archive"}))?;
    source.persist_actor_state("surface/state/new", &serde_json::json!({"revision":4}))?;
    local.persist_actor_state("surface/state/old", &serde_json::json!({"revision":9}))?;
    source.persist_actor_state("surface/state/old", &serde_json::json!({"revision":2}))?;
    source.store_message_content("thread", "message", b"all historical plaintext")?;
    source.append_event(
        "source-only-counter",
        "test.history",
        b"preserved despite actor-counter collision",
    )?;
    local.append_event("local-counter", "test.history", b"live event at the same counter")?;
    source.create_group("membership", "owner")?;
    source.add_group_member("membership", "peer", "member")?;
    local.create_group("membership", "owner")?;
    local.add_group_member("membership", "peer", "member")?;
    local.connection.execute_batch("UPDATE group_projection SET group_epoch=3 WHERE group_id='membership'; UPDATE group_member_projection SET active=0,removed_epoch=3 WHERE group_id='membership' AND member_id='peer';")?;
    source.create_group("new-membership", "owner")?;
    source.add_group_member("new-membership", "peer", "member")?;
    local.create_group("new-membership", "owner")?;
    stage_link_consent_order(&source, &local)?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let target = root.join("merged.db");
    let copied = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &copied.key)?;
    let report = merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(report.kept_newer.contacts, 1);
    assert_eq!(
        merged.db.query_row(
            "SELECT state FROM friend_link_projection WHERE link_id='link'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "blocked"
    );
    assert_eq!(merged.db.query_row("SELECT CAST(state_json AS TEXT) FROM runtime_actor_state WHERE state_kind='dm-pair/active/local'",[],|r|r.get::<_,String>(0))?,"\"live\"");
    assert_eq!(
        merged.db.query_row(
            "SELECT CAST(body AS TEXT) FROM runtime_message_content WHERE message_id='message'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "all historical plaintext"
    );
    assert!(merged.db.query_row("SELECT CAST(state_json AS TEXT) FROM runtime_actor_state WHERE state_kind='backup/inactive-pair/new'",[],|r|r.get::<_,String>(0))?.parse::<u64>()?>0);
    assert_eq!(merged.db.query_row("SELECT json_extract(CAST(state_json AS TEXT),'$.revision') FROM runtime_actor_state WHERE state_kind='surface/state/old'",[],|r|r.get::<_,u64>(0))?,9);
    assert_eq!(merged.db.query_row("SELECT CAST(event_body AS TEXT) FROM backup_archived_local_event WHERE event_id='source-only-counter'",[],|r|r.get::<_,String>(0))?,"preserved despite actor-counter collision");
    assert!(!merged.db.query_row("SELECT active FROM group_member_projection WHERE group_id='membership' AND member_id='peer'",[],|r|r.get::<_,bool>(0))?);
    assert!(merged.db.query_row("SELECT active FROM group_member_projection WHERE group_id='new-membership' AND member_id='peer'",[],|r|r.get::<_,bool>(0))?);
    assert_link_consent_order(&merged.db)?;
    merged.check_integrity()?;
    drop(merged);
    drop(source);
    drop(local);
    drop(index);
    drop(local_index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// Same-root decisions on one tie and two strictly ordered links, with pinned stamps.
fn stage_link_consent_order(source: &AccountDb, local: &AccountDb) -> TestResult {
    // Decision stamps are wall-clock milliseconds; pin them so the tie and both strict
    // orders are exercised deterministically instead of depending on runner speed.
    for (link, blocked_at, lifted_at) in
        [("tie-link", 5_000, 5_000), ("block-newer", 5_001, 5_000), ("lift-newer", 5_000, 5_001)]
    {
        source.establish_friend_link(link, "own", "tie-peer")?;
        local.establish_friend_link(link, "own", "tie-peer")?;
        source.block_friend_link(link, 1)?;
        local.connection.execute(
            "UPDATE friend_link_projection SET updated_at=1 WHERE link_id=?1",
            rusqlite::params![link],
        )?;
        source.connection.execute(
            "UPDATE contact_link_decision SET decided_at=?2 WHERE link_id=?1 AND state='blocked'",
            rusqlite::params![link, blocked_at],
        )?;
        local.connection.execute(
            "UPDATE contact_link_decision SET decided_at=?2 WHERE link_id=?1 AND state='lifted'",
            rusqlite::params![link, lifted_at],
        )?;
    }
    Ok(())
}
fn assert_link_consent_order(db: &rusqlite::Connection) -> TestResult {
    let blocked = |link: &str| {
        db.query_row("SELECT blocked FROM friend_link_projection WHERE link_id=?1", [link], |r| {
            r.get::<_, bool>(0)
        })
    };
    assert!(blocked("tie-link")?, "a block tied with a lift must not be dropped");
    assert!(blocked("block-newer")?, "a strictly newer block wins");
    assert!(!blocked("lift-newer")?, "a strictly newer lift wins");
    assert_eq!(
        db.query_row(
            "SELECT group_concat(link_id||'='||state,',') FROM (SELECT * FROM contact_link_decision WHERE link_id IN ('tie-link','block-newer','lift-newer') ORDER BY link_id)",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "block-newer=blocked,lift-newer=lifted,tie-link=blocked"
    );
    Ok(())
}

#[test]
fn merge_applies_tombstones_and_newer_receipts_without_resurrecting_plaintext() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-merge-deletion-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "root")?;
    local_index.create_account("account", "root")?;
    let source_key = AccountDbKey::generate()?;
    let local_key = AccountDbKey::generate()?;
    let source = AccountDb::open(&source_index, "account", &source_key)?;
    let local = AccountDb::open(&local_index, "account", &local_key)?;
    for db in [&source, &local] {
        db.upsert_device_directory_entry("sender", "root", "verified-own-device", 1)?;
        for id in ["source-deleted", "local-deleted", "last"] {
            db.import_direct_message_projection(crate::DirectMessageWrite {
                conversation_id: "thread",
                message_id: id,
                sender_id: "sender",
                encrypted_body: b"ciphertext",
                metadata: &crate::MessageMetadata::default(),
                created_at: 1,
            })?;
            db.store_message_content("thread", id, b"historical plaintext")?;
        }
    }
    source.persist_actor_state(
        "directory/conversation/empty-group-thread",
        &serde_json::json!({"id":"empty-group-thread","kind":"group"}),
    )?;
    source.delete_direct_message("thread", "source-deleted", "me", "source-tombstone")?;
    local.delete_direct_message("thread", "local-deleted", "me", "local-tombstone")?;
    source.connection.execute_batch(
        "INSERT INTO conversation_read_state VALUES('thread','reader','last',20);",
    )?;
    local.connection.execute_batch(
        "INSERT INTO conversation_read_state VALUES('thread','reader','last',10);",
    )?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    let report = merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(snapshot.counts.conversations, 2);
    assert_eq!(report.restored.conversations, 2);
    assert_eq!(report.kept_newer.conversations, 0);
    assert_eq!(merged.counts()?.conversations, 2);
    assert_eq!(merged.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id IN ('source-deleted','local-deleted') AND deleted=1",[],|r|r.get::<_,u64>(0))?,2);
    assert_eq!(merged.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id IN ('source-deleted','local-deleted') AND sender_id='' AND length(encrypted_body)=0 AND metadata_json=x'7b7d'",[],|r|r.get::<_,u64>(0))?,2);
    assert_eq!(merged.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id IN ('source-deleted','local-deleted') AND is_own=1",[],|r|r.get::<_,u64>(0))?,2);
    assert_eq!(merged.db.query_row("SELECT count(*) FROM runtime_message_content WHERE message_id IN ('source-deleted','local-deleted')",[],|r|r.get::<_,u64>(0))?,0);
    assert_eq!(
        merged.db.query_row(
            "SELECT read_at FROM conversation_read_state WHERE reader_id='reader'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        20
    );
    assert!(
        local.message_content("source-deleted")?.is_some(),
        "merging a private generation must not mutate the live account"
    );
    drop(merged);
    let reopened = BackupDatabase::open(&path, &target.key)?;
    assert_eq!(reopened.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id IN ('source-deleted','local-deleted') AND sender_id='' AND length(encrypted_body)=0 AND metadata_json=x'7b7d'",[],|r|r.get::<_,u64>(0))?,2);
    drop(reopened);
    drop(source);
    drop(local);
    drop(source_index);
    drop(local_index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn r2_merge_never_imports_restore_flags_or_marks_existing_local_sessions_inactive() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-flags-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let si = AccountIndex::open(root.join("source"))?;
    let li = AccountIndex::open(root.join("local"))?;
    si.create_account("a", "root")?;
    li.create_account("a", "root")?;
    let source = AccountDb::open(&si, "a", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&li, "a", &AccountDbKey::generate()?)?;
    for name in [
        "backup/reestablishing",
        "backup/fresh-outbound",
        "backup/previous-device-epoch",
        "backup/inactive-pair/live",
    ] {
        source.persist_actor_state(name, &true)?;
    }
    source.persist_actor_state("dm-pair/session/live", &serde_json::json!({"secret":"old"}))?;
    local.persist_actor_state("dm-pair/session/live", &serde_json::json!({"secret":"live"}))?;
    local.persist_actor_state("dm-pair/active/pair", &"live")?;
    source.persist_actor_state(
        "dm-pair/session/retired",
        &serde_json::json!({"secret":"retired key"}),
    )?;
    local.persist_actor_state("dm-pair/retired/retired", &serde_json::json!({"retired_at":1}))?;
    let path = root.join("incoming.db");
    let saved = source.write_backup_snapshot(&path)?;
    let target = root.join("target.db");
    let snapshot = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
    merged.merge_backup(&path, &saved.key, || Ok(()))?;
    let flags: u64 = merged.db.query_row(
        "SELECT count(*) FROM runtime_actor_state WHERE state_kind LIKE 'backup/%'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(flags, 0, "merge must not copy source restore state or poison live sessions");
    assert_eq!(
        merged.db.query_row(
            "SELECT count(*) FROM runtime_actor_state WHERE state_kind='dm-pair/session/retired'",
            [],
            |r| r.get::<_, u64>(0)
        )?,
        0
    );
    assert_eq!(merged.db.query_row("SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='dm-pair/session/retired'",[],|r|r.get::<_,u64>(0))?,0);
    drop(merged);
    drop(source);
    drop(local);
    drop(si);
    drop(li);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_tombstone_classifies_only_devices_under_the_local_account_root() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-own-classifier-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let source_index = AccountIndex::open(root.join("source"))?;
    let local_index = AccountIndex::open(root.join("local"))?;
    source_index.create_account("account", "own-root")?;
    local_index.create_account("account", "own-root")?;
    let source = AccountDb::open(&source_index, "account", &AccountDbKey::generate()?)?;
    let local = AccountDb::open(&local_index, "account", &AccountDbKey::generate()?)?;
    local.upsert_device_directory_entry("peer-device", "peer-root", "verified-peer", 1)?;
    local.upsert_device_directory_entry("sibling-device", "own-root", "verified-own-device", 1)?;
    for (id, sender) in [("peer-message", "peer-device"), ("sibling-message", "sibling-device")] {
        local.send_direct_message("thread", id, sender, b"ciphertext")?;
        source.send_direct_message("thread", id, "unknown-sender", b"ciphertext")?;
        source.delete_direct_message("thread", id, "me", &format!("delete-{id}"))?;
    }
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let path = root.join("merged.db");
    let target = local.write_backup_snapshot(&path)?;
    let mut merged = BackupDatabase::open(&path, &target.key)?;
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    for (id, expected_own) in [("peer-message", 0_i64), ("sibling-message", 1_i64)] {
        let stored: (i64, String, i64) = merged.db.query_row(
            "SELECT is_own,sender_id,deleted FROM direct_message_projection WHERE message_id=?1",
            rusqlite::params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        assert_eq!(stored, (expected_own, String::new(), 1), "{id}");
    }
    drop(merged);
    let reopened = BackupDatabase::open(&path, &target.key)?;
    assert_eq!(
        reopened.db.query_row(
            "SELECT is_own FROM direct_message_projection WHERE message_id='peer-message'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    drop(reopened);
    drop(source);
    drop(local);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
