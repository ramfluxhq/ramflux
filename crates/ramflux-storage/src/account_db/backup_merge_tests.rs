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
    source.establish_friend_link("tie-link", "own", "tie-peer")?;
    local.establish_friend_link("tie-link", "own", "tie-peer")?;
    source.block_friend_link("tie-link", 1)?;
    local
        .connection
        .execute_batch("UPDATE friend_link_projection SET updated_at=1 WHERE link_id='tie-link'")?;
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
    assert_eq!(merged.db.query_row("SELECT CAST(state_json AS TEXT) FROM runtime_actor_state WHERE state_kind='backup/inactive-pair/new'",[],|r|r.get::<_,String>(0))?,"true");
    assert_eq!(merged.db.query_row("SELECT json_extract(CAST(state_json AS TEXT),'$.revision') FROM runtime_actor_state WHERE state_kind='surface/state/old'",[],|r|r.get::<_,u64>(0))?,9);
    assert_eq!(merged.db.query_row("SELECT CAST(event_body AS TEXT) FROM backup_archived_local_event WHERE event_id='source-only-counter'",[],|r|r.get::<_,String>(0))?,"preserved despite actor-counter collision");
    assert!(!merged.db.query_row("SELECT active FROM group_member_projection WHERE group_id='membership' AND member_id='peer'",[],|r|r.get::<_,bool>(0))?);
    assert!(merged.db.query_row("SELECT active FROM group_member_projection WHERE group_id='new-membership' AND member_id='peer'",[],|r|r.get::<_,bool>(0))?);
    assert!(merged.db.query_row(
        "SELECT blocked FROM friend_link_projection WHERE link_id='tie-link'",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    merged.check_integrity()?;
    drop(merged);
    drop(source);
    drop(local);
    drop(index);
    drop(local_index);
    std::fs::remove_dir_all(root)?;
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
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert_eq!(merged.db.query_row("SELECT count(*) FROM direct_message_projection WHERE message_id IN ('source-deleted','local-deleted') AND deleted=1",[],|r|r.get::<_,u64>(0))?,2);
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
    drop(source);
    drop(local);
    drop(source_index);
    drop(local_index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
