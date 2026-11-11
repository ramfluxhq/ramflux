// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted backup merge: an archive cannot undo content-free erase floors.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex};
use ramflux_protocol::message as g;
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn state(
    conversation: &str,
    revision: u64,
    text: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let value = g::SelfSync {
        operation: 2,
        revision,
        draft: Some(g::Message { text: text.into(), ..Default::default() }),
        ..Default::default()
    };
    let (_, exact) = g::registry::encode_body(&g::Content {
        value: Some(g::content::Value::SelfSync(value.clone())),
    })?;
    Ok(
        json!({"conversation_id":conversation,"value":value,"exact_body":exact,"tie_break":g::self_sync::body_hash(&exact)?,"read_marker":null,"read_marker_body":null,"pending_read":null,"references":[]}),
    )
}

#[test]
fn self_sync_restore_imports_erase_floors_before_values_and_never_archives_erased_drafts()
-> TestResult {
    let root = std::env::temp_dir().join(format!(
        "rf-self-sync-restore-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let source_index = AccountIndex::open(root.join("source"))?;
    let target_index = AccountIndex::open(root.join("target"))?;
    source_index.create_account("source", "own")?;
    target_index.create_account("target", "own")?;
    let source_key = AccountDbKey::generate()?;
    let target_key = AccountDbKey::generate()?;
    let source = AccountDb::open(&source_index, "source", &source_key)?;
    let target = AccountDb::open(&target_index, "target", &target_key)?;
    source.persist_actor_state(
        "self-sync/state/erased-conversation",
        &state("erased", 99, "must never return")?,
    )?;
    source.persist_actor_state(
        "self-sync/revision/erased-conversation",
        &json!({"conversation_id":"erased","revision":"00000000000000000099"}),
    )?;
    target.persist_actor_state(
        "self-sync/erase/conversation-fence",
        &json!({"conversation_id":"erased","erased":true}),
    )?;
    source
        .persist_actor_state("self-sync/state/erased-scope", &state("kept", 12, "erased scope")?)?;
    target
        .persist_actor_state("self-sync/state/erased-scope", &state("kept", 12, "erased scope")?)?;
    target.remove_actor_state("self-sync/state/erased-scope")?;
    let floor: Value = target
        .load_actor_state("self-sync/revision/erased-scope")?
        .ok_or("delete must install floor")?;
    assert_eq!(floor["revision"], "00000000000000000012");
    assert_eq!(floor["erased"], true);
    source.persist_actor_state(
        "self-sync/state/incoming-erased-scope",
        &state("incoming-scope", 20, "source already erased")?,
    )?;
    source.remove_actor_state("self-sync/state/incoming-erased-scope")?;
    target.persist_actor_state(
        "self-sync/state/incoming-erased-scope",
        &state("incoming-scope", 20, "source already erased")?,
    )?;
    source.persist_actor_state(
        "self-sync/erase/incoming-conversation",
        &json!({"conversation_id":"incoming-erased","erased":true}),
    )?;
    target.persist_actor_state(
        "self-sync/state/incoming-erased-conversation",
        &state("incoming-erased", 7, "target must erase on restore")?,
    )?;
    source.persist_actor_state("self-sync/state/live", &state("live", 7, "newer source value")?)?;
    target.persist_actor_state("self-sync/state/live", &state("live", 6, "older target value")?)?;
    source.persist_actor_state(
        "self-sync/pending/not-restorable",
        &json!({"conversation_id":"live","exact_body":"old send"}),
    )?;
    let incoming = root.join("incoming.db");
    let snapshot = source.write_backup_snapshot(&incoming)?;
    let destination = root.join("merged.db");
    let local = target.write_backup_snapshot(&destination)?;
    let mut merged = BackupDatabase::open(&destination, &local.key)?;
    merged.merge_backup(&incoming, &snapshot.key, || Ok(()))?;
    assert!(read(&merged, "self-sync/state/erased-conversation")?.is_none());
    assert!(read(&merged, "self-sync/state/erased-scope")?.is_none());
    assert!(read(&merged, "self-sync/pending/not-restorable")?.is_none());
    assert!(read(&merged, "self-sync/state/incoming-erased-scope")?.is_none());
    assert!(read(&merged, "self-sync/state/incoming-erased-conversation")?.is_none());
    assert_eq!(
        read(&merged, "self-sync/revision/incoming-erased-scope")?.ok_or("incoming floor lost")?["revision"],
        "00000000000000000020"
    );
    let live = read(&merged, "self-sync/state/live")?.ok_or("live state missing")?;
    assert_eq!(live["value"]["revision"], "7");
    assert_eq!(live["value"]["draft"]["text"], "newer source value");
    let archived: u64 = merged.db.query_row(
        "SELECT count(*) FROM backup_archived_actor_state WHERE state_kind LIKE 'self-sync/%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(archived, 0);
    assert_eq!(
        read(&merged, "self-sync/revision/erased-scope")?.ok_or("floor lost")?["revision"],
        "00000000000000000012"
    );
    merged.check_integrity()?;
    drop(merged);
    drop(source);
    drop(target);
    drop(source_index);
    drop(target_index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn read(merged: &BackupDatabase, key: &str) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    use rusqlite::OptionalExtension;
    let bytes: Option<Vec<u8>> = merged
        .db
        .query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind=?1", [key], |row| {
            row.get(0)
        })
        .optional()?;
    bytes.map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into)).transpose()
}
