// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{AccountDbKey, AccountIndex};
fn database() -> Result<(std::path::PathBuf, AccountDb), StorageError> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root = std::env::temp_dir()
        .join(format!("ramflux-journal-{}-{sequence}-{unique}", std::process::id()));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "principal")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::derive("a", b"secret"))?;
    Ok((root, db))
}
#[test]
fn sequences_survive_reopen_and_retention_never_reuses_them() -> Result<(), StorageError> {
    let (root, db) = database()?;
    for n in 0..6 {
        db.append_journal(
            &format!("event:{n}"),
            "conversation.changed",
            &serde_json::json!({"id":n}),
            n,
            None,
        )?;
    }
    let head = db.journal_bounds()?.head_seq;
    assert_eq!(head, 6);
    db.retain_journal(6, 2, 100)?;
    assert_eq!(db.journal_bounds()?.floor_seq, 5);
    assert_eq!(db.journal_bounds()?.pruned_through, 4);
    assert_eq!(db.journal_after(4, 128)?.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![5, 6]);
    drop(db);
    let db =
        AccountDb::open(&AccountIndex::open(&root)?, "a", &AccountDbKey::derive("a", b"secret"))?;
    assert_eq!(db.journal_bounds()?.head_seq, head);
    db.retain_journal(1000, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, Vec::<JournalEvent>::new());
    assert!(
        db.append_journal("new", "sync.status", &serde_json::json!({}), 1000, None)?.seq > head
    );
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn sticky_events_survive_age_count_until_ack_and_holes_are_detectable() -> Result<(), StorageError>
{
    let (root, db) = database()?;
    let safety = db.append_journal(
        "safety",
        "safety.changed",
        &serde_json::json!({"id":"peer"}),
        1,
        Some("peer"),
    )?;
    let approval = db.append_journal(
        "approval",
        "mcp.approval.request",
        &serde_json::json!({"id":"approval"}),
        1,
        Some("approval"),
    )?;
    db.append_journal(
        "ordinary",
        "message.updated",
        &serde_json::json!({"id":"message"}),
        2,
        None,
    )?;
    db.retain_journal(100, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, vec![safety.clone(), approval.clone()]);
    assert_eq!(db.journal_bounds()?.floor_seq, safety.seq);
    assert_eq!(db.journal_bounds()?.pruned_through, 3);
    db.acknowledge_journal_subject("peer")?;
    db.acknowledge_journal(approval.seq)?;
    db.retain_journal(100, 0, 0)?;
    assert_eq!(db.journal_after(0, 128)?, Vec::<JournalEvent>::new());
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn outbox_and_journal_commit_atomically_and_quarantine_never_evicts() -> Result<(), StorageError> {
    let (root, db) = database()?;
    db.persist_actor_state("directory/conversation/example", &serde_json::json!({"id":"example"}))?;
    let entry = db.pending_outbox(128)?.pop().ok_or(StorageError::AuthorizationRejected)?;
    assert_eq!(entry.keys["state_kind"], "directory/conversation/example");
    let failed = db.journal_outbox(
        entry.sequence,
        &[(
            "conversation.changed".to_owned(),
            serde_json::json!({"huge":"x".repeat(600_000)}),
            None,
        )],
        1,
    );
    assert!(failed.is_err());
    assert_ne!(db.pending_outbox(128)?.len(), 0);
    assert_eq!(db.journal_bounds()?.head_seq, 0);
    db.journal_outbox(
        entry.sequence,
        &[("conversation.changed".to_owned(), serde_json::json!({"id":"example"}), None)],
        1,
    )?;
    assert_eq!(db.pending_outbox(128)?.len(), 0);
    assert_eq!(db.journal_bounds()?.head_seq, 1);
    for n in 0..64 {
        db.hold_unrouted(&format!("e{n}"), n, b"ciphertext", 1)?;
    }
    db.hold_unrouted("overflow", 65, b"ciphertext", 1)?;
    assert_eq!(db.unrouted_count()?, 64);
    assert_eq!(db.unrouted_entries()?.len(), 64);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn deleting_message_erases_approved_content_copy() -> Result<(), StorageError> {
    let (root, db) = database()?;
    db.send_direct_message("conversation", "message", "sender", b"encrypted bytes")?;
    db.store_message_content("conversation", "message", b"approved plaintext")?;
    assert!(db.message_content("message")?.is_some());
    db.delete_direct_message("conversation", "message", "local", "tombstone")?;
    assert_eq!(db.message_content("message")?, None);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn dead_letters_evict_oldest_expire_and_keep_ciphertext_out_of_journal() -> Result<(), StorageError>
{
    let (root, db) = database()?;
    for n in 0..65 {
        db.dead_letter_inbox(&format!("bad-{n:02}"),b"PRIVATE_CIPHERTEXT",&serde_json::json!({"envelope_id":format!("e{n}"),"error_code":"authentication_failed"}),100+n)?;
    }
    let count: u32 =
        db.connection
            .query_row("SELECT count(*) FROM runtime_inbox_dead_letter", [], |row| row.get(0))?;
    assert_eq!(count, 64);
    let oldest: String = db.connection.query_row(
        "SELECT envelope_key FROM runtime_inbox_dead_letter ORDER BY received_at LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(oldest, "bad-01");
    for event in db.journal_after(0, 100)? {
        assert!(!serde_json::to_string(&event)?.contains("PRIVATE_CIPHERTEXT"));
    }
    db.expire_inbox_holds(165 + 7 * 24 * 60 * 60)?;
    let count: u32 =
        db.connection
            .query_row("SELECT count(*) FROM runtime_inbox_dead_letter", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn transient_retry_capacity_and_expiry_emit_terminal_metadata_with_bounded_backoff()
-> Result<(), StorageError> {
    let (root, db) = database()?;
    for n in 0..65 {
        assert_eq!(db.defer_inbox_entry(&format!("retry-{n:02}"), b"PRIVATE_RETRY", 100)?, 1);
    }
    assert_eq!(db.due_inbox_retries(101)?.len(), 0);
    assert_eq!(db.due_inbox_retries(102)?.len(), 64);
    assert_eq!(db.journal_after(0, 100)?[0].body["error_code"], "retry_capacity");
    assert_eq!(db.defer_inbox_entry("retry-64", b"PRIVATE_RETRY", 102)?, 2);
    assert_eq!(db.due_inbox_retries(105)?.len(), 63);
    db.expire_inbox_holds(101 + 7 * 24 * 60 * 60)?;
    assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
    let events = db.journal_after(0, 100)?;
    assert!(events.iter().any(|event| event.body["error_code"] == "retry_expired"));
    assert!(!serde_json::to_string(&events)?.contains("PRIVATE_RETRY"));
    drop(db);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
