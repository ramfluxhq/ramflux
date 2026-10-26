// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Backup preflight uses a read worker independently of a busy account writer.
use super::*;
#[tokio::test]
async fn r4_missing_reference_enumeration_completes_while_the_account_writer_is_blocked()
-> Result<(), Box<dyn std::error::Error>> {
    let root = crate::bus::runtime_tests::root("backup-independent-reader");
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let key = ramflux_storage::AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "a", &key)?;
    db.persist_actor_state(
        "attachment/reference/pending",
        &serde_json::json!({"reference":{"manifest_hash":"missing","plaintext_hash":"missing"}}),
    )?;
    let readers = AccountReaders::start(&db, None)?;
    let lock = AccountDb::open(&index, "a", &key)?;
    let (held, ready) = std::sync::mpsc::sync_channel(1);
    let (release, resume) = std::sync::mpsc::sync_channel(1);
    let holder = std::thread::spawn(move || {
        lock.write_transaction(|| -> Result<(), ramflux_storage::StorageError> {
            lock.persist_actor_state("held-write", &true)?;
            let _ = held.send(());
            let _ = resume.recv();
            Ok(())
        })
    });
    ready.recv_timeout(std::time::Duration::from_secs(5))?;
    let writer = db;
    let (started, waiting) = std::sync::mpsc::sync_channel(1);
    let blocked = std::thread::spawn(move || {
        let _ = started.send(());
        writer.persist_actor_state("queued-write", &true)
    });
    waiting.recv_timeout(std::time::Duration::from_secs(5))?;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        readers.backup_missing_references(),
    )
    .await;
    let _ = release.send(());
    holder.join().map_err(|_| "lock-holder panic")??;
    blocked.join().map_err(|_| "writer panic")??;
    let missing = result??;
    assert_eq!(missing.account_id, "a");
    assert_eq!(missing.total, 1);
    assert_eq!(missing.selectors, vec!["pending"]);
    readers.stop().await;
    drop(readers);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
