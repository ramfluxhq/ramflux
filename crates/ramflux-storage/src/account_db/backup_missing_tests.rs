// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large reference sets must not trigger a correlated full scan per attachment.
use super::AccountDb;
use crate::{AccountDbKey, AccountIndex};
#[test]
fn r4_twenty_thousand_downloaded_references_are_scanned_with_bounded_work()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "backup-missing-scan-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let db = AccountDb::open(&index, "a", &AccountDbKey::generate()?)?;
    db.connection.execute_batch("BEGIN;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<20000)
        INSERT INTO object_index(object_id,chunk_manifest_hash,object_state,total_cipher_size,chunk_count,created_at,updated_at,manifest_hash,plaintext_hash)
        SELECT printf('object-%d',i),x'00','complete',0,0,0,0,CAST(printf('manifest-%d',i) AS BLOB),printf('plain-%d',i) FROM n;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<20000)
        INSERT INTO runtime_actor_state SELECT printf('attachment/reference/%08d',i),CAST(json_object('reference',json_object('manifest_hash',printf('manifest-%d',i),'plaintext_hash',printf('plain-%d',i))) AS BLOB) FROM n;
        COMMIT;")?;
    let started = std::time::Instant::now();
    assert_eq!(db.backup_missing_count()?, 0);
    let elapsed = started.elapsed();
    eprintln!("20k missing-reference scan: {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "a 20k reference scan must not be quadratic: {elapsed:?}"
    );
    db.connection.execute_batch("INSERT INTO runtime_actor_state VALUES('attachment/reference/unavailable',CAST('{\"reference\":{\"manifest_hash\":\"missing\",\"plaintext_hash\":\"missing\"}}' AS BLOB))")?;
    assert_eq!(db.backup_missing_count()?, 1);
    assert_eq!(db.backup_missing_page("")?, vec!["unavailable"]);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
