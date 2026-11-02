// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large reference sets must not trigger a correlated full scan per attachment.
use super::{AccountDb, backup_database::BackupDatabase};
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
        SELECT printf('object-%d',i),x'00','complete',0,0,0,0,CASE WHEN i%2=0 THEN printf('manifest-%d',i) ELSE CAST(printf('manifest-%d',i) AS BLOB) END,'same-plaintext' FROM n;
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<20000)
        INSERT INTO runtime_actor_state SELECT printf('attachment/reference/%08d',i),CAST(json_object('reference',json_object('object_id',printf('object-%d',i),'manifest_hash',printf('manifest-%d',i),'plaintext_hash','same-plaintext')) AS BLOB) FROM n;
        COMMIT;")?;
    db.send_direct_message("thread", "fixture-owner", "peer", b"body")?;
    let owner_root = db.object_erasure_root().to_owned();
    db.connection.call(move |connection| Ok(bind_metadata_owners(connection, &owner_root)))??;
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
    let snapshot_path = root.join("private.db");
    let snapshot = db.write_backup_snapshot(&snapshot_path)?;
    let private = BackupDatabase::open(&snapshot_path, &snapshot.key)?;
    let started = std::time::Instant::now();
    assert_eq!(private.missing_attachment_count()?, 1);
    assert_eq!(private.missing_attachment_page("")?, vec!["unavailable"]);
    let elapsed = started.elapsed();
    eprintln!("20k duplicate-content private scan: {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "duplicate plaintext hashes must not cause a quadratic private scan: {elapsed:?}"
    );
    drop(private);
    drop(db);
    drop(index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

// Ownership setup is outside the timed scans and models authenticated receive metadata.
fn bind_metadata_owners(
    db: &mut rusqlite::Connection,
    root: &str,
) -> Result<(), crate::StorageError> {
    let transaction = db.transaction()?;
    {
        let mut payload = transaction.prepare("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,?2,?3,?4,'legacy')")?;
        let mut reference =
            transaction.prepare("INSERT INTO object_retention_reference VALUES(?1,?2,?3,?4,?5)")?;
        let mut edge = transaction
            .prepare("INSERT INTO object_message_reference VALUES('fixture-owner',?1,x'7b7d')")?;
        for number in 1..=20_001 {
            let (selector, wire, manifest, plaintext) = if number == 20_001 {
                ("unavailable".into(), "missing-wire".into(), "missing".into(), "missing")
            } else {
                (
                    format!("{number:08}"),
                    format!("object-{number}"),
                    format!("manifest-{number}"),
                    "same-plaintext",
                )
            };
            let value = serde_json::json!({"object_id":wire,"manifest_hash":manifest,"plaintext_hash":plaintext});
            let hash = ramflux_crypto::blake3_256_base64url(
                "ramflux.attachment.reference.v1",
                &ramflux_protocol::canonical_json_bytes(&value)?,
            );
            let commitment = ramflux_crypto::object_erasure_commitment(root, &wire, &manifest);
            payload.execute(rusqlite::params![
                commitment,
                wire,
                manifest,
                ramflux_crypto::object_erasure_lookup(root, &wire)
            ])?;
            reference.execute(rusqlite::params![
                hash,
                commitment,
                selector,
                ramflux_crypto::object_erasure_lookup(root, &selector),
                serde_json::to_vec(&serde_json::json!({"reference":value}))?
            ])?;
            edge.execute([&hash])?;
        }
    }
    transaction.commit()?;
    Ok(())
}
