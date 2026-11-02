// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pre-import deletion fences survive writes, encrypted snapshots and stale restores.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex, ObjectWrite};
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    db: AccountDb,
    root: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-object-revoke-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = AccountIndex::open(&root)?;
        index.create_account("account", "root")?;
        let db = AccountDb::open(&index, "account", &AccountDbKey::generate()?)?;
        Ok(Self { db, root })
    }
    fn write_live(&self) -> TestResult {
        self.db.upsert_object(&ObjectWrite {
            object_id: "object",
            manifest_hash: "manifest",
            nonce: "nonce",
            ciphertext: b"ciphertext",
            plaintext_hash: "plaintext",
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&[1; 32]),
            object: &json!({"object_id":"object","tombstoned":false}),
            updated_at: i64::MAX,
        })?;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn late_import_cannot_replace_tombstone_placeholder() -> TestResult {
    let fixture = Fixture::new()?;
    let db = &fixture.db;
    db.persist_client_record(
        "object",
        "object",
        &json!({
            "owner":"owner", "manifest_hash":"manifest", "message_id":"message"
        }),
    )?;
    db.set_object_tombstoned_with_revocation("object", Some("owner"), Some("revoke-wire"), 10)?;
    let check = || -> TestResult {
        let shape = db.connection.query_row(
            "SELECT tombstoned,object_state,chunk_count,total_cipher_size,length(ciphertext),
                    length(nonce),plaintext_hash IS NULL,object_content_key IS NULL,
                    backup_excluded,CAST(manifest_hash AS TEXT),object_body
               FROM object_index WHERE object_id='object'",
            [],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, bool>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )?;
        assert!(shape.0);
        assert_eq!(shape.1, "tombstoned");
        assert_eq!((shape.2, shape.3, shape.4, shape.5), (0, 0, 0, 12));
        assert!(shape.6 && shape.7 && !shape.8);
        assert_eq!(shape.9, "manifest");
        let body: Value = serde_json::from_slice(&shape.10)?;
        assert_eq!(
            body,
            json!({"object_id":"object","owner":"owner","tombstoned":true,
            "revoked_at":10,"revocation":{"sender":"owner","wire_id":"revoke-wire",
            "manifest_hash":"manifest"}})
        );
        Ok(())
    };
    check()?;
    fixture.write_live()?;
    check()?;
    assert_eq!(db.client_directory_ids("object", "", 100)?, Vec::<String>::new());
    assert_eq!(db.client_message_object_ids("message")?, Vec::<String>::new());
    Ok(())
}

#[test]
fn object_placeholder_without_manifest_uses_zero_bytes() -> TestResult {
    let f = Fixture::new()?;
    f.db.set_object_tombstoned("object")?;
    let (manifest, nonce): (Vec<u8>, Vec<u8>) = f.db.connection.query_row(
        "SELECT chunk_manifest_hash,nonce FROM object_index WHERE object_id='object'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(manifest, [0_u8; 32]);
    assert_eq!(nonce, [0_u8; 12]);
    assert!(f.db.load_object::<Value>("object")?.is_some());
    Ok(())
}

#[test]
fn backup_merge_keeps_tombstone_placeholder() -> TestResult {
    let local = Fixture::new()?;
    let old = Fixture::new()?;
    old.write_live()?;
    local.db.persist_client_record(
        "object",
        "object",
        &json!({
            "owner":"owner","manifest_hash":"manifest","message_id":"message"
        }),
    )?;
    local.db.persist_actor_state("attachment/reference/object", &json!({
        "reference":{"object_id":"object","manifest_hash":"manifest","plaintext_hash":"plaintext"}
    }))?;
    local.db.set_object_tombstoned_with_revocation("object", Some("owner"), Some("wire"), 10)?;
    assert_eq!(local.db.backup_missing_selectors()?, Vec::<String>::new());
    let old_path = old.root.join("old.db");
    let archive = old.db.write_backup_snapshot(&old_path)?;
    drop(BackupDatabase::open(&old_path, &archive.key)?);
    let path = local.root.join("export.db");
    let export = local.db.write_backup_snapshot(&path)?;
    assert_eq!(export.counts.attachments, 1, "the fence must be exported");
    assert_eq!(export.counts.attachment_bytes, 0);
    let mut restored = BackupDatabase::open(&path, &export.key)?;
    assert_eq!(restored.verify_attachments(|_, _| Ok(()))?.missing, 0);
    restored.merge_backup(&old_path, &archive.key, || Ok(()))?;
    let retained: (bool,i64,i64) = restored.db.query_row(
        "SELECT tombstoned,chunk_count,length(ciphertext) FROM object_index WHERE object_id='object'",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    assert_eq!(retained, (true, 0, 0), "a later archive timestamp cannot defeat the fence");
    assert_eq!(
        restored.verify_archive_contribution(&old_path, &archive.key, |_, _| Ok(()))?.missing,
        0
    );
    // Import the exported fence into an independent empty generation as well.
    let empty = Fixture::new()?;
    let empty_path = empty.root.join("empty.db");
    let snapshot = empty.db.write_backup_snapshot(&empty_path)?;
    let mut roundtrip = BackupDatabase::open(&empty_path, &snapshot.key)?;
    roundtrip.merge_backup(&path, &export.key, || Ok(()))?;
    assert!(roundtrip.db.query_row(
        "SELECT tombstoned FROM object_index WHERE object_id='object'",
        [],
        |row| row.get::<_, bool>(0)
    )?);
    assert_eq!(roundtrip.verify_attachments(|_, _| Ok(()))?.missing, 0);
    Ok(())
}
