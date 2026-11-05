// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact standalone replacement receipts never authorize private aliases.
use crate::StorageError;
use rusqlite::{Connection, OptionalExtension};
use std::io::Read;

pub(in crate::account_db) fn checked(
    db: &Connection,
    schema: &str,
    commitment: &str,
) -> Result<bool, StorageError> {
    let row: Option<(i64,String)> = db.query_row(&format!("SELECT o.rowid,p.manifest_hash FROM {schema}.object_identity_replacement x JOIN {schema}.object_retention_payload p USING(commitment) JOIN {schema}.object_index o ON o.object_id=p.wire_id AND CAST(o.manifest_hash AS TEXT)=p.manifest_hash WHERE x.commitment=?1 AND p.retention_class='standalone' AND o.tombstoned=0 AND length(o.ciphertext)>0 AND NOT EXISTS(SELECT 1 FROM main.object_erasure_fence f WHERE f.commitment=x.commitment)"),[commitment],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((id, manifest)) = row else { return Ok(false) };
    let cached: Option<String> = db.query_row("SELECT ciphertext_hash FROM main.backup_replacement_hash WHERE schema_name=?1 AND object_row_id=?2", rusqlite::params![schema,id], |r| r.get(0)).optional()?;
    let hash = if let Some(hash) = cached {
        hash
    } else {
        let hash = hash_ciphertext(db, schema, id)?;
        db.execute(
            "INSERT INTO main.backup_replacement_hash VALUES(?1,?2,?3)",
            rusqlite::params![schema, id, hash],
        )?;
        hash
    };
    Ok(hash == manifest)
}

// The source schema is attached read-only. Main rows can change during arbitration,
// so their cached bytes are invalidated before another check can use them.
pub(super) fn prepare(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE main.backup_replacement_hash(schema_name TEXT NOT NULL,object_row_id INTEGER NOT NULL,ciphertext_hash TEXT NOT NULL,PRIMARY KEY(schema_name,object_row_id)); CREATE TRIGGER main.backup_replacement_hash_update AFTER UPDATE OF ciphertext,manifest_hash,rowid ON object_index BEGIN DELETE FROM backup_replacement_hash WHERE schema_name='main' AND object_row_id=OLD.rowid; END; CREATE TRIGGER main.backup_replacement_hash_delete AFTER DELETE ON object_index BEGIN DELETE FROM backup_replacement_hash WHERE schema_name='main' AND object_row_id=OLD.rowid; END;")
}

fn hash_ciphertext(db: &Connection, schema: &str, id: i64) -> Result<String, StorageError> {
    #[cfg(test)]
    HASH_COUNT.set(HASH_COUNT.get().saturating_add(1));
    let mut blob = db.blob_open(schema, "object_index", "ciphertext", id, true)?;
    let mut hasher =
        ramflux_crypto::Blake3DomainHasher::new(ramflux_protocol::domain::OBJECT_MANIFEST);
    let mut buffer = [0; 8192];
    loop {
        let count = blob.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize_base64url())
}

#[cfg(test)]
thread_local! {
    pub(super) static HASH_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn merge(db: &Connection) -> Result<(), StorageError> {
    let mut query=db.prepare("SELECT commitment FROM incoming.object_identity_replacement x WHERE NOT EXISTS(SELECT 1 FROM backup_erased_copy e JOIN incoming.object_index o ON o.rowid=e.row_id JOIN incoming.object_retention_payload p ON p.wire_id=o.object_id AND p.commitment=x.commitment WHERE e.database_name='incoming' AND e.table_name='object_index')")?;
    for row in query.query_map([], |r| r.get::<_, String>(0))? {
        let commitment = row?;
        if checked(db, "incoming", &commitment)? {
            db.execute(
                "INSERT INTO object_identity_replacement VALUES(?1) ON CONFLICT DO NOTHING",
                [commitment],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackupDatabase, ObjectWrite};

    #[test]
    fn replacement_hash_cache_reuses_bytes_and_invalidates_target_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("replacement-hash-cache")?;
        let bytes = b"replacement cache bytes";
        let manifest =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, bytes);
        db.replace_object(
            None,
            &ObjectWrite {
                object_id: "wire",
                manifest_hash: &manifest,
                nonce: "n",
                ciphertext: bytes,
                plaintext_hash: "plain",
                tombstoned: false,
                backup_excluded: false,
                content_key: Some(&[9; 32]),
                object: &serde_json::json!({}),
                updated_at: 1,
            },
        )?;
        let path = root.join("cache.db");
        let saved = db.write_backup_snapshot(&path)?;
        let target = BackupDatabase::open(&path, &saved.key)?;
        prepare(&target.db)?;
        let commitment = ramflux_crypto::object_erasure_commitment("principal", "wire", &manifest);
        let before = HASH_COUNT.get();
        assert!(checked(&target.db, "main", &commitment)?);
        assert!(checked(&target.db, "main", &commitment)?);
        assert_eq!(HASH_COUNT.get(), before + 1);
        target
            .db
            .execute("UPDATE object_index SET ciphertext=x'010203' WHERE object_id='wire'", [])?;
        assert!(!checked(&target.db, "main", &commitment)?);
        assert_eq!(HASH_COUNT.get(), before + 2);
        super::super::drop_scratch(&target.db)?;
        assert_eq!(
            target.db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'backup_replacement_hash%'",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        drop(target);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
