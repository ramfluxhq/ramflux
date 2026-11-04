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
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "rf-object-revoke-{}-{sequence}-{}",
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

    fn received_reference(&self, selector: &str, metadata_manifest: Option<&str>) -> TestResult {
        self.db.send_direct_message("thread", "message", "peer", b"message")?;
        let reference = json!({
            "reference":{"object_id":"object","manifest_hash":"manifest","plaintext_hash":"plaintext"}
        });
        let mut metadata = json!({"object_id":selector,"owner":"peer","message_id":"message"});
        if let Some(manifest) = metadata_manifest {
            metadata["manifest_hash"] = json!(manifest);
        }
        self.db.register_object_reference(
            crate::ObjectReferenceAdmission::FreshMessage,
            &crate::ObjectReferenceOwner {
                reference_hash: "authenticated-reference",
                wire_id: "object",
                manifest_hash: "manifest",
                selector,
                message_id: "message",
                reference: &reference,
                metadata: &metadata,
            },
        )?;
        self.db.persist_actor_state(&format!("attachment/reference/{selector}"), &reference)?;
        self.db.persist_client_record("object", selector, &metadata)?;
        Ok(())
    }

    fn legacy_placeholder(&self) -> TestResult {
        let body: Vec<u8> = self.db.connection.query_row(
            "SELECT object_body FROM object_index WHERE object_id='object'",
            [],
            |row| row.get(0),
        )?;
        let mut body: Value = serde_json::from_slice(&body)?;
        body["revocation"]["manifest_hash"] = Value::Null;
        self.db.connection.execute(
            "UPDATE object_index SET manifest_hash=?1,chunk_manifest_hash=?1,object_body=?2
             WHERE object_id='object'",
            rusqlite::params![&[0_u8; 32][..], serde_json::to_vec(&body)?],
        )?;
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
    backup_placeholder_roundtrip(true)
}

// Mutation: check the manifest identity before allowing the current tombstone to win.
#[test]
fn backup_merge_keeps_zero_manifest_tombstone_placeholder() -> TestResult {
    backup_placeholder_roundtrip(false)
}

fn backup_placeholder_roundtrip(known_manifest: bool) -> TestResult {
    let local = Fixture::new()?;
    let old = Fixture::new()?;
    assert_ne!(local.root, old.root, "independent backup fixtures must have distinct roots");
    old.write_live()?;
    if known_manifest {
        local.db.persist_client_record(
            "object",
            "object",
            &json!({
                "owner":"owner","manifest_hash":"manifest","message_id":"message"
            }),
        )?;
    }

    local.db.register_object_reference(crate::ObjectReferenceAdmission::FreshMessage, &crate::ObjectReferenceOwner {
        reference_hash: "backup-reference", wire_id: "object", manifest_hash: "manifest",
        selector: "object", message_id: "message",
        reference: &json!({"reference":{"object_id":"object","manifest_hash":"manifest","plaintext_hash":"plaintext"}}),
        metadata: &json!({"object_id":"object","manifest_hash":"manifest","message_id":"message"}),
    })?;
    local.db.persist_actor_state("attachment/reference/object", &json!({
        "reference":{"object_id":"object","manifest_hash":"manifest","plaintext_hash":"plaintext"}
    }))?;
    local.db.set_object_tombstoned_with_revocation("object", Some("owner"), Some("wire"), 10)?;
    if !known_manifest {
        // Preserve coverage of archives written before authenticated manifest binding.
        local.legacy_placeholder()?;
    }
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

// Mutation: replace the authenticated reference manifest with the old zero-byte fallback.
#[test]
fn revocation_placeholder_is_erased_with_its_last_message() -> TestResult {
    for selector in ["object", "alias"] {
        for metadata_manifest in [None, Some("stale-display-manifest")] {
            let f = Fixture::new()?;
            f.received_reference(selector, metadata_manifest)?;
            f.db.set_object_tombstoned_with_revocation(selector, Some("peer"), Some("revoke"), 10)?;
            assert!(f.db.object_is_tombstoned(selector)?);
            f.db.delete_direct_message("thread", "message", "local", "delete")?;
            assert_eq!(
                f.db.connection.query_row(
                    "SELECT COUNT(*) FROM object_index WHERE object_id=?1",
                    rusqlite::params![selector],
                    |row| row.get::<_, i64>(0),
                )?,
                0,
                "last-message erasure must remove revocation provenance: {selector}, metadata={metadata_manifest:?}"
            );
            assert!(matches!(
                f.db.check_object_access(selector),
                Err(crate::StorageError::ObjectErased)
            ));
            let archive = f.db.write_backup_snapshot(&f.root.join("after-erasure.db"))?;
            assert_eq!(archive.counts.attachments, 0, "the erased fence must not enter backups");
        }
    }
    Ok(())
}

// Mutation: remove the source-placeholder exemption from backup manifest conflict checking.
#[test]
fn backup_revocation_placeholder_restores_onto_live_object() -> TestResult {
    for (legacy, current_newer) in [(false, false), (true, false), (true, true)] {
        let incoming = Fixture::new()?;
        incoming.received_reference("object", None)?;
        incoming.db.set_object_tombstoned_with_revocation(
            "object",
            Some("peer"),
            Some("revoke"),
            10,
        )?;
        if legacy {
            incoming.legacy_placeholder()?;
        }
        let incoming_path = incoming.root.join("incoming.db");
        let archive = incoming.db.write_backup_snapshot(&incoming_path)?;
        let current = Fixture::new()?;
        current.write_live()?;
        if !current_newer {
            current.db.connection.execute("UPDATE object_index SET updated_at=1", [])?;
        }
        let current_path = current.root.join("current.db");
        let snapshot = current.db.write_backup_snapshot(&current_path)?;
        let mut restored = BackupDatabase::open(&current_path, &snapshot.key)?;
        restored.merge_backup(&incoming_path, &archive.key, || Ok(()))?;
        let row: (bool, String, String) = restored.db.query_row(
            "SELECT tombstoned,CAST(manifest_hash AS TEXT),CAST(chunk_manifest_hash AS TEXT)
             FROM object_index WHERE object_id='object'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(row, (!current_newer, "manifest".into(), "manifest".into()));
        assert_eq!(restored.verify_attachments(|_, _| Ok(()))?.missing, 0);
    }
    Ok(())
}

// Mutation: remove the private-reference veto from retention reclamation.
#[test]
fn tombstone_placeholder_survives_retention_sweep_while_reference_exists() -> TestResult {
    for retention in [
        crate::ObjectRetention::Imported,
        crate::ObjectRetention::PreSend { expires_at: 0 },
        crate::ObjectRetention::OwnDeviceTransport,
    ] {
        for (selector, known_manifest) in [("object", true), ("object", false), ("alias", false)] {
            let f = Fixture::new()?;
            f.db.retain_object("object", "manifest", crate::ObjectRetention::Imported)?;
            f.db.register_object_reference(crate::ObjectReferenceAdmission::FreshMessage, &crate::ObjectReferenceOwner {
                reference_hash: "reference",
                wire_id: "object",
                manifest_hash: "manifest",
                selector,
                message_id: "message",
                reference: &json!({"reference":{"object_id":"object","manifest_hash":"manifest"}}),
                metadata: &json!({"object_id":selector,"message_id":"message"}),
            })?;
            f.db.retain_object("object", "manifest", retention)?;
            f.db.connection.execute("UPDATE object_retention_payload SET hold_expires_at=0", [])?;
            // Exercise orphan/expired maintenance, independently of explicit last-message erasure.
            f.db.connection.execute("DELETE FROM object_message_reference", [])?;
            let key = format!("attachment/reference/{selector}");
            f.db.persist_actor_state(
                &key,
                &json!({
                    "reference":{"object_id":"object","manifest_hash":"manifest"}
                }),
            )?;
            if known_manifest {
                f.db.persist_client_record(
                    "object",
                    selector,
                    &json!({"manifest_hash":"manifest"}),
                )?;
            }
            f.db.set_object_tombstoned(selector)?;
            for _ in 0..8 {
                f.db.maintain_object_retention()?;
                f.db.maintain_expired_object_holds()?;
            }
            assert_eq!(
                f.db.connection.query_row(
                    "SELECT phase FROM object_retention_upgrade WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                5,
                "discovery must finish before the assertion"
            );
            assert!(f.db.object_is_tombstoned(selector)?, "the revocation fence must survive");
            assert!(f.db.load_actor_state::<Value>(&key)?.is_some());
            assert_eq!(
                f.db.object_erasure_generation()?,
                0,
                "maintenance must not replace revocation with erasure"
            );
            // Removing the last private reference makes the eligible payload reclaimable again.
            f.db.remove_actor_state(&key)?;
            f.db.maintain_object_retention()?;
            assert!(matches!(
                f.db.check_object_identity("object", "manifest"),
                Err(crate::StorageError::ObjectErased)
            ));
        }
    }
    Ok(())
}

// Mutation: remove check_object_access before inserting a placeholder.
#[test]
fn revocation_after_erasure_does_not_insert_placeholder() -> TestResult {
    let f = Fixture::new()?;
    f.db.retain_object("object", "manifest", crate::ObjectRetention::Imported)?;
    for _ in 0..8 {
        f.db.maintain_object_retention()?;
    }
    assert!(matches!(f.db.check_object_access("object"), Err(crate::StorageError::ObjectErased)));
    f.db.set_object_tombstoned("object")?;
    assert!(!f.db.object_is_tombstoned("object")?);
    assert_eq!(
        f.db.connection
            .query_row("SELECT COUNT(*) FROM object_index", [], |row| row.get::<_, i64>(0))?,
        0
    );
    Ok(())
}

// Mutation: filter only the directory arm instead of the UNION output.
#[test]
fn message_attachment_union_filters_revoked_retention_and_directory_selectors() -> TestResult {
    let f = Fixture::new()?;
    f.db.register_object_reference(
        crate::ObjectReferenceAdmission::FreshMessage,
        &crate::ObjectReferenceOwner {
            reference_hash: "reference",
            wire_id: "object",
            manifest_hash: "manifest",
            selector: "object",
            message_id: "message",
            reference: &json!({"reference":{"object_id":"object","manifest_hash":"manifest"}}),
            metadata: &json!({"object_id":"object","message_id":"message"}),
        },
    )?;
    f.db.persist_actor_state(
        "directory/object/directory",
        &json!({"object_id":"directory","message_id":"message"}),
    )?;
    assert_eq!(f.db.client_message_object_ids("message")?, vec!["directory", "object"]);
    f.db.set_object_tombstoned("object")?;
    f.db.set_object_tombstoned("directory")?;
    assert_eq!(f.db.client_message_object_ids("message")?, Vec::<String>::new());
    Ok(())
}
