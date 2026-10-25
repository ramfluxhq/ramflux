// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Incremental attachment merge and strict missing-reference accounting.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::{AccountDbKey, AccountIndex, ObjectWrite};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
#[test]
fn incremental_merge_preserves_attachment_bytes_keys_and_hashes_and_refuses_missing_references()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "rf-backup-files-{}-{}",
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
    let id = "large-file";
    let key = [17; 32];
    let clear = vec![91; 2 * 1024 * 1024 + 17];
    let nonce = ramflux_crypto::blake3_256(ramflux_protocol::domain::OBJECT, id.as_bytes());
    let ciphertext = ChaCha20Poly1305::new((&key).into())
        .encrypt(Nonce::from_slice(&nonce[..12]), Payload { msg: &clear, aad: id.as_bytes() })
        .map_err(|_| "encryption")?;
    let manifest = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::OBJECT_MANIFEST,
        &ciphertext,
    );
    let plaintext = ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &clear);
    source.upsert_object(&ObjectWrite {
        object_id: id,
        manifest_hash: &manifest,
        nonce: "nonce",
        ciphertext: &ciphertext,
        plaintext_hash: &plaintext,
        tombstoned: false,
        backup_excluded: false,
        content_key: Some(&key),
        object: &serde_json::json!({"ciphertext":"ramflux:column:1"}),
        updated_at: 1,
    })?;
    source.persist_actor_state(
        "attachment/reference/received:selector",
        &serde_json::json!({"reference":{"manifest_hash":manifest,"plaintext_hash":plaintext}}),
    )?;
    let path = root.join("incoming.db");
    let incoming = source.write_backup_snapshot(&path)?;
    let target = root.join("merged.db");
    let snapshot = local.write_backup_snapshot(&target)?;
    let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
    let report = merged.merge_backup(&path, &incoming.key, || Ok(()))?;
    assert_eq!(report.restored.attachments, 1);
    assert_eq!(report.restored.attachment_bytes, ciphertext.len() as u64);
    let verified = merged.verify_attachments(|_, _| Ok(()))?;
    assert_eq!(verified.verified, 1);
    assert_eq!(verified.missing, 0);
    assert_eq!(verified.mismatched, 0);
    merged.put_state(
        "attachment/reference/missing",
        &serde_json::json!({"reference":{"manifest_hash":"missing","plaintext_hash":"missing"}}),
    )?;
    assert_eq!(merged.verify_attachments(|_, _| Ok(()))?.missing, 1);
    merged.put_state("attachment/reference/invalid", &serde_json::json!({"reference":{}}))?;
    assert_eq!(merged.verify_attachments(|_, _| Ok(()))?.missing, 2);
    drop(merged);
    drop(source);
    drop(local);
    drop(source_index);
    drop(local_index);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
