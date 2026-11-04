// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Handler refusal classification and propagation of a real failed storage write.
use super::*;
use ramflux_storage::{FileVaultSecretSource, StorageError, VaultSecretSource};
use std::fmt::Write;

pub(super) fn connection(f: &Fixture) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let vault = FileVaultSecretSource::new(&f.root).vault_secret("account")?;
    let wrapped = f.client.account_index()?.load_wrapped_db_key("account")?.ok_or("key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(&vault, b"test-secret"),
        &wrapped,
    )?;
    let db = rusqlite::Connection::open(&f.client.account_db()?.path)?;
    let mut hex = String::with_capacity(64);
    for byte in key.bytes() {
        write!(&mut hex, "{byte:02x}")?;
    }
    db.execute_batch(&format!("PRAGMA key=\"x'{hex}'\";"))?;
    Ok(db)
}

#[test]
fn c1_revoke_with_owner_only_record_is_inbound_rejected() -> Result<(), Box<dyn std::error::Error>>
{
    let f = Fixture::without_owner()?;
    let entry = cached_commit::revocation_entry(&f)?;
    let db = f.client.account_db()?;
    db.persist_client_record("object", "remote-object", &json!({"owner":"owner"}))?;
    assert_eq!(db.actor_state_keys("attachment/reference/")?, Vec::<String>::new());
    let sql = connection(&f)?;
    assert_eq!(
        sql.query_row("SELECT count(*) FROM object_retention_reference", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    // Owner authentication succeeds; the missing manifest must be a terminal refusal.
    let error = f
        .client
        .project_contact_control(
            &entry,
            &json!({"type":"object.revoke_access","object_id":"remote-object"}),
        )
        .err()
        .ok_or("owner-only revocation accepted")?;
    assert!(matches!(error, SdkError::InboundRejected(_)), "{error:?}");
    assert!(error.to_string().contains("no admissible manifest source"));
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM object_index WHERE object_id='remote-object'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn c1_storage_io_error_still_propagates() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let entry = cached_commit::revocation_entry(&f)?;
    let sql = connection(&f)?;
    // Fail the actual writer after identity resolution, without storage test hooks.
    sql.execute_batch("CREATE TRIGGER refuse_revocation_write BEFORE INSERT ON object_index BEGIN SELECT RAISE(ABORT,'revocation writer failed'); END;")?;
    let event = json!({"type":"object.revoke_access","object_id":"remote-object"});
    let error = f
        .client
        .project_contact_control(&entry, &event)
        .err()
        .ok_or("failed writer accepted revocation")?;
    assert!(matches!(error, SdkError::Storage(StorageError::Sqlite(_))), "{error:?}");
    assert!(error.to_string().contains("revocation writer failed"));
    assert!(!f.client.account_db()?.object_is_tombstoned("remote-object")?);
    sql.execute_batch("DROP TRIGGER refuse_revocation_write;")?;
    f.client.project_contact_control(&entry, &event)?;
    assert!(f.client.account_db()?.object_is_tombstoned("remote-object")?);
    Ok(())
}
