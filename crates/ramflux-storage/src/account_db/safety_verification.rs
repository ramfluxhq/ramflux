// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-time and imported-row safety baselining share eligibility and failure isolation.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::SignedDeviceSetRecord;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

pub const LEGACY_SAFETY_VERIFICATION_MARKER: &str = "identity/safety-verification-migration/v1";
const DIRECTORY: &str = "directory/identity/";

#[derive(Clone, Copy)]
pub(super) enum MigrationScope {
    AccountUpgrade,
    ImportedRows,
}

fn state<T: serde::de::DeserializeOwned>(
    db: &Connection,
    key: &str,
) -> Result<Option<T>, StorageError> {
    let value: Option<Vec<u8>> = db
        .query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind=?1", [key], |row| {
            row.get(0)
        })
        .optional()?;
    value.map(|v| serde_json::from_slice(&v).map_err(StorageError::from)).transpose()
}

impl AccountDb {
    /// Completes one legacy-verification scan before query-only readers are opened.
    /// Individual malformed contacts remain unstamped; enumeration/transaction errors abort.
    /// # Errors
    /// Returns account-wide storage or completion-marker errors.
    pub fn migrate_legacy_contact_verifications(&self) -> Result<(), StorageError> {
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        self.write_transaction(|| {
            self.connection.call(move |sql| {
                let result = tracing::dispatcher::with_default(&dispatch, || {
                    if state::<bool>(sql, LEGACY_SAFETY_VERIFICATION_MARKER)? == Some(true) {
                        return Ok(());
                    }
                    migrate_rows(sql, MigrationScope::AccountUpgrade)?;
                    sql.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json WHERE state_json<>excluded.state_json", params![LEGACY_SAFETY_VERIFICATION_MARKER,b"true".as_slice()])?;
                    Ok(())
                });
                Ok(result)
            })?
        })
    }
}

pub(super) fn migrate_rows(db: &Connection, scope: MigrationScope) -> Result<(), StorageError> {
    let mut after = String::new();
    loop {
        // Listing is the account-wide failure boundary. Row decoding is isolated below.
        let keys = db.prepare("SELECT state_kind FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<'directory/identity0' AND state_kind>?2 ORDER BY state_kind LIMIT 100")?
            .query_map(params![DIRECTORY,after], |row| row.get::<_,String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for key in &keys {
            let id = key.strip_prefix(DIRECTORY).ok_or(StorageError::AuthorizationRejected)?;
            if let Err(error) = stamp_contact(db, key, scope) {
                let error_class = match error {
                    StorageError::Serde(_) => "record_decode",
                    StorageError::Protocol(_) => "authority_state",
                    _ => "storage",
                };
                tracing::warn!(
                    contact_id = id,
                    error_class,
                    "skipping legacy contact verification migration"
                );
            }
        }
        if keys.len() < 100 {
            return Ok(());
        }
        after.clone_from(keys.last().ok_or(StorageError::AuthorizationRejected)?);
    }
}

fn stamp_contact(db: &Connection, key: &str, scope: MigrationScope) -> Result<(), StorageError> {
    let Some(identity) = state::<Value>(db, key)? else {
        return Ok(());
    };
    let Some(root) = identity["contact_identity_commitment"].as_str() else {
        return Ok(());
    };
    if matches!(scope, MigrationScope::ImportedRows)
        && !db.query_row(
            "SELECT EXISTS(SELECT 1 FROM backup_imported_verification WHERE root=?1)",
            [root],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Ok(());
    }
    let verification: Option<(String,String)> = db.query_row(
        "SELECT verification_state,verified_device_set_hash FROM contact_verification_projection WHERE contact_identity_commitment=?1",
        [root], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
    let Some((status, hash)) = verification else {
        return Ok(());
    };
    if status != "verified" || identity["device_set_hash"].as_str() != Some(hash.as_str()) {
        return Ok(());
    }
    let stamp_key = format!("identity/safety_verified_set/{root}");
    if state::<String>(db, &stamp_key)?.is_some() {
        return Ok(());
    }
    let Some(observed) =
        state::<SignedDeviceSetRecord>(db, &format!("identity/signed_set/{root}"))?
    else {
        return Ok(());
    };
    let fingerprint = ramflux_protocol::device_set_authority_fingerprint(&observed)?;
    db.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO NOTHING", params![stamp_key,serde_json::to_vec(&fingerprint)?])?;
    Ok(())
}

impl super::backup_database::BackupDatabase {
    pub(super) fn begin_legacy_verification_import(
        &self,
        native_data_only: bool,
    ) -> Result<bool, StorageError> {
        let legacy = !native_data_only
            && !self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM incoming.runtime_actor_state WHERE state_kind=?1)",
                [LEGACY_SAFETY_VERIFICATION_MARKER],
                |row| row.get::<_, bool>(0),
            )?;
        if legacy {
            self.db.execute_batch(
                "CREATE TABLE backup_imported_verification(root TEXT PRIMARY KEY);",
            )?;
        }
        Ok(legacy)
    }

    pub(super) fn finish_legacy_verification_import(&self) -> Result<(), StorageError> {
        migrate_rows(&self.db, MigrationScope::ImportedRows)?;
        self.db.execute_batch("DROP TABLE backup_imported_verification;")?;
        Ok(())
    }
}
