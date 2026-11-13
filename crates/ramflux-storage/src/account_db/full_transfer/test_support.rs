// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed fixture seeding only; end-to-end oracles use the ordinary object identity gate.
use crate::{AccountDb, StorageError};
impl AccountDb {
    /// Seed one actual append-only fixture veto and its max generation without importing payload.
    /// This exists solely under the preexisting storage instrumentation feature used by SDK tests.
    /// # Errors
    /// Refuses oversized fixture identities/generation and actual transaction failures.
    pub fn seed_full_transfer_object_veto_for_test(
        &self,
        wire: &str,
        manifest: &str,
        generation: u64,
    ) -> Result<(), StorageError> {
        if wire.is_empty()
            || manifest.is_empty()
            || wire.len() > 256
            || manifest.len() > 256
            || generation > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            return Err(StorageError::PairingField("UnsupportedRecord"));
        }
        let commitment =
            ramflux_crypto::object_erasure_commitment(&self.principal_commitment, wire, manifest);
        self.write_transaction(|| {
            self.connection.execute("INSERT INTO object_erasure_fence VALUES(?1) ON CONFLICT DO NOTHING",rusqlite::params![commitment])?;
            self.connection.execute("UPDATE account_erasure_generation SET generation=max(generation,?1) WHERE singleton=1",rusqlite::params![generation])?;
            Ok(())
        })
    }
}

impl crate::AccountDb {
    /// Inspect one actual portable dependency in component fixtures without exposing SQL.
    /// # Errors
    /// Returns local database errors.
    pub fn full_transfer_dependency_present_for_test(
        &self,
        parent_wire: &str,
        parent_manifest: &str,
        child_wire: &str,
        child_manifest: &str,
    ) -> Result<bool, crate::StorageError> {
        let parent = ramflux_crypto::object_erasure_commitment(
            &self.principal_commitment,
            parent_wire,
            parent_manifest,
        );
        let child = ramflux_crypto::object_erasure_commitment(
            &self.principal_commitment,
            child_wire,
            child_manifest,
        );
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2)", rusqlite::params![parent,child], |row| row.get(0))?)
    }
}

#[cfg(test)]
pub(super) fn owned_source_test_db(
    name: &str,
) -> Result<(tempfile::TempDir, AccountDb), StorageError> {
    let root = tempfile::Builder::new().prefix(&format!("ramflux-storage-{name}-")).tempdir()?;
    let index = crate::AccountIndex::open(root.path())?;
    index.create_account("acct", "principal")?;
    let key = crate::AccountDbKey::derive("acct", b"storage-test-secret");
    let db = AccountDb::open(&index, "acct", &key)?;
    Ok((root, db))
}
