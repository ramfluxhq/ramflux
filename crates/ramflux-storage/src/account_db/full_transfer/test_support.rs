// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed fixture seeding only; end-to-end oracles use the ordinary object identity gate.
use crate::{AccountDb, StorageError};
impl AccountDb {
    /// Populate every currently compiled portable SQL owner for endpoint fixtures.
    /// # Errors
    /// Returns errors from the actual local writes and original-root MAC namespace.
    pub fn seed_full_transfer_supported_state_for_test(&self) -> Result<(), StorageError> {
        let h = |n: u8| ramflux_protocol::encode_base64url([n; 32]);
        self.write_transaction(|| {
            self.connection.execute(
                "UPDATE account_erasure_generation SET generation=max(generation,7)",
                [],
            )?;
            self.connection
                .execute("INSERT INTO object_erasure_fence VALUES(?1)", rusqlite::params![h(81)])?;
            self.connection.execute(
                "INSERT INTO object_identity_replacement VALUES(?1)",
                rusqlite::params![h(82)],
            )?;
            self.connection.execute(
                "INSERT INTO object_segment_reference_veto VALUES(?1)",
                rusqlite::params![[83_u8; 32].as_slice()],
            )?;
            self.connection.execute(
                "INSERT INTO object_erasure_lookup VALUES(?1,?2)",
                rusqlite::params![h(84), h(81)],
            )?;
            self.connection.execute(
                "INSERT INTO object_payload_dependency VALUES(?1,?2)",
                rusqlite::params![h(85), h(86)],
            )?;
            let source = ramflux_protocol::custody::DeviceRef {
                account_anchor: self.principal_commitment.clone(),
                device_id: "historical-pairing-fixture".into(),
                device_epoch: 1,
            };
            self.connection.call(move |db| {
                let keys = zeroize::Zeroizing::new([87_u8; 192]);
                let id = super::super::mac_subkeys::bundle_id(keys.as_slice());
                Ok(super::super::mac_subkeys::full::import_into_private_generation(
                    db,
                    &source,
                    &id,
                    keys.as_slice(),
                ))
            })??;
            Ok(())
        })
    }
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
    /// Remove only a source-local dependency assertion to exercise an authenticated absence.
    /// # Errors
    /// Returns local writer or database errors.
    pub fn remove_full_transfer_dependency_for_test(
        &self,
        parent_wire: &str,
        parent_manifest: &str,
        child_wire: &str,
        child_manifest: &str,
    ) -> Result<(), crate::StorageError> {
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
        self.write_transaction(|| {
            self.connection.execute(
                "DELETE FROM object_payload_dependency WHERE parent_commitment=?1 AND child_commitment=?2",
                rusqlite::params![parent, child],
            )?;
            Ok(())
        })
    }

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
