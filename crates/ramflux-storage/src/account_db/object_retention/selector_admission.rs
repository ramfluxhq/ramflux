// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit freshness and independently admitted ownership govern selector access.
use super::*;

/// Authority under which an authenticated reference enters the live account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectReferenceAdmission {
    /// Newly authenticated outgoing or incoming message.
    FreshMessage,
    /// Historical reference from an account archive.
    Restore,
    /// Historical reference reconstructed by bounded discovery.
    ArchiveDiscovery,
    /// Historical reference carried by signed own-device history.
    OwnCopy,
}

impl AccountDb {
    pub(super) fn check_selector_lookup(&self, selector: &str) -> Result<(), StorageError> {
        let lookup = object_erasure_lookup(&self.principal_commitment, selector);
        let erased: bool = self.erasure_authority.as_ref().unwrap_or(&self.connection).query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
            params![lookup],
            |row| row.get(0),
        )?;
        if erased { Err(StorageError::ObjectErased) } else { Ok(()) }
    }

    /// Resolve only references with an independently admitted, non-deleted owner.
    pub(super) fn admitted_selector_identity(
        &self,
        selector: &str,
        expected: Option<(&str, &str)>,
    ) -> Result<Option<(String, String)>, StorageError> {
        let authority = self.erasure_authority.as_ref().unwrap_or(&self.connection);
        let rows = authority
            .prepare(&identity_query("main"))?
            .query_map(params![selector], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        resolve_admitted_identity(rows, expected, |wire, manifest, message| {
            if self.message_is_deleted(message)? {
                return Ok(false);
            }
            self.check_object_identity(wire, manifest)?;
            Ok(true)
        })
    }

    pub(super) fn check_reference_admission(
        &self,
        admission: ObjectReferenceAdmission,
        owner: &ObjectReferenceOwner<'_>,
    ) -> Result<(), StorageError> {
        // Validate hash identity before inserting any payload or ownership row.
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT commitment FROM object_retention_reference WHERE reference_hash=?1",
                params![owner.reference_hash],
                |row| row.get(0),
            )
            .optional()?;
        let digest = object_erasure_commitment(
            &self.principal_commitment,
            owner.wire_id,
            owner.manifest_hash,
        );
        if existing.is_some_and(|commitment| commitment != digest) {
            return Err(StorageError::AuthorizationRejected);
        }
        if admission != ObjectReferenceAdmission::FreshMessage {
            match self.check_selector_lookup(owner.selector) {
                Ok(()) => return Ok(()),
                Err(StorageError::ObjectErased) => {}
                Err(error) => return Err(error),
            }
            let survivor = self.admitted_selector_identity(
                owner.selector,
                Some((owner.wire_id, owner.manifest_hash)),
            )?;
            if survivor.as_ref().is_none_or(|(wire, manifest)| {
                wire != owner.wire_id || manifest != owner.manifest_hash
            }) {
                // Preserve I/O errors from the authority query.
                self.check_selector_lookup(owner.selector)?;
            }
        }
        Ok(())
    }
}

/// Shared G6 identity traversal; callers supply live or restore admission authority.
pub(in crate::account_db) fn identity_query(schema: &str) -> String {
    format!(
        "SELECT p.wire_id,p.manifest_hash,m.message_id FROM {schema}.object_retention_reference r
         JOIN {schema}.object_retention_payload p USING(commitment)
         JOIN {schema}.object_message_reference m USING(reference_hash)
         WHERE r.selector=?1 ORDER BY r.reference_hash,m.message_id"
    )
}

pub(in crate::account_db) fn resolve_admitted_identity(
    rows: Vec<(String, String, String)>,
    expected: Option<(&str, &str)>,
    mut admitted: impl FnMut(&str, &str, &str) -> Result<bool, StorageError>,
) -> Result<Option<(String, String)>, StorageError> {
    for (wire, manifest, message) in rows {
        if expected.is_some_and(|(w, m)| w != wire || m != manifest) {
            continue;
        }
        if admitted(&wire, &manifest, &message)? {
            return Ok(Some((wire, manifest)));
        }
    }
    Ok(None)
}
