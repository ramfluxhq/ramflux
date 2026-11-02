// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Indexed attachment ownership and portable, append-only erasure fences.
mod actors;
mod holds;
mod resources;
mod schema;
use super::AccountDb;
use crate::StorageError;
pub use holds::PreSendObjectHold;
use ramflux_crypto::{object_erasure_commitment, object_erasure_lookup};
pub use resources::ObjectResourceRetirement;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::cell::Cell;
use std::sync::Arc;

pub(crate) use schema::install;
pub(super) use schema::{erasure_body, payload_erasure_body};

/// The reason an object may outlive message ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectRetention {
    Standalone,
    OwnDeviceTransport,
    PreSend { expires_at: i64 },
    Imported,
}

/// Exact authenticated reference and its per-message directory projection.
pub struct ObjectReferenceOwner<'a> {
    pub reference_hash: &'a str,
    pub wire_id: &'a str,
    pub manifest_hash: &'a str,
    pub selector: &'a str,
    pub message_id: &'a str,
    pub reference: &'a Value,
    pub metadata: &'a Value,
}

/// A committed retirement notification contains only opaque identity commitments.
pub type ObjectRetirementObserver = Arc<dyn Fn(Option<&[String]>) + Send + Sync>;

#[derive(Default)]
pub(super) struct RetirementObserver {
    pub callback: std::cell::RefCell<Option<ObjectRetirementObserver>>,
    pub cursor: Cell<i64>,
    pub resources: resources::Resources,
}

impl AccountDb {
    /// Authenticated root used to bind opaque object erasure identities.
    #[must_use]
    pub fn object_erasure_root(&self) -> &str {
        &self.principal_commitment
    }

    /// # Errors
    /// Returns storage errors while reading the current append-only fence generation.
    pub fn observe_object_retirement(
        &self,
        callback: ObjectRetirementObserver,
    ) -> Result<(), StorageError> {
        self.object_retirement.cursor.set(self.object_erasure_generation()?);
        *self.object_retirement.callback.borrow_mut() = Some(callback);
        Ok(())
    }

    /// # Errors
    /// Returns storage errors while reading the account-scoped erasure generation.
    pub fn object_erasure_generation(&self) -> Result<i64, StorageError> {
        Ok(self.connection.query_row(
            "SELECT COALESCE(MAX(rowid),0) FROM object_erasure_fence",
            [],
            |row| row.get(0),
        )?)
    }

    pub(super) fn notify_object_retirement(&self) -> Result<(), StorageError> {
        if !self.connection.is_autocommit()? {
            return Ok(());
        }
        let callback = self.object_retirement.callback.borrow().clone();
        let result = (|| -> Result<(), StorageError> {
            loop {
                let mut statement = self.connection.prepare("SELECT rowid,commitment FROM object_erasure_fence WHERE rowid>?1 ORDER BY rowid LIMIT 256")?;
                let rows = statement
                    .query_map(params![self.object_retirement.cursor.get()], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let Some((last, _)) = rows.last() else { break };
                if let Some(callback) = &callback {
                    callback(Some(
                        &rows.iter().map(|(_, digest)| digest.clone()).collect::<Vec<_>>(),
                    ));
                }
                resources::retire(
                    &self.object_retirement.resources,
                    Some(&rows.iter().map(|(_, digest)| digest.clone()).collect::<Vec<_>>()),
                )?;
                self.object_retirement.cursor.set(*last);
            }
            Ok(())
        })();
        if result.is_err() {
            if let Some(callback) = &callback {
                callback(None);
            }
        }
        result
    }

    /// # Errors
    /// Refuses retired identities before loading ciphertext or private reference state.
    pub fn check_object_identity(&self, wire: &str, manifest: &str) -> Result<(), StorageError> {
        let digest = object_erasure_commitment(&self.principal_commitment, wire, manifest);
        let erased: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_fence WHERE commitment=?1)",
            params![digest],
            |row| row.get(0),
        )?;
        if erased { Err(StorageError::ObjectErased) } else { Ok(()) }
    }

    /// # Errors
    /// Returns ObjectErased for an erased selector, including after payload removal.
    pub fn check_object_access(&self, selector: &str) -> Result<(), StorageError> {
        let current: Option<String> = self
            .connection
            .query_row(
                "SELECT CAST(manifest_hash AS TEXT) FROM object_index WHERE object_id=?1",
                params![selector],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(manifest) = current {
            return self.check_object_identity(selector, &manifest);
        }
        let reference: Option<(String,String)> = self.connection.query_row("SELECT p.wire_id,p.manifest_hash FROM object_retention_reference r JOIN object_retention_payload p USING(commitment) WHERE r.selector=?1 ORDER BY r.reference_hash LIMIT 1", params![selector], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((wire, manifest)) = reference {
            return self.check_object_identity(&wire, &manifest);
        }
        let lookup = object_erasure_lookup(&self.principal_commitment, selector);
        let erased: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_erasure_lookup WHERE lookup=?1)",
            params![lookup],
            |row| row.get(0),
        )?;
        if erased { Err(StorageError::ObjectErased) } else { Ok(()) }
    }

    /// # Errors
    /// Rejects erased identities and conflicting retention identities.
    pub fn retain_object(
        &self,
        wire: &str,
        manifest: &str,
        retention: ObjectRetention,
    ) -> Result<(), StorageError> {
        self.check_object_identity(wire, manifest)?;
        let (class, expiry) = match retention {
            ObjectRetention::Standalone => ("standalone", None),
            ObjectRetention::OwnDeviceTransport => ("transport", None),
            ObjectRetention::PreSend { expires_at } => {
                ("pre_send", Some(expires_at.min(self.now_unix().saturating_add(600))))
            }
            ObjectRetention::Imported => ("imported", None),
        };
        let digest = object_erasure_commitment(&self.principal_commitment, wire, manifest);
        let lookup = object_erasure_lookup(&self.principal_commitment, wire);
        self.connection.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class,hold_expires_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(commitment) DO UPDATE SET retention_class=CASE WHEN object_retention_payload.retention_class='standalone' THEN 'standalone' ELSE excluded.retention_class END,hold_expires_at=excluded.hold_expires_at", params![digest, wire, manifest, lookup, class, expiry])?;
        Ok(())
    }

    /// # Errors
    /// Registers each message even when a shared reference already exists; deleted messages fail closed.
    pub fn register_object_reference(
        &self,
        owner: &ObjectReferenceOwner<'_>,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            if self.message_is_deleted(owner.message_id)? { return Err(StorageError::ObjectErased); }
            self.check_object_identity(owner.wire_id, owner.manifest_hash)?;
            let digest = object_erasure_commitment(&self.principal_commitment, owner.wire_id, owner.manifest_hash);
            self.connection.execute("INSERT INTO object_retention_payload(commitment,wire_id,manifest_hash,wire_lookup,retention_class) VALUES(?1,?2,?3,?4,'imported') ON CONFLICT(commitment) DO UPDATE SET retention_class=CASE WHEN object_retention_payload.retention_class='pre_send' THEN 'imported' ELSE object_retention_payload.retention_class END,hold_expires_at=NULL", params![digest, owner.wire_id, owner.manifest_hash, object_erasure_lookup(&self.principal_commitment, owner.wire_id)])?;
            self.connection.execute("INSERT INTO object_retention_reference(reference_hash,commitment,selector,selector_lookup,reference_json) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(reference_hash) DO NOTHING", params![owner.reference_hash,digest,owner.selector,object_erasure_lookup(&self.principal_commitment, owner.selector),serde_json::to_vec(owner.reference)?])?;
            self.connection.execute("INSERT INTO object_message_reference(message_id,reference_hash,metadata_json) VALUES(?1,?2,?3) ON CONFLICT DO NOTHING", params![owner.message_id,owner.reference_hash,serde_json::to_vec(owner.metadata)?])?;
            self.connection.execute("INSERT INTO message_copy_binding VALUES(?1,?2) ON CONFLICT DO NOTHING", params![format!("object:{}",owner.selector),owner.message_id])?;
            self.connection.execute("INSERT INTO message_copy_binding VALUES(?1,?2) ON CONFLICT DO NOTHING", params![format!("object:{}",owner.wire_id),owner.message_id])?;
            // Copies already associated with the shared selector must gain the new owner too.
            self.connection.execute("INSERT INTO message_footprint SELECT ?1,f.kind,f.locator FROM message_copy_binding b JOIN message_footprint f ON f.message_id=b.message_id WHERE b.copy_id IN (?2,?3) AND (f.kind='actor' AND (f.locator GLOB 'attachment/*' OR f.locator GLOB 'sync/attachment/*' OR f.locator GLOB 'directory/object/*')) ON CONFLICT DO NOTHING", params![owner.message_id,format!("object:{}",owner.selector),format!("object:{}",owner.wire_id)])?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
