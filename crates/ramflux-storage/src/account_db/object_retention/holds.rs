// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A cancelled send releases its unconverted hold; durable expiry covers process death.
use super::*;

/// Owns a bounded, provisional retention claim until send success converts it to message edges.
pub struct PreSendObjectHold {
    connection: crate::database::Connection,
    commitment: String,
    observer: Option<ObjectRetirementObserver>,
    armed: bool,
    resources: resources::Resources,
}

impl PreSendObjectHold {
    /// # Errors
    /// Returns transactional cleanup errors; the durable expiry remains available for recovery.
    pub fn release(mut self) -> Result<(), StorageError> {
        self.release_inner()?;
        self.armed = false;
        Ok(())
    }

    fn release_inner(&self) -> Result<(), StorageError> {
        let transaction = self.connection.immediate_transaction()?;
        self.connection.execute("DELETE FROM object_erasure_work", [])?;
        let changed = self.connection.execute("INSERT INTO object_erasure_work SELECT commitment,wire_id,manifest_hash FROM object_retention_payload p WHERE commitment=?1 AND retention_class='pre_send' AND NOT EXISTS(SELECT 1 FROM object_retention_reference r WHERE r.commitment=p.commitment)", params![self.commitment])?;
        let sql = self.connection.call(|db| schema::payload_erasure_body(db))?;
        self.connection.execute_batch(&sql)?;
        transaction.commit()?;
        if changed > 0 {
            if let Some(observer) = &self.observer {
                observer(Some(std::slice::from_ref(&self.commitment)));
            }
            resources::retire(&self.resources, Some(std::slice::from_ref(&self.commitment)))?;
        }
        Ok(())
    }
}

impl Drop for PreSendObjectHold {
    fn drop(&mut self) {
        if self.armed && self.release_inner().is_err() {
            tracing::warn!(
                error_code = "object_hold_cleanup_failed",
                "provisional object cleanup deferred to durable expiry"
            );
        }
    }
}

impl AccountDb {
    /// # Errors
    /// Creates a hold with a maximum lifetime of ten minutes, without copying keys or payloads.
    pub fn pre_send_object_hold(
        &self,
        wire: &str,
        manifest: &str,
    ) -> Result<PreSendObjectHold, StorageError> {
        self.retain_object(
            wire,
            manifest,
            ObjectRetention::PreSend { expires_at: self.now_unix().saturating_add(600) },
        )?;
        Ok(PreSendObjectHold {
            connection: self.connection.clone(),
            commitment: object_erasure_commitment(&self.principal_commitment, wire, manifest),
            observer: self.object_retirement.callback.borrow().clone(),
            armed: true,
            resources: Arc::clone(&self.object_retirement.resources),
        })
    }
}
