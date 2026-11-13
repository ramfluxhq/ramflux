// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Terminal stage reclamation requires independent actual-account completion evidence.
use super::completion::Completion;
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::{VerifiedRecord, pairing::verify_full_tail_authority};
use rusqlite::{OptionalExtension as _, params};
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl AccountDb {
    /// Expiry closes only original A's saved tail opportunity; ordinary A data is retained.
    /// The tail remains visibly pending. No later view may replace the lost immutable cut.
    /// # Errors
    /// Refuses a foreign generation, missing J6/cleanup evidence, non-source role or live lease.
    pub fn expire_full_source_tail(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<(), StorageError> {
        if self.full_completion(operation, generation, "initiator", now)?.is_some() {
            return Ok(());
        }
        let Some((stage, status)) = self.source_tail_status_stage(operation, generation, now)?
        else {
            return Err(wrong());
        };
        if now < stage.reference().lease_expires_at.0 || status != "pending" {
            return Err(wrong());
        }
        let completion = Completion::from_stage(&stage, operation, "expired", None)?;
        stage.connection.execute(
            "INSERT INTO data_terminal VALUES(1,'expired') ON CONFLICT(singleton) DO NOTHING",
            [],
        )?;
        super::stage::sync_stage(&stage.directory)?;
        self.write_transaction(|| self.retain_full_completion(&completion, now))
    }
    /// Remove only this terminal operation's private stage after local jobs are cancelled/drained.
    /// The exclusive stage lock also excludes any remaining off-loan byte/key worker.
    /// No account database, selected generation, ordinary object or vault item is removed.
    /// # Errors
    /// Refuses missing/foreign completion evidence, active workers, unsafe paths or I/O failure.
    pub fn reclaim_full_tail_stage(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<bool, StorageError> {
        self.require_full_stage_unlock()?;
        let row: Option<(String,bool)> = self.connection.query_row(
            "SELECT role,cleanup_state='done' FROM pairing_full_completion WHERE operation_id=?1",
            params![operation], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        let Some((role, done)) = row else {
            return Ok(false);
        };
        let completion =
            self.full_completion(operation, generation, &role, now)?.ok_or_else(wrong)?;
        if done {
            return Ok(true);
        }
        if completion.outcome() == "expired" && now < completion.expires_at() {
            return Err(wrong());
        }
        let directory = match super::stage::stage_directory(self, completion.stage_id(), false) {
            Ok(path) => Some(path),
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(directory) = directory {
            let lock = match super::stage::open_regular(&directory.join("stage.lock"), true) {
                Ok(file) => {
                    fs2::FileExt::try_lock_exclusive(&file)?;
                    Some(file)
                }
                Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    None
                }
                Err(error) => return Err(error),
            };
            let parent = directory.parent().ok_or_else(wrong)?;
            std::fs::remove_dir_all(&directory)?;
            std::fs::File::open(parent)?.sync_all()?;
            drop(lock);
        }
        self.write_transaction(|| {
            self.connection.execute("DELETE FROM pairing_full_tail_dependency WHERE operation_id=?1", params![operation])?;
            self.connection.execute("DELETE FROM pairing_full_tail_apply WHERE operation_id=?1 AND tail_status IN('merged','abandoned')", params![operation])?;
        if self.connection.execute("UPDATE pairing_full_completion SET cleanup_state='done' WHERE operation_id=?1 AND generation=?2", params![operation,generation])? != 1 { return Err(wrong()); }
            Ok(())
        })?;
        Ok(true)
    }
    /// Recheck only the data-only predicate for an exact cached reply in an existing epoch.
    /// This can never construct a signer, reader, fresh epoch or a new data opportunity.
    /// # Errors
    /// Refuses absent terminal evidence, expired lease, changed original roles/keys or stale scope.
    pub fn admit_cached_full_tail_reply(
        &self,
        operation: &str,
        generation: u64,
        current: &VerifiedRecord,
        now: u64,
    ) -> Result<(), StorageError> {
        let completion =
            self.full_completion(operation, generation, "responder", now)?.ok_or_else(wrong)?;
        if completion.outcome() != "merged" {
            return Err(wrong());
        }
        let scope = completion.scope();
        if now >= scope.lease_expires_at {
            return Err(StorageError::PairingField("LeaseExpired"));
        }
        verify_full_tail_authority(&scope.grant, current, now).map_err(|error| match error {
            ramflux_crypto::CryptoError::Pairing("LeaseExpired") => {
                StorageError::PairingField("LeaseExpired")
            }
            _ => StorageError::PairingField("HeadChanged"),
        })
    }
}
