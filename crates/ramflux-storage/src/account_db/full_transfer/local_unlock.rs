// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Weak liveness of an actual unlocked writer, without retaining its connection or key.
use super::source_scalar::SourceGuard;
use crate::{AccountDb, StorageError};

/// Local data-unlock liveness only. This contains no database loan, stage key, signing
/// permission, SAS confirmation, generation reservation or native publication authority.
/// An ordinary write does not invalidate it; locking, removing or selecting another data
/// generation does. A subsequent unlock cannot revive a guard from the old writer.
pub struct FullLocalUnlockGuard(SourceGuard);
impl FullLocalUnlockGuard {
    /// Check the same original unlocked writer and selected root/path/account again.
    /// # Errors
    /// Refuses a locked/dead writer, a removed account or a changed selected generation.
    pub fn require_unlocked(&self) -> Result<(), StorageError> {
        crate::database::require_generation_rebase_deadline()?;
        self.0.require()
    }
}
impl AccountDb {
    /// Issue a weak data-only liveness guard while the actual ordinary writer is borrowed.
    /// Drop the loan before network I/O; consumers must recheck before/after each local use.
    /// # Errors
    /// Refuses query-only snapshots, stale selected scope or a missing actual unlock owner.
    pub fn full_local_unlock_guard(&self) -> Result<FullLocalUnlockGuard, StorageError> {
        self.require_full_stage_unlock()?;
        let guard = FullLocalUnlockGuard(SourceGuard::new(self, None));
        guard.require_unlocked()?;
        Ok(guard)
    }
}

#[cfg(test)]
mod tests {
    use crate::{AccountDb, AccountDbKey, AccountIndex};
    #[test]
    fn pairing_full_local_unlock_guard_does_not_retain_or_revive_original_writer()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("full-local-unlock-guard")?;
        let guard = db.full_local_unlock_guard()?;
        guard.require_unlocked()?;
        // Background proof signing must allow concurrent ordinary writes, not quiesce A.
        db.persist_actor_state("full-guard-ordinary-write", &1_u64)?;
        guard.require_unlocked()?;
        let (reader, _) = db.pin_full_transfer_target()?;
        drop(db);
        assert!(guard.require_unlocked().is_err(), "read view retained the real unlock owner");
        let index = AccountIndex::open(&root)?;
        let reopened =
            AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"storage-test-secret"))?;
        assert!(guard.require_unlocked().is_err(), "new unlock revived an old signer scope");
        reopened.full_local_unlock_guard()?.require_unlocked()?;
        drop(reader);
        drop(reopened);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
