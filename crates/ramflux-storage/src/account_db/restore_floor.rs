// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generic restore floors: unsigned counters never move backwards and newer schemas never merge.
use super::AccountDb;
use crate::StorageError;

/// What a writer does with a value below the stored floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloorPolicy {
    /// Refuse the write; the stored value is unchanged.
    Refuse,
    /// Keep the stored value and report it to the caller.
    Lift,
}

/// Exact unsigned maximum of a stored floor and a proposed value under `policy`.
/// # Errors
/// Returns `AuthorizationRejected` when `policy` refuses a value below the floor.
pub fn admit_floor(
    stored: Option<u64>,
    proposed: u64,
    policy: FloorPolicy,
) -> Result<u64, StorageError> {
    match stored {
        Some(floor) if proposed < floor && policy == FloorPolicy::Refuse => {
            Err(StorageError::AuthorizationRejected)
        }
        Some(floor) => Ok(floor.max(proposed)),
        None => Ok(proposed),
    }
}

impl AccountDb {
    /// Write a plain unsigned counter register so that it can only stay or grow.
    /// Returns the value in force after the write.
    /// # Errors
    /// Requires the caller's writer transaction; refuses a rollback under
    /// [`FloorPolicy::Refuse`] and returns SQL or stored JSON decoding errors.
    pub fn admit_actor_counter_floor(
        &self,
        key: &str,
        proposed: u64,
        policy: FloorPolicy,
    ) -> Result<u64, StorageError> {
        if self.connection.is_autocommit()? {
            return Err(StorageError::AuthorizationRejected);
        }
        let stored = self.load_actor_state::<u64>(key)?;
        let value = admit_floor(stored, proposed, policy)?;
        if stored != Some(value) {
            self.persist_actor_state(key, &value)?;
        }
        Ok(value)
    }
}

/// An archive written by a newer schema of the same generation cannot merge into this binary:
/// rows and floors this binary does not know would be dropped silently.
pub(super) fn refuse_schema_downgrade(db: &rusqlite::Connection) -> Result<(), StorageError> {
    let generation =
        db.query_row("PRAGMA incoming.user_version", [], |row| row.get::<_, i64>(0))?;
    crate::schema_generation::require(generation)?;
    let recorded: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name='schema_migration')",
        [],
        |row| row.get(0),
    )?;
    if !recorded {
        return Ok(());
    }
    let newest: i64 = db.query_row(
        "SELECT COALESCE(MAX(schema_version),0) FROM incoming.schema_migration",
        [],
        |row| row.get(0),
    )?;
    let supported = super::receive::schema_version();
    if newest > supported {
        return Err(StorageError::AccountSchemaTooNew { schema_version: newest, supported });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_db::backup_database::BackupDatabase;

    #[test]
    fn floor_admission_lifts_or_refuses_and_never_decreases() -> Result<(), StorageError> {
        assert_eq!(admit_floor(None, 0, FloorPolicy::Refuse)?, 0);
        assert_eq!(admit_floor(Some(7), 9, FloorPolicy::Refuse)?, 9);
        assert_eq!(admit_floor(Some(7), 7, FloorPolicy::Refuse)?, 7);
        assert!(admit_floor(Some(7), 6, FloorPolicy::Refuse).is_err());
        assert_eq!(admit_floor(Some(7), 6, FloorPolicy::Lift)?, 7);
        assert_eq!(admit_floor(Some(u64::MAX), u64::MAX - 1, FloorPolicy::Lift)?, u64::MAX);
        assert_eq!(admit_floor(Some(u64::MAX - 1), u64::MAX, FloorPolicy::Refuse)?, u64::MAX);
        Ok(())
    }

    #[test]
    fn actor_counter_floor_lifts_and_refuses_rollback() -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("actor-counter-floor")?;
        let _root_guard = crate::tests::TestDirGuard(root.clone());
        let key = "restore-floor-test/counter";
        assert!(db.admit_actor_counter_floor(key, 3, FloorPolicy::Lift).is_err());
        db.write_transaction(|| db.admit_actor_counter_floor(key, 1 << 62, FloorPolicy::Refuse))?;
        let refused: Result<u64, StorageError> =
            db.write_transaction(|| db.admit_actor_counter_floor(key, 5, FloorPolicy::Refuse));
        assert!(refused.is_err());
        assert_eq!(
            db.write_transaction(|| db.admit_actor_counter_floor(key, 5, FloorPolicy::Lift))?,
            1 << 62
        );
        assert_eq!(db.load_actor_state::<u64>(key)?, Some(1 << 62));
        assert_eq!(
            db.write_transaction(|| db.admit_actor_counter_floor(
                key,
                u64::MAX,
                FloorPolicy::Refuse
            ))?,
            u64::MAX
        );
        assert_eq!(db.load_actor_state::<u64>(key)?, Some(u64::MAX));
        drop(db);

        Ok(())
    }

    #[test]
    fn restore_refuses_archive_from_newer_schema_in_same_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source_root, source) = crate::tests::test_db("schema-downgrade-source")?;
        let _source_root_guard = crate::tests::TestDirGuard(source_root.clone());
        let (target_root, target) = crate::tests::test_db("schema-downgrade-target")?;
        let _target_root_guard = crate::tests::TestDirGuard(target_root.clone());
        source.persist_actor_state("message-identity/hlc/unreachable", &9_u64)?;
        source.connection.execute_batch(
            "CREATE TEMP TABLE newer_schema AS SELECT * FROM schema_migration ORDER BY schema_version DESC LIMIT 1;
             UPDATE newer_schema SET schema_version=schema_version+1000;
             INSERT INTO schema_migration SELECT * FROM newer_schema;",
        )?;
        let incoming = source_root.join("incoming.db");
        let first = source.write_backup_snapshot(&incoming)?;
        let path = target_root.join("merged.db");
        let second = target.write_backup_snapshot(&path)?;
        let mut merged = BackupDatabase::open(&path, &second.key)?;
        merged.attach(&incoming, &first.key)?;
        assert!(
            matches!(
                refuse_schema_downgrade(&merged.db),
                Err(StorageError::AccountSchemaTooNew { .. })
            ),
            "the initial schema fence must refuse before merge preparation, independently of later object-schema guards"
        );
        merged.db.execute_batch("DETACH DATABASE incoming")?;
        let before: i64 =
            merged
                .db
                .query_row("SELECT count(*) FROM runtime_actor_state", [], |row| row.get(0))?;
        let refused = merged.merge_backup(&incoming, &first.key, || Ok(()));
        assert!(
            matches!(refused, Err(StorageError::AccountSchemaTooNew { .. })),
            "a newer same-generation archive must be refused before any merge effect"
        );
        let after: i64 =
            merged
                .db
                .query_row("SELECT count(*) FROM runtime_actor_state", [], |row| row.get(0))?;
        assert_eq!(before, after);
        drop((merged, source, target));

        Ok(())
    }
}
