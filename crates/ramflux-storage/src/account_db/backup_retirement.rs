// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restored receive-only pairs have the same erasure semantics as ordinary retired pairs.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
impl AccountDb {
    /// Erases the retained private archive of a retired pair as well as its inactive marker.
    /// # Errors
    /// Returns SQL errors; callers checkpoint retired secrets after commit as usual.
    pub fn erase_backup_pair(&self, id: &str) -> Result<(), StorageError> {
        self.remove_actor_state(&format!("backup/inactive-pair/{id}"))?;
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='backup_archived_actor_state')",
            [],
            |r| r.get(0),
        )?;
        if exists {
            self.connection.execute(
                "DELETE FROM backup_archived_actor_state WHERE state_kind=?1 OR state_kind=?2",
                params![format!("dm-pair/session/{id}"), format!("dm-pair/bootstrap/{id}")],
            )?;
        }
        Ok(())
    }
    /// Retires unused restored receive chains after a 24-hour late-delivery window.
    /// # Errors
    /// Returns SQL errors. Legacy boolean markers acquire one durable migration deadline.
    pub fn expire_backup_pairs(&self, at: i64) -> Result<(), StorageError> {
        self.write_transaction(||->Result<(),StorageError>{
            self.connection.execute("UPDATE runtime_actor_state SET state_json=CAST(?1 AS BLOB) WHERE state_kind LIKE 'backup/inactive-pair/%' AND CAST(state_json AS TEXT) IN ('true','false')",params![at.to_string()])?;
            let mut after=String::new();
            loop {
                let mut q=self.connection.prepare("SELECT substr(state_kind,length('backup/inactive-pair/')+1) FROM runtime_actor_state WHERE state_kind LIKE 'backup/inactive-pair/%' AND CAST(state_json AS INTEGER)<=?1 AND state_kind>?2 ORDER BY state_kind LIMIT 64")?;
                let ids=q.query_map(params![at.saturating_sub(86400),after],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                if ids.is_empty(){break;}
                for id in ids {
                    after=format!("backup/inactive-pair/{id}");
                    self.persist_actor_state(&format!("dm-pair/retired/{id}"),&serde_json::json!({"retired_at":at}))?;
                    self.remove_actor_state(&format!("dm-pair/session/{id}"))?;
                    self.remove_actor_state(&format!("dm-pair/bootstrap/{id}"))?;
                    self.erase_backup_pair(&id)?;
                    self.persist_actor_state("secrets/retired",&true)?;
                }
            }
            self.prune_pair_metadata()?;Ok(())
        })
    }
}

impl super::backup_database::BackupDatabase {
    pub(super) fn discard_retired_pair_secrets(&self) -> Result<(), StorageError> {
        self.db.execute_batch("DELETE FROM runtime_actor_state WHERE (state_kind LIKE 'dm-pair/session/%' OR state_kind LIKE 'dm-pair/bootstrap/%') AND EXISTS(SELECT 1 FROM runtime_actor_state t WHERE t.state_kind='dm-pair/retired/'||substr(runtime_actor_state.state_kind,CASE WHEN runtime_actor_state.state_kind LIKE 'dm-pair/session/%' THEN 17 ELSE 19 END)); DELETE FROM backup_archived_actor_state WHERE (state_kind LIKE 'dm-pair/session/%' OR state_kind LIKE 'dm-pair/bootstrap/%') AND EXISTS(SELECT 1 FROM runtime_actor_state t WHERE t.state_kind='dm-pair/retired/'||substr(backup_archived_actor_state.state_kind,CASE WHEN backup_archived_actor_state.state_kind LIKE 'dm-pair/session/%' THEN 17 ELSE 19 END)); DELETE FROM runtime_actor_state WHERE state_kind LIKE 'backup/inactive-pair/%' AND EXISTS(SELECT 1 FROM runtime_actor_state t WHERE t.state_kind='dm-pair/retired/'||substr(runtime_actor_state.state_kind,22));")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inactive_receive_secrets_expire_after_the_late_delivery_window_including_archived_copies()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-backup-retention-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let key = crate::AccountDbKey::generate()?;
        let db = AccountDb::open(&index, "a", &key)?;
        db.persist_actor_state(
            "dm-pair/session/old",
            &serde_json::json!({"secret":"old private key"}),
        )?;
        super::super::backup_database::BackupDatabase::open(&db.path, &key)?.archive_outbound()?;
        db.persist_actor_state("backup/inactive-pair/old", &10)?;
        db.expire_backup_pairs(86409)?;
        assert!(db.actor_state_exists("dm-pair/session/old")?);
        db.expire_backup_pairs(86410)?;
        assert!(!db.actor_state_exists("dm-pair/session/old")?);
        assert!(db.actor_state_exists("dm-pair/retired/old")?);
        assert_eq!(db.connection.query_row("SELECT count(*) FROM backup_archived_actor_state WHERE state_kind='dm-pair/session/old'",[],|r|r.get::<_,u64>(0))?,0);
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
