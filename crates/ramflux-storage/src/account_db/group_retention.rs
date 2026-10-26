// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Active group key scopes and diagnostic journals have independent bounded retention.
use super::AccountDb;
use crate::StorageError;
use rusqlite::{OptionalExtension, params};
impl AccountDb {
    pub(super) fn install_group_message_retention_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("             INSERT OR IGNORE INTO runtime_actor_state(state_kind,state_json)
                VALUES('group-message/upgrade-start',CAST(unixepoch() AS BLOB));
             UPDATE runtime_actor_state SET state_json=CAST(state_json AS BLOB)
                WHERE state_kind='group-message/upgrade-start' AND typeof(state_json)='text';
             CREATE TRIGGER IF NOT EXISTS group_alias_delete AFTER DELETE ON direct_message_projection
                BEGIN DELETE FROM runtime_actor_state WHERE state_kind='group-message/alias/'||OLD.message_id; END;
             CREATE TRIGGER IF NOT EXISTS group_alias_redact AFTER UPDATE OF deleted ON direct_message_projection
                WHEN NEW.deleted=1 BEGIN DELETE FROM runtime_actor_state WHERE state_kind='group-message/alias/'||NEW.message_id; END;
")?;
        Ok(())
    }

    /// Remove expired uncommitted message aliases; committed aliases live exactly
    /// as long as their message and are deleted by history-retention triggers.
    /// # Errors
    /// Returns database errors.
    pub fn retain_group_message_aliases(&self, now: i64) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM runtime_actor_state WHERE substr(state_kind,1,20)='group-message/alias/' AND NOT EXISTS(SELECT 1 FROM direct_message_projection m WHERE m.message_id=substr(state_kind,21) AND m.deleted=0) AND coalesce(json_extract(CAST(state_json AS TEXT),'$.expires_at'),0)<=?1",params![now])?;
        Ok(())
    }
    /// Retains at most 64 active key-head checkpoints per group, sender and direction.
    /// Historical event bodies remain governed by account history retention.
    /// # Errors
    /// Rejects non-group checkpoints or returns database failures.
    pub fn retain_group_key_checkpoint(
        &self,
        scope: &str,
        checkpoint: &str,
    ) -> Result<(), StorageError> {
        if !checkpoint.starts_with("group_sender_key:v3/") {
            return Err(StorageError::GroupPermissionDenied);
        }
        self.write_transaction(|| {
            let id=format!("group-key/scopes/{scope}");
            let mut scopes: Vec<String>=self.load_actor_state(&id)?.unwrap_or_default();
            scopes.retain(|key| key!=checkpoint); scopes.push(checkpoint.into());
            while scopes.len()>64 {
                let old=scopes.remove(0);
                self.connection.execute("DELETE FROM projection_checkpoint WHERE projection_name=?1 AND projection_name LIKE 'group_sender_key:v3/%'",params![old])?;
            }
            self.persist_actor_state(&id,&scopes)
        })
    }
    /// Appends bounded diagnostics, retaining 8 rows per device/group subject and 4096 total.
    /// # Errors
    /// Rejects unrelated topics or returns journal/database errors.
    pub fn append_group_journal(
        &self,
        source: &str,
        topic: &str,
        body: &serde_json::Value,
        at: i64,
        subject: &str,
    ) -> Result<(), StorageError> {
        if !matches!(topic, "group.state.conflict" | "group.state.delivery_failed") {
            return Err(StorageError::GroupPermissionDenied);
        }
        self.write_transaction(|| {
            self.append_journal(source,topic,body,at,Some(subject))?;
            let subject_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic=?1 AND subject=?2 ORDER BY seq DESC LIMIT 1 OFFSET 8",params![topic,subject],|row|row.get(0)).optional()?;
            let global_floor:Option<u64>=self.connection.query_row("SELECT seq FROM runtime_journal WHERE topic IN ('group.state.conflict','group.state.delivery_failed') ORDER BY seq DESC LIMIT 1 OFFSET 4096",[],|row|row.get(0)).optional()?;
            let cutoff=at.saturating_sub(7*86400);
            let condition="topic IN ('group.state.conflict','group.state.delivery_failed') AND (at<?1 OR seq<=?2 OR (topic=?3 AND subject=?4 AND seq<=?5))";
            let floor:Option<u64>=self.connection.query_row(&format!("SELECT max(seq) FROM runtime_journal WHERE {condition}"),params![cutoff,global_floor.unwrap_or(0),topic,subject,subject_floor.unwrap_or(0)],|row|row.get(0))?;
            self.connection.execute(&format!("DELETE FROM runtime_journal WHERE {condition}"),params![cutoff,global_floor.unwrap_or(0),topic,subject,subject_floor.unwrap_or(0)])?;
            if let Some(floor)=floor {self.connection.execute("UPDATE runtime_journal_bounds SET pruned_through=max(pruned_through,?1) WHERE singleton=1",params![floor])?;}
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upgrade_marker_is_a_typed_blob_and_repairs_text_without_renewing_the_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rf-group-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("a", "root")?;
        let db = AccountDb::open(&index, "a", &crate::AccountDbKey::derive("a", b"secret"))?;
        assert!(db.load_actor_state::<i64>("group-message/upgrade-start")?.is_some());
        db.connection.execute("UPDATE runtime_actor_state SET state_json='12345' WHERE state_kind='group-message/upgrade-start'",[])?;
        db.install_group_message_retention_schema()?;
        assert_eq!(db.load_actor_state::<i64>("group-message/upgrade-start")?, Some(12345));
        db.install_group_message_retention_schema()?;
        assert_eq!(db.load_actor_state::<i64>("group-message/upgrade-start")?, Some(12345));
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
