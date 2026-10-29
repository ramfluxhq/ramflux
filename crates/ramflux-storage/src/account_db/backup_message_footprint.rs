// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relocation of opaque per-message copy ownership during private-generation merges.
use super::backup_database::BackupDatabase;
use crate::{AccountDbKey, StorageError};
use rusqlite::params;

impl BackupDatabase {
    pub(super) fn link_imported_message_footprints(
        &self,
        key: &AccountDbKey,
    ) -> Result<(), StorageError> {
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name='message_footprint')",[],|r|r.get(0))?;
        if !exists {
            return Ok(());
        }
        // A live opaque value inherits ownership only when this exact incoming value won.
        // Local newer values retain their locally registered owners. Archive rows are copied
        // separately and addressed by their new rowid, never the incoming rowid.
        self.db.execute_batch("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'actor',l.state_kind FROM incoming.message_footprint f JOIN incoming.runtime_actor_state r ON r.state_kind=f.locator JOIN runtime_actor_state l ON l.state_kind=r.state_kind AND l.state_json=r.state_json WHERE f.kind='actor';")?;
        let source = key.fingerprint();
        self.db.execute("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'archived_actor',CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN backup_archived_actor_state a ON a.state_kind=f.locator AND a.source=?1 WHERE f.kind='actor'",params![source])?;
        self.db.execute("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'archived_event',CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN backup_archived_local_event a ON a.event_id=f.locator AND a.source=?1 WHERE f.kind='event'",params![source])?;
        for (table, kind, key_column) in [
            ("backup_archived_actor_state", "archived_actor", "state_kind"),
            ("backup_archived_local_event", "archived_event", "event_id"),
        ] {
            let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name=?1)",[table],|r|r.get(0))?;
            if exists {
                self.db.execute(&format!("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,?1,CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN incoming.{table} r ON r.rowid=CAST(f.locator AS INTEGER) JOIN {table} a ON a.source=?2||'/'||r.source AND a.{key_column}=r.{key_column} WHERE f.kind=?1"),params![kind,source])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDb, AccountIndex};
    use serde_json::json;

    #[test]
    fn backup_merge_relocates_opaque_live_and_archived_footprints_before_applying_tombstones()
    -> Result<(), Box<dyn std::error::Error>> {
        for source_deleted in [false, true] {
            let root = crate::tests::temp_root(&format!("backup-footprint-{source_deleted}"));
            let source_index = AccountIndex::open(root.join("source"))?;
            let local_index = AccountIndex::open(root.join("local"))?;
            source_index.create_account("acct", "own-root")?;
            local_index.create_account("acct", "own-root")?;
            let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
            let local = AccountDb::open(&local_index, "acct", &AccountDbKey::generate()?)?;
            for db in [&source, &local] {
                db.send_direct_message("thread", "message", "private-peer", b"private-body")?;
                db.persist_message_actor_state(
                    "message",
                    "message/origin/opaque-origin",
                    &json!({"sender":"private-peer"}),
                )?;
                db.persist_message_watermark(
                    "message",
                    "thread",
                    "routed/commit-watermark/opaque",
                    &"routed/committed/private-unkeyed-hash",
                )?;
            }
            if source_deleted {
                source.delete_direct_message("thread", "message", "local", "delete")?;
            } else {
                local.delete_direct_message("thread", "message", "local", "delete")?;
            }
            let path = root.join("incoming.db");
            let incoming = source.write_backup_snapshot(&path)?;
            let target = root.join("target.db");
            let snapshot = local.write_backup_snapshot(&target)?;
            let mut merged = BackupDatabase::open(&target, &snapshot.key)?;
            merged.merge_backup(&path, &incoming.key, || Ok(()))?;
            for table in ["runtime_actor_state", "backup_archived_actor_state"] {
                let mut q =
                    merged.db.prepare(&format!("SELECT state_kind,state_json FROM {table}"))?;
                let rows = q
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                for (key, value) in rows {
                    for secret in ["private-peer", "private-unkeyed-hash"] {
                        assert!(
                            !key.contains(secret)
                                && !String::from_utf8_lossy(&value).contains(secret),
                            "residual in {table}: {key}"
                        );
                    }
                }
            }
            assert_eq!(
                merged.db.query_row(
                    "SELECT count(*) FROM message_footprint WHERE message_id='message'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            drop(merged);
            drop(source);
            drop(local);
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
