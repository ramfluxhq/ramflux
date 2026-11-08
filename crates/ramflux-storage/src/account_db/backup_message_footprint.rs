// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Relocation of opaque per-message copy ownership during private-generation merges.
use super::backup_database::BackupDatabase;
use crate::{AccountDbKey, StorageError};
use rusqlite::params;
use std::collections::BTreeSet;

impl BackupDatabase {
    pub(super) fn link_imported_message_footprints(
        &self,
        key: &AccountDbKey,
        native_data_only: bool,
    ) -> Result<(), StorageError> {
        // Tombstones are unioned here, inside the merge transaction, after the MAC bundle set
        // has been merged and before publication; the generic row merge skips the table.
        super::receive::erased_input::merge_from(&self.db, "incoming")?;
        if !native_data_only {
            let raw_conflict: bool = self.db.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM incoming.raw_inner_owner i JOIN main.raw_inner_owner l USING(owner_id)
                     WHERE i.source_anchor<>l.source_anchor
                 ) OR EXISTS(
                     SELECT 1 FROM incoming.raw_inner_copy i JOIN main.raw_inner_copy l USING(copy_id)
                     WHERE i.owner_id<>l.owner_id OR i.copy_kind<>l.copy_kind
                        OR i.raw_digest<>l.raw_digest OR i.raw_bytes<>l.raw_bytes
                 )",
                [],
                |row| row.get(0),
            )?;
            if raw_conflict {
                return Err(StorageError::AuthorizationRejected);
            }
        }
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name='message_footprint')",[],|r|r.get(0))?;
        if !exists {
            return Ok(super::message_footprint::migration::register_imported(&self.db)?);
        }
        let candidate = super::backup_selector_admission::placeholders::active(&self.db)?;
        let actor = if candidate {
            super::backup_selector_admission::preservation::expression(
                "runtime_actor_state",
                "state_json",
            )
        } else {
            "r.state_json".into()
        };
        // Message footprints restrict surviving copies, including redacted copies;
        // attachment admission must never remove their message ownership.
        // A live opaque value inherits ownership only when its incoming projection won.
        // Local newer values retain their locally registered owners. Archive rows are copied
        // separately and addressed by their new rowid, never the incoming rowid.
        self.db.execute_batch(&format!("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'actor',l.state_kind FROM incoming.message_footprint f JOIN incoming.runtime_actor_state r ON r.state_kind=f.locator JOIN runtime_actor_state l ON l.state_kind=r.state_kind AND l.state_json={actor} WHERE f.kind='actor';"))?;
        let source = key.fingerprint();
        self.db.execute("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'archived_actor',CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN incoming.runtime_actor_state r ON r.state_kind=f.locator JOIN backup_archived_actor_state a ON a.state_kind=f.locator AND a.source=?1 WHERE f.kind='actor'",params![source])?;
        self.db.execute("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,'archived_event',CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN incoming.local_event_log r ON r.event_id=f.locator JOIN backup_archived_local_event a ON a.event_id=f.locator AND a.source=?1 WHERE f.kind='event'",params![source])?;
        for (table, kind, key_column) in [
            ("backup_archived_actor_state", "archived_actor", "state_kind"),
            ("backup_archived_local_event", "archived_event", "event_id"),
        ] {
            let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM incoming.sqlite_master WHERE type='table' AND name=?1)",[table],|r|r.get(0))?;
            if exists {
                self.db.execute(&format!("INSERT OR IGNORE INTO message_footprint SELECT f.message_id,?1,CAST(a.rowid AS TEXT) FROM incoming.message_footprint f JOIN incoming.{table} r ON r.rowid=CAST(f.locator AS INTEGER) JOIN {table} a ON a.source=?2||'/'||r.source AND a.{key_column}=r.{key_column} WHERE f.kind=?1"),params![kind,source])?;
            }
        }
        if !native_data_only {
            self.erase_deleted_raw_rows()?;
            self.db.execute_batch(
                "DELETE FROM message_copy_binding
                 WHERE copy_id IN (
                     SELECT b.copy_id FROM incoming.message_copy_binding b
                     JOIN incoming.raw_inner_copy i ON b.copy_id='raw:'||i.copy_id
                     JOIN raw_inner_copy c ON c.copy_id=i.copy_id
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM incoming.message_copy_binding b
                     WHERE b.copy_id=message_copy_binding.copy_id
                       AND b.message_id=message_copy_binding.message_id
                 );
                 DELETE FROM message_footprint
                 WHERE kind='raw_inner'
                   AND locator IN (SELECT copy_id FROM incoming.raw_inner_copy)
                   AND NOT EXISTS (
                     SELECT 1 FROM incoming.message_copy_binding b
                     WHERE b.copy_id='raw:'||message_footprint.locator
                       AND b.message_id=message_footprint.message_id
                   );
                 INSERT OR IGNORE INTO message_copy_binding(copy_id,message_id)
                 SELECT b.copy_id,b.message_id FROM incoming.message_copy_binding b
                 JOIN incoming.raw_inner_copy i ON b.copy_id='raw:'||i.copy_id
                 JOIN raw_inner_copy c ON c.copy_id=i.copy_id;
                 INSERT OR IGNORE INTO message_footprint(message_id,kind,locator)
                 SELECT b.message_id,'raw_inner',c.copy_id FROM raw_inner_copy c
                 JOIN message_copy_binding b ON b.copy_id='raw:'||c.copy_id;
                 INSERT OR IGNORE INTO message_footprint(message_id,kind,locator)
                 SELECT message_id,'raw_inner_evidence',message_id FROM raw_inner_evidence;",
            )?;
            super::raw_inner::quota::validate_all(&self.db)?;
        }
        self.db.execute(
            "INSERT OR IGNORE INTO message_footprint
             SELECT f.message_id,'archived_actor',CAST(a.rowid AS TEXT)
             FROM incoming.message_footprint f
             JOIN backup_archived_actor_state a
               ON a.state_kind=f.locator AND a.source=?1
             WHERE f.kind IN ('prepared','history_container')",
            params![source],
        )?;
        Ok(super::message_footprint::migration::register_imported(&self.db)?)
    }

    fn erase_deleted_raw_rows(&self) -> Result<(), StorageError> {
        let owners = {
            let mut query = self.db.prepare("SELECT owner_id FROM raw_inner_owner")?;
            query
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut deleted_owners = BTreeSet::new();
        for owner in owners {
            if super::raw_inner::message_deleted(&self.db, &owner)? {
                deleted_owners.insert(owner);
            }
        }

        let copies = {
            let mut query = self.db.prepare("SELECT copy_id FROM raw_inner_copy")?;
            query
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut deleted_copies = BTreeSet::new();
        for copy_id in copies {
            if super::raw_inner::raw_copy_deleted(&self.db, &copy_id)? {
                deleted_copies.insert(copy_id);
            }
        }

        let bound_targets = {
            let mut query = self.db.prepare(
                "SELECT c.copy_id,b.message_id FROM incoming.raw_inner_copy c
                 JOIN incoming.message_copy_binding b ON b.copy_id='raw:'||c.copy_id
                 UNION
                 SELECT c.copy_id,b.message_id FROM main.raw_inner_copy c
                 JOIN main.message_copy_binding b ON b.copy_id='raw:'||c.copy_id",
            )?;
            query
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (copy_id, message_id) in bound_targets {
            if super::raw_inner::message_deleted(&self.db, &message_id)? {
                deleted_copies.insert(copy_id);
            }
        }

        let evidence_messages = {
            let mut query = self.db.prepare("SELECT message_id FROM raw_inner_evidence")?;
            query
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut deleted_evidence = Vec::new();
        for message_id in evidence_messages {
            if super::raw_inner::message_deleted(&self.db, &message_id)? {
                deleted_evidence.push(message_id);
            }
        }

        for owner_id in deleted_owners {
            self.db.execute(
                "DELETE FROM message_copy_binding WHERE copy_id IN
                 (SELECT 'raw:'||copy_id FROM raw_inner_copy WHERE owner_id=?1)",
                [&owner_id],
            )?;
            self.db.execute(
                "DELETE FROM message_footprint WHERE kind='raw_inner' AND locator IN
                 (SELECT copy_id FROM raw_inner_copy WHERE owner_id=?1)",
                [&owner_id],
            )?;
            self.db.execute("DELETE FROM raw_inner_copy WHERE owner_id=?1", [&owner_id])?;
            self.db.execute("DELETE FROM raw_inner_owner WHERE owner_id=?1", [owner_id])?;
        }
        for copy_id in deleted_copies {
            self.db.execute(
                "DELETE FROM message_copy_binding WHERE copy_id=?1",
                [format!("raw:{copy_id}")],
            )?;
            self.db.execute(
                "DELETE FROM message_footprint WHERE kind='raw_inner' AND locator=?1",
                [&copy_id],
            )?;
            self.db.execute("DELETE FROM raw_inner_copy WHERE copy_id=?1", [copy_id])?;
        }
        for message_id in deleted_evidence {
            self.db.execute("DELETE FROM raw_inner_evidence WHERE message_id=?1", [&message_id])?;
            self.db.execute(
                "DELETE FROM message_footprint WHERE kind='raw_inner_evidence' AND message_id=?1",
                [message_id],
            )?;
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

    #[test]
    fn deleted_raw_rows_are_removed_at_the_full_merge_footprint_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::tests::temp_root("backup-footprint-raw-delete-boundary");
        let source_index = AccountIndex::open(root.join("source"))?;
        let target_index = AccountIndex::open(root.join("target"))?;
        source_index.create_account("acct", "own-root")?;
        target_index.create_account("acct", "own-root")?;
        let source = AccountDb::open(&source_index, "acct", &AccountDbKey::generate()?)?;
        let target = AccountDb::open(&target_index, "acct", &AccountDbKey::generate()?)?;
        for db in [&source, &target] {
            db.send_direct_message("thread", "message-target", "peer", b"body")?;
            db.write_transaction(|| {
                db.put_unsupported_raw_copy(super::super::raw_inner::RawInnerCopyWrite {
                    owner_id: "copy:authenticated-envelope",
                    verified_source_anchor: "verified-root",
                    copy_id: "bound-copy",
                    kind: super::super::raw_inner::RawInnerCopyKind::NestedGroup,
                    bytes: b"stale bound bytes",
                    bounded_metadata: b"{}",
                })?;
                db.bind_raw_inner_copy("bound-copy", "message-target")
            })?;
            db.write_transaction(|| {
                db.put_known_content_evidence(
                    "message-target",
                    "thread",
                    b"known content",
                    b"private provenance",
                    b"private opening",
                )
            })?;
        }
        target.delete_direct_message("thread", "message-target", "peer", "delete")?;

        let source_path = root.join("incoming.db");
        let source_snapshot = source.write_backup_snapshot(&source_path)?;
        let target_path = root.join("target.db");
        let target_snapshot = target.write_backup_snapshot(&target_path)?;
        let merged = BackupDatabase::open(&target_path, &target_snapshot.key)?;
        merged.attach(&source_path, &source_snapshot.key)?;
        // Recreate the generic row-merge result to exercise this final deletion guard directly.
        merged.db.execute_batch(
            "INSERT INTO main.raw_inner_owner SELECT * FROM incoming.raw_inner_owner;
             INSERT INTO main.raw_inner_copy SELECT * FROM incoming.raw_inner_copy;
             INSERT INTO main.raw_inner_evidence SELECT * FROM incoming.raw_inner_evidence;
             INSERT INTO main.message_copy_binding SELECT * FROM incoming.message_copy_binding
                WHERE copy_id='raw:bound-copy';",
        )?;

        merged.erase_deleted_raw_rows()?;

        for table in ["raw_inner_copy", "raw_inner_owner", "raw_inner_evidence"] {
            assert_eq!(
                merged.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get::<_, u64>(0)
                })?,
                0,
                "deleted raw data survived in {table}"
            );
        }
        assert_eq!(
            merged.db.query_row(
                "SELECT count(*) FROM message_copy_binding WHERE copy_id='raw:bound-copy'",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );
        drop(merged);
        drop(source);
        drop(target);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
