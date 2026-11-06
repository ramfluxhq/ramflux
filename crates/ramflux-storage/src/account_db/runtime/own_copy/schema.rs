// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Derived indexes contain no new message identities and follow every write, rollback and erasure.
use super::*;
impl AccountDb {
    pub(in super::super) fn install_own_copy_schema(&self) -> Result<(), StorageError> {
        let installed: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_own_copy_state')", [], |row| row.get(0))?;
        let upgrade_send_index = installed && self.connection.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='own_copy_index_3_INSERT' AND instr(sql,'$.intent.expires_at')>0)",
            [], |row| row.get::<_, bool>(0),
        )?;
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS runtime_own_copy_state(
                state_kind TEXT PRIMARY KEY,namespace TEXT NOT NULL,bytes INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,completed INTEGER NOT NULL,next_attempt_at INTEGER);
             CREATE INDEX IF NOT EXISTS runtime_own_copy_expiry ON runtime_own_copy_state(namespace,expires_at,state_kind);
             CREATE INDEX IF NOT EXISTS runtime_own_copy_eviction ON runtime_own_copy_state(namespace,completed DESC,expires_at,state_kind);
             CREATE INDEX IF NOT EXISTS runtime_own_copy_due ON runtime_own_copy_state(namespace,next_attempt_at,state_kind);
             CREATE TABLE IF NOT EXISTS runtime_own_copy_usage(namespace TEXT PRIMARY KEY,rows INTEGER NOT NULL,bytes INTEGER NOT NULL,next_cleanup_at INTEGER NOT NULL DEFAULT 0);
             CREATE TRIGGER IF NOT EXISTS own_copy_count_insert AFTER INSERT ON runtime_own_copy_state BEGIN
                UPDATE runtime_own_copy_usage SET rows=rows+1,bytes=bytes+NEW.bytes WHERE namespace=NEW.namespace; END;
             CREATE TRIGGER IF NOT EXISTS own_copy_count_update AFTER UPDATE ON runtime_own_copy_state BEGIN
                UPDATE runtime_own_copy_usage SET bytes=bytes+NEW.bytes-OLD.bytes WHERE namespace=NEW.namespace; END;
             CREATE TRIGGER IF NOT EXISTS own_copy_count_delete AFTER DELETE ON runtime_own_copy_state BEGIN
                UPDATE runtime_own_copy_usage SET rows=rows-1,bytes=bytes-OLD.bytes WHERE namespace=OLD.namespace; END;",
        )?;
        for (index, prefix) in PREFIXES.iter().enumerate() {
            self.connection.execute(
                "INSERT OR IGNORE INTO runtime_own_copy_usage(namespace,rows,bytes) VALUES(?1,0,0)",
                params![prefix],
            )?;
            let end = format!("{}0", prefix.trim_end_matches('/'));
            // Parse only the row being changed. The bounded target list is indexed once on write,
            // never deserialized again by an idle sender pass.
            let json = "CASE WHEN json_valid(CAST(NEW.state_json AS TEXT)) THEN CAST(NEW.state_json AS TEXT) ELSE '{}' END";
            let expiry = if index == 3 {
                format!(
                    "COALESCE(json_extract({json},'$.intent.expires_at'),COALESCE(json_extract({json},'$.intent.created_at'),0)+600)"
                )
            } else {
                format!("COALESCE(json_extract({json},'$.expires_at'),0)")
            };
            let next = if index == 3 {
                format!("min({expiry},CASE
                WHEN NOT COALESCE(json_extract({json},'$.local_manifest'),0) AND json_extract({json},'$.intent.owner_record[0]')='message' THEN 0
                WHEN COALESCE(json_extract({json},'$.held'),0) THEN {expiry}
                WHEN json_extract({json},'$.packet') IS NULL THEN CASE WHEN COALESCE(json_extract({json},'$.attempts'),0)>=10 THEN 0 ELSE COALESCE(json_extract({json},'$.next_at'),0) END
                WHEN json_array_length({json},'$.targets')>0 THEN COALESCE((SELECT min(json_extract(value,'$.next_at')) FROM json_each({json},'$.targets') WHERE NOT json_extract(value,'$.acknowledged') AND json_extract(value,'$.attempts')<10),0)
                ELSE COALESCE(json_extract({json},'$.next_at'),0) END)")
            } else {
                "NULL".into()
            };
            if index == 3 && upgrade_send_index {
                self.connection.execute_batch("DROP TRIGGER IF EXISTS own_copy_index_3_INSERT; DROP TRIGGER IF EXISTS own_copy_index_3_UPDATE;")?;
                self.connection.execute(
                    "DELETE FROM runtime_own_copy_state WHERE namespace=?1",
                    params![prefix],
                )?;
            }
            for operation in ["INSERT", "UPDATE"] {
                self.connection.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS own_copy_index_{index}_{operation} AFTER {operation} ON runtime_actor_state WHEN NEW.state_kind>='{prefix}' AND NEW.state_kind<'{end}' AND EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=NEW.state_kind) BEGIN
                    INSERT INTO runtime_own_copy_state VALUES(NEW.state_kind,'{prefix}',length(NEW.state_json),{expiry},COALESCE(json_extract({json},'$.completed'),json_extract({json},'$.acknowledged'),0),{next})
                    ON CONFLICT(state_kind) DO UPDATE SET bytes=excluded.bytes,expires_at=excluded.expires_at,completed=excluded.completed,next_attempt_at=excluded.next_attempt_at; END;"))?;
            }
            self.connection.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS own_copy_index_{index}_DELETE AFTER DELETE ON runtime_actor_state WHEN OLD.state_kind>='{prefix}' AND OLD.state_kind<'{end}' BEGIN
                DELETE FROM runtime_own_copy_state WHERE state_kind=OLD.state_kind;
                DELETE FROM message_footprint WHERE kind='actor' AND locator=OLD.state_kind;
                DELETE FROM message_copy_binding WHERE copy_id='actor:'||OLD.state_kind; END;"))?;
            if !installed || (index == 3 && upgrade_send_index) {
                // One-time upgrade, outside the per-copy path. Reuse the exact write-time projection.
                let projection = format!(
                    "SELECT NEW.state_kind,'{prefix}',length(NEW.state_json),{expiry},COALESCE(json_extract({json},'$.completed'),json_extract({json},'$.acknowledged'),0),{next} FROM runtime_actor_state NEW WHERE NEW.state_kind>='{prefix}' AND NEW.state_kind<'{end}'"
                );
                self.connection
                    .execute(&format!("INSERT INTO runtime_own_copy_state {projection}"), [])?;
            }
        }
        Ok(())
    }
}
