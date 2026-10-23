// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scoped recovery changes and erasure of obsolete exported ratchet state.
use super::super::AccountDb;
use crate::StorageError;
impl AccountDb {
    pub(super) fn install_inbox_recovery_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_inbox_recovery(singleton INTEGER PRIMARY KEY,revision INTEGER NOT NULL); INSERT OR IGNORE INTO runtime_inbox_recovery VALUES(1,0); DROP TRIGGER IF EXISTS inbox_recovery_actor_insert; DROP TRIGGER IF EXISTS inbox_recovery_actor_update;")?;
        for (table, fields, keys) in [
            (
                "group_projection",
                vec!["group_epoch", "role", "new_member_history", "deleted_at"],
                vec!["group_id"],
            ),
            (
                "group_member_projection",
                vec!["role", "joined_epoch", "removed_epoch", "active"],
                vec!["group_id", "member_principal_id"],
            ),
            (
                "group_member_device_key",
                vec!["device_signing_public_key"],
                vec!["group_id", "member_id"],
            ),
        ] {
            let same = fields
                .iter()
                .chain(keys.iter())
                .map(|f| format!("t.{f} IS NEW.{f}"))
                .collect::<Vec<_>>()
                .join(" AND ");
            let changed = fields
                .iter()
                .map(|f| format!("OLD.{f} IS NOT NEW.{f}"))
                .collect::<Vec<_>>()
                .join(" OR ");
            for action in ["INSERT", "UPDATE", "DELETE"] {
                self.connection.execute_batch(&format!(
                    "DROP TRIGGER IF EXISTS inbox_recovery_{table}_{action};"
                ))?;
                let (timing, guard, subject) = match action {
                    "INSERT" => (
                        "BEFORE",
                        format!("WHEN NOT EXISTS(SELECT 1 FROM {table} t WHERE {same})"),
                        "NEW.group_id",
                    ),
                    "UPDATE" => ("AFTER", format!("WHEN {changed}"), "NEW.group_id"),
                    _ => ("AFTER", String::new(), "OLD.group_id"),
                };
                self.connection.execute_batch(&format!("CREATE TRIGGER inbox_recovery_{table}_{action} {timing} {action} ON {table} {guard} BEGIN UPDATE runtime_inbox_recovery SET revision=revision+1; INSERT INTO runtime_inbox_changes VALUES('group',{subject},(SELECT revision FROM runtime_inbox_recovery)) ON CONFLICT(kind,subject) DO UPDATE SET revision=excluded.revision; END;"))?;
            }
        }
        // Upgrade old holds without extending their original local lifetime.
        for (table, time, attempts) in [
            ("runtime_inbox_retry", "created_at", "attempts"),
            ("runtime_inbox_dead_letter", "received_at", "0"),
        ] {
            self.connection.execute_batch(&format!("INSERT OR IGNORE INTO runtime_inbox_policy SELECT envelope_key,CASE WHEN json_valid(CAST(entry_json AS TEXT)) THEN coalesce(json_extract(CAST(entry_json AS TEXT),'$.envelope.source_device_id'),envelope_key) ELSE envelope_key END,0,{time},{time}+30,{attempts},'none','',0,0 FROM {table} LIMIT 64;"))?;
        }
        let changed=["principal_id","signing_public_key","x25519_identity_public"].iter().map(|f|format!("json_extract(CAST(t.state_json AS TEXT),'$.{f}') IS json_extract(CAST(NEW.state_json AS TEXT),'$.{f}')")).collect::<Vec<_>>().join(" AND ");
        for (action, timing, guard) in [
            (
                "insert",
                "BEFORE",
                format!(
                    "NOT EXISTS(SELECT 1 FROM runtime_actor_state t WHERE t.state_kind=NEW.state_kind AND {changed})"
                ),
            ),
            (
                "update",
                "AFTER",
                changed
                    .replace("t.state_json", "OLD.state_json")
                    .replace(" IS ", " IS NOT ")
                    .replace(" AND ", " OR "),
            ),
        ] {
            self.connection.execute_batch(&format!("CREATE TRIGGER inbox_recovery_actor_{action} {timing} {action} ON runtime_actor_state WHEN NEW.state_kind LIKE 'directory/device/%' AND EXISTS(SELECT 1 FROM runtime_inbox_policy WHERE failure_class='manifest' AND subject=substr(NEW.state_kind,18)) AND ({guard}) BEGIN UPDATE runtime_inbox_recovery SET revision=revision+1; INSERT INTO runtime_inbox_changes VALUES('manifest',substr(NEW.state_kind,18),(SELECT revision FROM runtime_inbox_recovery)) ON CONFLICT(kind,subject) DO UPDATE SET revision=excluded.revision; END;"))?;
        }
        self.retire_imported_ratchet_payloads()?;
        self.connection.execute_batch("DELETE FROM runtime_actor_state WHERE state_kind LIKE 'own-device/pair-history/%'; UPDATE runtime_actor_state SET state_json=CAST(json_remove(CAST(state_json AS TEXT),'$.prepared_slot.session') AS BLOB) WHERE state_kind LIKE 'attachment/reference/%' AND json_type(CAST(state_json AS TEXT),'$.prepared_slot.session') IS NOT NULL;")?;
        Ok(())
    }
}

impl AccountDb {
    pub(crate) fn retire_imported_ratchet_payloads(&self) -> Result<(), StorageError> {
        // Keep ledger ids/counters as tombstones. Deleting them can invalidate causal edges or
        // let append_event reuse the last device counter. Payloads and signatures are erased;
        // ordinary event reads and history export exclude these explicitly retired rows.
        self.connection.execute_batch("DELETE FROM projection_checkpoint WHERE last_event_id IN (SELECT event_id FROM local_event_log WHERE event_type='dm.ratchet_session' AND event_id LIKE 'dm.session:%:own-device-sync:%'); UPDATE local_event_log SET event_body=x'7b7d',signature=x'',signature_status='retired' WHERE event_type='dm.ratchet_session' AND event_id LIKE 'dm.session:%:own-device-sync:%' AND signature_status!='retired';")?;
        Ok(())
    }
}
