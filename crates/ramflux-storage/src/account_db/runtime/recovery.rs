// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive recovery revision and retirement of obsolete exported ratchet state.
use super::super::AccountDb;
use crate::StorageError;
impl AccountDb {
    pub(super) fn install_inbox_recovery_schema(&self) -> Result<(), StorageError> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS runtime_inbox_recovery(singleton INTEGER PRIMARY KEY, revision INTEGER NOT NULL); INSERT OR IGNORE INTO runtime_inbox_recovery VALUES(1,0);
            CREATE TRIGGER IF NOT EXISTS inbox_recovery_actor_insert AFTER INSERT ON runtime_actor_state WHEN NEW.state_kind LIKE 'directory/identity/%' OR NEW.state_kind LIKE 'directory/device/%' BEGIN UPDATE runtime_inbox_recovery SET revision=revision+1; END;
            CREATE TRIGGER IF NOT EXISTS inbox_recovery_actor_update AFTER UPDATE ON runtime_actor_state WHEN (NEW.state_kind LIKE 'directory/identity/%' OR NEW.state_kind LIKE 'directory/device/%') AND NEW.state_json != OLD.state_json BEGIN UPDATE runtime_inbox_recovery SET revision=revision+1; END;")?;
        for table in ["group_projection", "group_member_projection", "group_member_device_key"] {
            for action in ["INSERT", "UPDATE", "DELETE"] {
                self.connection.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS inbox_recovery_{table}_{action} AFTER {action} ON {table} BEGIN UPDATE runtime_inbox_recovery SET revision=revision+1; END;"))?;
            }
        }
        self.connection.execute_batch("DELETE FROM runtime_actor_state WHERE state_kind LIKE 'own-device/pair-history/%'; UPDATE runtime_actor_state SET state_json=CAST(json_remove(CAST(state_json AS TEXT),'$.prepared_slot.session') AS BLOB) WHERE state_kind LIKE 'attachment/reference/%' AND json_type(CAST(state_json AS TEXT),'$.prepared_slot.session') IS NOT NULL;")?;
        Ok(())
    }
}
