// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native data archives cannot install authority, credentials or active outbound state.
use super::backup_database::BackupDatabase;
use crate::{AccountDbKey, BackupMergeReport, StorageError};
use std::path::Path;

pub(super) const DATA_STATE_FILTER: &str = "r.state_kind NOT LIKE 'backup/%' AND r.state_kind NOT LIKE 'identity/%' AND r.state_kind NOT LIKE 'account/%' AND r.state_kind NOT LIKE 'sync/%' AND r.state_kind NOT LIKE 'gateway/%' AND (r.state_kind NOT LIKE 'directory/%' OR r.state_kind LIKE 'directory/conversation/%') AND (r.state_kind NOT LIKE 'dm-pair/%' OR r.state_kind LIKE 'dm-pair/session/%' OR r.state_kind LIKE 'dm-pair/retired/%') AND r.state_kind NOT LIKE 'own-copy/%' AND r.state_kind NOT LIKE 'own-device/%'";

pub(super) fn authority_table(table: &str) -> bool {
    matches!(
        table,
        "device_identity"
            | "lineage_checkpoint"
            | "home_node_binding"
            | "session_capability_cache"
            | "device_directory"
            | "identity_lifecycle_projection"
            | "contact_verification_projection"
            | "mcp_grant"
            | "mcp_standing_approval"
            | "bot_trust_pin"
            | "bot_install_grant"
            | "guardian_recovery_share_projection"
            | "pending_recovery_projection"
            | "pending_recovery_approval_projection"
    )
}
impl BackupDatabase {
    /// Removes local runtime credentials and pending work from a native archive snapshot.
    /// Public evidence and historical receive keys do not grant branch or primary authority.
    /// # Errors
    /// Returns SQLite errors. Callers must discard the private snapshot on any failure.
    pub fn sanitize_native_backup(&self) -> Result<(), StorageError> {
        self.db.execute_batch("PRAGMA secure_delete=ON; BEGIN IMMEDIATE;
            DELETE FROM runtime_actor_state WHERE state_kind LIKE 'account/%' OR state_kind LIKE 'identity/owned_%' OR state_kind LIKE 'sync/%' OR state_kind LIKE 'gateway/%';
            DELETE FROM runtime_operation; DELETE FROM runtime_journal; DELETE FROM runtime_outbox;
            DELETE FROM outbox_queue; DELETE FROM session_capability_cache;
            DELETE FROM pending_recovery_projection; DELETE FROM pending_recovery_approval_projection;
            DELETE FROM guardian_recovery_share_projection; COMMIT; VACUUM;")?;
        Ok(())
    }

    /// Merges data while leaving live authority, key pins, permissions and replay state intact.
    /// Imported DM sessions are receive-only and outbound sessions bootstrap independently.
    /// # Errors
    /// Rejects conflicting pins, invalid schemas, cancellation and SQL/I/O errors.
    pub fn merge_native_backup(
        &mut self,
        path: &Path,
        key: &AccountDbKey,
        progress: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<BackupMergeReport, StorageError> {
        self.merge_backup_mode(path, key, true, progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDb, AccountIndex};
    use serde_json::json;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn native_merge_cannot_install_authority_or_resume_saved_outbound_sessions() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "rf-native-merge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
        ));
        let source_index = AccountIndex::open(root.join("source"))?;
        let local_index = AccountIndex::open(root.join("local"))?;
        source_index.create_account("account", "anchor")?;
        local_index.create_account("account", "anchor")?;
        let source_key = AccountDbKey::generate()?;
        let local_key = AccountDbKey::generate()?;
        let source = AccountDb::open(&source_index, "account", &source_key)?;
        let local = AccountDb::open(&local_index, "account", &local_key)?;
        let retained = [
            ("identity/custody/anchor", json!({"pins":{"epoch":9,"fenced":true},"revision":9})),
            ("identity/owned_pending_set", json!({"revision":9})),
            (
                "directory/identity/peer",
                json!({"revision":9,"contact_identity_commitment":"peer-anchor"}),
            ),
            ("account/node-id", json!("trusted-node")),
            ("dm-pair/active/pair", json!("live")),
            ("dm-pair/session/live", json!({"counter":91})),
            ("dm-pair/pair/bootstrap-high-water/owner", json!(912)),
        ];
        for (key, value) in &retained {
            local.persist_actor_state(key, value)?;
            source.persist_actor_state(key, &json!({"revision":99999}))?;
        }
        source.persist_actor_state("identity/custody/unknown", &json!({"revision":99999}))?;
        source.persist_actor_state("dm-pair/session/imported", &json!({"counter":3}))?;
        source.persist_actor_state("dm-pair/active/imported", &"imported")?;
        source.persist_actor_state("dm-pair/bootstrap/imported", &json!({"seed":"saved"}))?;
        source.store_message_content("thread", "history", b"inbound history")?;
        let incoming = root.join("incoming.db");
        let snapshot = source.write_backup_snapshot(&incoming)?;
        let target = root.join("merged.db");
        let copied = local.write_backup_snapshot(&target)?;
        let mut merged = BackupDatabase::open(&target, &copied.key)?;
        merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
        for (key, value) in &retained {
            let bytes: Vec<u8> = merged.db.query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                [key],
                |row| row.get(0),
            )?;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes)?,
                *value,
                "live state changed: {key}"
            );
        }
        for key in
            ["identity/custody/unknown", "dm-pair/active/imported", "dm-pair/bootstrap/imported"]
        {
            assert!(
                !merged.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",
                    [key],
                    |row| row.get::<_, bool>(0)
                )?,
                "archive installed active state: {key}"
            );
        }
        assert!(merged.db.query_row("SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind='backup/inactive-pair/imported')", [], |row| row.get::<_,bool>(0))?);
        assert_eq!(
            merged.db.query_row(
                "SELECT body FROM runtime_message_content WHERE message_id='history'",
                [],
                |row| row.get::<_, Vec<u8>>(0)
            )?,
            b"inbound history"
        );
        drop(merged);
        drop(local);
        drop(source);
        drop(local_index);
        drop(source_index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
