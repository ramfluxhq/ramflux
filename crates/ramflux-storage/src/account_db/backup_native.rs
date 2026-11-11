// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native data archives cannot install authority, credentials or active outbound state.
use super::{backup_database::BackupDatabase, backup_merge::BackupMergeMode};
use crate::{AccountDbKey, BackupMergeReport, StorageError};
use std::path::Path;

/// A full-transfer cut cannot discard a transaction's unresolved normalization scratch.
/// Empty scratch is harmless and is classified E by the logical encoder.
pub(super) fn full_transfer_snapshot_preflight(
    db: &rusqlite::Connection,
) -> Result<(), StorageError> {
    let mut tables = db.prepare("SELECT name FROM sqlite_schema WHERE type='table'")?;
    for table in tables.query_map([], |row| row.get::<_, String>(0))? {
        let table = table?;
        let scratch = super::backup_selector_admission::is_scratch(&table)
            || matches!(
                table.as_str(),
                "backup_changed_conversation"
                    | "backup_erased_capture"
                    | "backup_erased_capture_message"
                    | "backup_erased_copy"
                    | "backup_local_consent"
                    | "backup_local_conversation"
                    | "backup_local_link_consent"
                    | "backup_local_message_own"
                    | "backup_local_pair"
                    | "backup_source_consent"
                    | "backup_source_conversation"
                    | "backup_source_link_consent"
                    | "footprint_merge_imported"
            );
        if scratch {
            let quoted = table.replace('"', "\"\"");
            let nonempty =
                db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM \"{quoted}\")"), [], |row| {
                    row.get::<_, bool>(0)
                })?;
            if nonempty {
                return Err(StorageError::PairingField("SnapshotBusy"));
            }
        }
    }
    Ok(())
}

pub(super) const DATA_STATE_FILTER: &str = "r.state_kind NOT LIKE 'backup/%' AND r.state_kind NOT LIKE 'identity/%' AND r.state_kind NOT LIKE 'account/%' AND r.state_kind NOT LIKE 'sync/%' AND r.state_kind NOT LIKE 'gateway/%' AND (r.state_kind NOT LIKE 'directory/%' OR r.state_kind LIKE 'directory/conversation/%') AND (r.state_kind NOT LIKE 'dm-pair/%' OR r.state_kind LIKE 'dm-pair/session/%' OR r.state_kind LIKE 'dm-pair/retired/%') AND r.state_kind NOT LIKE 'own-copy/%' AND r.state_kind NOT LIKE 'own-device/%' AND r.state_kind NOT LIKE 'group-transfer/%'";

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
            DELETE FROM runtime_operation; DELETE FROM message_footprint WHERE kind='journal'; DELETE FROM runtime_journal; DELETE FROM runtime_outbox;
            DELETE FROM outbox_queue; DELETE FROM session_capability_cache;
            DELETE FROM pending_recovery_projection; DELETE FROM pending_recovery_approval_projection;
            DELETE FROM guardian_recovery_share_projection; COMMIT; VACUUM;")?;
        Ok(())
    }

    /// Candidate admission with every native data-only exclusion preserved.
    /// # Errors
    /// Refuses invalid graphs, conflicting pins, cancellation and storage errors.
    #[doc(hidden)]
    pub fn merge_native_backup_candidate(
        &mut self,
        path: &Path,
        key: &AccountDbKey,
        mut progress: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<BackupMergeReport, StorageError> {
        self.merge_backup_pipeline(
            path,
            key,
            (BackupMergeMode::NativeDataOnly, true),
            &mut progress,
            |_| Ok(()),
        )
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
        self.merge_backup_mode(path, key, BackupMergeMode::NativeDataOnly, progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountDb, AccountIndex};
    use serde_json::json;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn full_transfer_private_cut_preserves_input_and_refuses_unresolved_scratch() -> TestResult {
        let (root, source) = crate::tests::test_db("full-transfer-private-cut")?;
        source.persist_actor_state("own-device/sequence-locator/source", &"source-only-canary")?;
        let path = root.join("full-cut.db");
        let cut = source.write_full_transfer_snapshot_cancellable(
            &path,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        // Open raw only inside A's private owner: archive normalization would alter the input.
        let private = rusqlite::Connection::open(&path)?;
        private.execute_batch(&format!("PRAGMA key=\"x'{}'\";", cut.key.sqlcipher_hex()))?;
        let retained: Vec<u8> = private.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind='own-device/sequence-locator/source'", [], |row| row.get(0),
        )?;
        assert_eq!(retained, b"\"source-only-canary\"");
        private.close().map_err(|(_, error)| error)?;
        source.connection.execute_batch("CREATE TABLE backup_local_consent(value TEXT); INSERT INTO backup_local_consent VALUES('unresolved');")?;
        assert!(matches!(
            source.write_full_transfer_snapshot_cancellable(
                &root.join("busy-cut.db"),
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ),
            Err(StorageError::PairingField("SnapshotBusy"))
        ));
        assert_eq!(
            source.connection.query_row(
                "SELECT count(*) FROM backup_local_consent",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn full_transfer_pinned_cut_does_not_hold_writer_or_capture_later_edits() -> TestResult {
        let (root, source) = crate::tests::test_db("full-transfer-pinned-cut")?;
        source.persist_actor_state("draft/pinned-cut", &"before-pin")?;
        let cut = source.pin_full_transfer_cut()?;
        // A real committed write completes while the independent read transaction stays pinned.
        source.persist_actor_state("draft/pinned-cut", &"after-pin")?;
        let path = root.join("pinned-cut.db");
        let copied = cut.write_private_snapshot(
            &path,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let private = rusqlite::Connection::open(&path)?;
        private.execute_batch(&zeroize::Zeroizing::new(format!(
            "PRAGMA key=\"x'{}'\";",
            zeroize::Zeroizing::new(copied.key.sqlcipher_hex()).as_str()
        )))?;
        let pinned: Vec<u8> = private.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind='draft/pinned-cut'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(pinned, b"\"before-pin\"");
        let current: Vec<u8> = source.connection.query_row(
            "SELECT state_json FROM runtime_actor_state WHERE state_kind='draft/pinned-cut'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(current, b"\"after-pin\"");
        private.close().map_err(|(_, error)| error)?;
        Ok(())
    }

    #[test]
    fn full_transfer_cut_account_erase_invalidates_without_copying_old_generation() -> TestResult {
        let (root, source) = crate::tests::test_db("full-transfer-erased-cut")?;
        let cut = source.pin_full_transfer_cut()?;
        drop(source);
        AccountIndex::open(&root)?.erase_account_database("acct")?;
        let destination = root.join("refused-erased-cut.db");
        assert!(matches!(
            cut.write_private_snapshot(
                &destination,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
            ),
            Err(StorageError::PairingField("SnapshotInvalidated"))
        ));
        assert!(!destination.exists());
        Ok(())
    }

    fn add_raw_fixture(source: &AccountDb) -> TestResult {
        source.write_transaction(|| {
            source.put_unsupported_raw_copy(crate::RawInnerCopyWrite {
                owner_id: "unsupported-message",
                verified_source_anchor: "verified-peer-root",
                copy_id: "raw-copy",
                kind: crate::RawInnerCopyKind::OuterInner,
                bytes: b"native merge must exclude this raw copy",
                bounded_metadata: b"{}",
            })
        })?;
        Ok(())
    }

    fn add_local_raw_fixture(local: &AccountDb) -> TestResult {
        local.write_transaction(|| {
            local.put_unsupported_raw_copy(crate::RawInnerCopyWrite {
                owner_id: "unsupported-message",
                verified_source_anchor: "verified-peer-root",
                copy_id: "raw-copy",
                kind: crate::RawInnerCopyKind::OuterInner,
                bytes: b"local raw copy must remain unchanged",
                bounded_metadata: b"{}",
            })
        })?;
        Ok(())
    }

    fn assert_native_raw_copy_unchanged(merged: &BackupDatabase) -> TestResult {
        assert_eq!(
            merged.db.query_row(
                "SELECT raw_bytes FROM raw_inner_copy WHERE copy_id='raw-copy'",
                [],
                |row| row.get::<_, Vec<u8>>(0)
            )?,
            b"local raw copy must remain unchanged",
            "native merge must not import or overwrite Unsupported raw copies"
        );
        Ok(())
    }
    #[test]
    fn native_merge_cannot_install_authority_or_resume_saved_outbound_sessions() -> TestResult {
        native_exclusions(false)?;
        native_exclusions(true)
    }
    fn native_exclusions(candidate: bool) -> TestResult {
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
        add_local_raw_fixture(&local)?;
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
        add_raw_fixture(&source)?;
        source.persist_actor_state("own-device/status/imported", &json!({"expires_at":900}))?;
        local.persist_actor_state("own-device/status/local", &json!({"expires_at":900}))?;
        let incoming = root.join("incoming.db");
        let snapshot = source.write_backup_snapshot(&incoming)?;
        let target = root.join("merged.db");
        let copied = local.write_backup_snapshot(&target)?;
        let mut merged = BackupDatabase::open(&target, &copied.key)?;
        if candidate {
            merged.merge_native_backup_candidate(&incoming, &snapshot.key, || Ok(()))?;
        } else {
            merged.merge_native_backup(&incoming, &snapshot.key, || Ok(()))?;
        }
        assert!(!merged.db.query_row("SELECT EXISTS(SELECT 1 FROM runtime_own_copy_state WHERE state_kind='own-device/status/imported')", [], |row| row.get::<_,bool>(0))?, "derived own-copy state must not be imported without its actor row");
        assert!(merged.db.query_row("SELECT EXISTS(SELECT 1 FROM runtime_own_copy_state WHERE state_kind='own-device/status/local')", [], |row| row.get::<_,bool>(0))?);
        assert_eq!(
            merged.db.query_row(
                "SELECT rows FROM runtime_own_copy_usage WHERE namespace='own-device/status/'",
                [],
                |row| row.get::<_, u64>(0)
            )?,
            1
        );
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
        assert_native_raw_copy_unchanged(&merged)?;
        drop(merged);
        drop(local);
        drop(source);
        drop(local_index);
        drop(source_index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
