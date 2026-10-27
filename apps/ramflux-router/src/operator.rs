// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Offline identity admission journal maintenance.

use ramflux_node_core::{NodeServiceConfig, RouterCore, RouterRedbStore};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityJournalCommand {
    Checkpoint,
    DiscardStale,
}

pub(crate) fn resolved_store_path(config: &NodeServiceConfig) -> anyhow::Result<PathBuf> {
    let path = ramflux_node_core::effective_redb_path(config);
    if path.is_absolute() { Ok(path) } else { Ok(std::env::current_dir()?.join(path)) }
}

pub(crate) fn run(command: IdentityJournalCommand, path: &Path) -> anyhow::Result<()> {
    println!("ramflux-router:identity-registry-store path={}", path.display());
    match command {
        IdentityJournalCommand::Checkpoint => {
            let store = RouterRedbStore::open_existing(path)?;
            let pending_rows = store.pending_identity_admission_count()?;
            let router = store.load_router()?.unwrap_or_default();
            checkpoint_for_shutdown(&router, &store)?;
            println!(
                "ramflux-router:identity-registry-checkpoint-complete drained_rows={pending_rows}"
            );
        }
        IdentityJournalCommand::DiscardStale => {
            let report = RouterRedbStore::discard_stale_identity_journal(path)?;
            let roots = report.affected_root_ids.join(",");
            tracing::info!(
                discarded_rows = report.discarded_rows,
                affected_root_ids = %roots,
                "stale identity admission journal rows discarded"
            );
            println!(
                "ramflux-router:identity-registry-discard-complete discarded_rows={} affected_root_ids={roots}",
                report.discarded_rows
            );
        }
    }
    Ok(())
}

pub(crate) fn checkpoint_for_shutdown(
    router: &RouterCore,
    store: &RouterRedbStore,
) -> anyhow::Result<()> {
    router.persist_identity_registry(store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
    use std::sync::atomic::{AtomicU64, Ordering};

    const ADMISSIONS: TableDefinition<u64, &[u8]> =
        TableDefinition::new("router_identity_admission_v1");
    const BUDGETS: TableDefinition<&str, &[u8]> =
        TableDefinition::new("router_registration_budget_v1");
    const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("router_snapshot_v1");
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ramflux-router-operator-{label}-{}-{}.redb",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn insert_row(path: &Path, stale: bool) -> anyhow::Result<()> {
        let db = redb::Database::open(path)?;
        let txn = db.begin_write()?;
        let base_snapshot_hash = if stale {
            "stale-base".to_owned()
        } else {
            let snapshots = txn.open_table(SNAPSHOTS)?;
            let bytes = snapshots
                .get("identity_registry")?
                .ok_or_else(|| anyhow::anyhow!("identity registry snapshot missing"))?;
            ramflux_crypto::blake3_256_base64url(
                "ramflux.identity_admission.base_snapshot.v1",
                bytes.value(),
            )
        };
        let entry = serde_json::json!({
            "base_snapshot_hash": base_snapshot_hash,
            "delta": {
                "principal_root_bindings": {}, "identity_authority_fences": {},
                "signed_device_sets": {}, "root_public_keys": {},
                "root_public_keys_by_commitment": {}, "devices": {},
                "prekey_bundles": {}, "revoked_devices": {},
                "delivery_root_bindings": {}, "registration_trust_tiers": {},
                "removed_receipts": [], "receipts": [], "source_budgets": {},
                "registration_policy": null
            }
        });
        let bytes = serde_json::to_vec(&entry)?;
        txn.open_table(ADMISSIONS)?.insert(1, bytes.as_slice())?;
        txn.commit()?;
        Ok(())
    }

    #[test]
    fn offline_commands_refuse_missing_and_locked_stores() -> anyhow::Result<()> {
        let missing = path("missing");
        assert!(run(IdentityJournalCommand::Checkpoint, &missing).is_err());
        assert!(!missing.exists());

        let locked = path("locked");
        let store = RouterRedbStore::open(&locked)?;
        assert!(run(IdentityJournalCommand::Checkpoint, &locked).is_err());
        assert!(run(IdentityJournalCommand::DiscardStale, &locked).is_err());
        drop(store);
        std::fs::remove_file(locked)?;
        Ok(())
    }

    #[test]
    fn discard_command_removes_only_stale_rows_and_reopens_store() -> anyhow::Result<()> {
        let path = path("discard");
        let store = RouterRedbStore::open(&path)?;
        RouterCore::new().persist_identity_registry(&store)?;
        drop(store);
        insert_row(&path, true)?;

        run(IdentityJournalCommand::DiscardStale, &path)?;
        let store = RouterRedbStore::open_existing(&path)?;
        assert_eq!(store.pending_identity_admission_count()?, 0);
        drop(store);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn drain_command_and_shutdown_hook_empty_the_journal() -> anyhow::Result<()> {
        let drain_path = path("drain");
        let store = RouterRedbStore::open(&drain_path)?;
        RouterCore::new().persist_identity_registry(&store)?;
        drop(store);
        {
            let db = redb::Database::open(&drain_path)?;
            let txn = db.begin_write()?;
            txn.open_table(BUDGETS)?.insert("obsolete", b"[1]".as_slice())?;
            txn.commit()?;
        }
        run(IdentityJournalCommand::Checkpoint, &drain_path)?;
        let drained = RouterRedbStore::open_existing(&drain_path)?;
        assert_eq!(drained.pending_identity_admission_count()?, 0);
        drop(drained);
        let txn = redb::Database::open(&drain_path)?.begin_read()?;
        assert!(txn.open_table(BUDGETS)?.is_empty()?);
        drop(txn);
        std::fs::remove_file(drain_path)?;

        let shutdown_path = path("shutdown");
        let store = RouterRedbStore::open(&shutdown_path)?;
        RouterCore::new().persist_identity_registry(&store)?;
        drop(store);
        insert_row(&shutdown_path, false)?;
        let store = RouterRedbStore::open_existing(&shutdown_path)?;
        assert_eq!(store.pending_identity_admission_count()?, 1);
        checkpoint_for_shutdown(&RouterCore::new(), &store)?;
        assert_eq!(store.pending_identity_admission_count()?, 0);
        drop(store);
        let txn = redb::Database::open(&shutdown_path)?.begin_read()?;
        assert!(txn.open_table(SNAPSHOTS)?.get("identity_registry")?.is_some());
        drop(txn);
        std::fs::remove_file(shutdown_path)?;
        Ok(())
    }
}
