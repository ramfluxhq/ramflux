// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Registration compatibility, bounded journal checkpointing and shared-source admission.
use super::*;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("router_snapshot_v1");
const ADMISSIONS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("router_identity_admission_v1");
const BUDGETS: TableDefinition<&str, &[u8]> = TableDefinition::new("router_registration_budget_v1");

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn clean(path: &std::path::Path) {
    let _removed = std::fs::remove_file(path);
    let _removed = std::fs::remove_dir_all(path.with_extension("redb.wal"));
}
#[test]
fn registration_legacy_snapshot_is_unchanged_by_small_admissions_and_replay_is_exact() -> TestResult
{
    let path = temp_store_path("registration-deltas-legacy")?;
    let router = RouterCore::new();
    let alice = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
    router.mvp1_register_identity(&alice)?;
    let original = serde_json::to_vec(&router.mvp1_identities_snapshot())?;
    // Model the pre-journal database: only the existing JSON snapshot table exists.
    {
        let db = redb::Database::create(&path)?;
        let txn = db.begin_write()?;
        txn.open_table(SNAPSHOTS)?.insert("identity_registry", original.as_slice())?;
        txn.commit()?;
    }
    let store = RouterRedbStore::open(&path)?;
    let bob = registration_request(&router, "bob", "phone", 2, None, "192.0.2.1")?;
    router.register_identity_durable(&bob, &store)?;
    let expected = router.mvp1_identities_snapshot();
    assert_eq!(store.load_router()?.ok_or("router missing")?.mvp1_identities_snapshot(), expected);
    drop(store);
    {
        let db = redb::Database::open(&path)?;
        let txn = db.begin_read()?;
        let snapshot = txn.open_table(SNAPSHOTS)?;
        assert_eq!(snapshot.get("identity_registry")?.ok_or("snapshot")?.value(), original);
        let legacy_reader: IdentityRegistry = serde_json::from_slice(
            snapshot.get("identity_registry")?.ok_or("legacy snapshot")?.value(),
        )?;
        assert_eq!(serde_json::to_vec(&legacy_reader)?, original);
        let journal = txn.open_table(ADMISSIONS)?;
        assert_eq!(journal.len()?, 1);
        let (_, row) = journal.first()?.ok_or("admission")?;
        let text = std::str::from_utf8(row.value())?;
        assert!(text.contains("base_snapshot_hash"));
        assert!(!text.contains("alice"), "unrelated authority must not be rewritten");
        assert!(text.contains("bob"));
    }
    let store = RouterRedbStore::open(&path)?;
    let restored = store.load_router()?.ok_or("router missing after reopen")?;
    assert_eq!(restored.mvp1_identities_snapshot(), expected);
    assert!(
        restored.register_identity_durable(&bob, &store).is_err(),
        "receipt must survive crash/reopen"
    );
    // A full publication supersedes the delta prefix atomically.
    restored.persist_identity_registry(&store)?;
    drop(store);
    let db = redb::Database::open(&path)?;
    assert_eq!(db.begin_read()?.open_table(ADMISSIONS)?.len()?, 0);
    drop(db);
    clean(&path);
    Ok(())
}
#[test]
fn registration_journal_checkpoints_at_count_and_byte_bounds_without_replaying_old_authority()
-> TestResult {
    for byte_boundary in [false, true] {
        let path = temp_store_path(if byte_boundary {
            "registration-byte-bound"
        } else {
            "registration-count-bound"
        })?;
        let router = RouterCore::new();
        let alice = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
        let store = RouterRedbStore::open(&path)?;
        router.register_identity_durable(&alice, &store)?;
        drop(store);
        // Fill a logically idempotent prefix to exercise the checkpoint boundary
        // without minting 127 irrelevant identities in a storage regression.
        {
            let db = redb::Database::open(&path)?;
            let txn = db.begin_write()?;
            {
                let mut table = txn.open_table(ADMISSIONS)?;
                let bytes = table.first()?.ok_or("first delta")?.1.value().to_vec();
                if byte_boundary {
                    txn.open_table(SNAPSHOTS)?.insert(
                        "identity_admission_bytes",
                        (4_u64 * 1024 * 1024 - 1).to_le_bytes().as_slice(),
                    )?;
                } else {
                    for seq in 2..=127 {
                        table.insert(seq, bytes.as_slice())?;
                    }
                }
            }
            txn.commit()?;
        }
        let store = RouterRedbStore::open(&path)?;
        let bob = registration_request(&router, "bob", "phone", 2, None, "192.0.2.2")?;
        router.register_identity_durable(&bob, &store)?;
        let expected = router.mvp1_identities_snapshot();
        drop(store);
        {
            let db = redb::Database::open(&path)?;
            let txn = db.begin_read()?;
            assert_eq!(txn.open_table(ADMISSIONS)?.len()?, 0);
            let snapshot = txn.open_table(SNAPSHOTS)?;
            let bytes = snapshot.get("identity_registry")?.ok_or("checkpoint")?;
            assert_eq!(serde_json::from_slice::<IdentityRegistry>(bytes.value())?, expected);
            assert_eq!(txn.open_table(BUDGETS)?.len()?, 2);
        }
        let store = RouterRedbStore::open(&path)?;
        assert_eq!(
            store.load_router()?.ok_or("reopened router")?.mvp1_identities_snapshot(),
            expected
        );
        let charlie = registration_request(&router, "charlie", "phone", 3, None, "192.0.2.3")?;
        router.register_identity_durable(&charlie, &store)?;
        assert_eq!(
            store.load_router()?.ok_or("tail")?.mvp1_identities_snapshot(),
            router.mvp1_identities_snapshot()
        );
        drop(store);
        clean(&path);
    }
    Ok(())
}
#[test]
fn registration_failure_or_unwind_restores_only_affected_entries_and_all_receipts() -> TestResult {
    let router = RouterCore::new();
    let alice = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
    let bob = registration_request(&router, "bob", "phone", 2, None, "192.0.2.2")?;
    let mut registry = IdentityRegistry::new();
    registry.register_identity(&alice)?;
    let prepared = registry.prepare_registration(&bob, RegistrationTrustTier::New)?;
    let before = registry.clone();
    {
        let guard = prepared.apply_to(&mut registry);
        assert_ne!(*guard.registry, before);
    }
    assert_eq!(registry, before);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = prepared.apply_to(&mut registry);
        std::panic::resume_unwind(Box::new("simulated admission persistence unwind"));
    }));
    assert!(unwind.is_err());
    assert_eq!(registry, before);
    prepared.apply_to(&mut registry).commit();
    assert!(registry.signed_device_set(&bob.principal_commitment).is_some());
    assert!(registry.signed_device_set(&alice.principal_commitment).is_some());
    Ok(())
}

#[test]
fn router_store_failure_rolls_back_authority_and_session_and_allows_retry() -> TestResult {
    let path = temp_store_path("registration-router-store-failure")?;
    let router = RouterCore::new();
    let request = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
    let store = RouterRedbStore::open(&path)?;
    store.fail_next_registration_admission();

    let failure = router.register_identity_durable(&request, &store);
    assert!(
        matches!(failure, Err(NodeCoreError::Redb(message)) if message == "injected registration admission store failure")
    );
    assert!(router.signed_device_set(&request.principal_commitment).is_none());
    assert!(router.session(&request.target_delivery_id).is_none());
    let stored = store.load_router()?.unwrap_or_default();
    assert!(stored.signed_device_set(&request.principal_commitment).is_none());
    assert!(stored.session(&request.target_delivery_id).is_none());

    router.register_identity_durable(&request, &store)?;
    assert!(router.signed_device_set(&request.principal_commitment).is_some());
    assert!(router.session(&request.target_delivery_id).is_some());
    drop(store);
    clean(&path);
    Ok(())
}

#[test]
fn concurrent_two_root_router_admissions_both_commit() -> TestResult {
    let path = temp_store_path("registration-concurrent-roots")?;
    let router = RouterCore::new();
    let alice = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
    let bob = registration_request(&router, "bob", "phone", 2, None, "192.0.2.2")?;
    let store = RouterRedbStore::open(&path)?;
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> Result<(), NodeCoreError> {
        let first = scope.spawn(|| {
            barrier.wait();
            router.register_identity_durable(&alice, &store)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            router.register_identity_durable(&bob, &store)
        });
        first.join().map_err(|_| NodeCoreError::ItestJson("alice admission panicked".into()))??;
        second.join().map_err(|_| NodeCoreError::ItestJson("bob admission panicked".into()))??;
        Ok(())
    })?;

    for request in [&alice, &bob] {
        assert!(router.signed_device_set(&request.principal_commitment).is_some());
        assert!(router.session(&request.target_delivery_id).is_some());
    }
    let restored = store.load_router()?.ok_or("router missing")?;
    for request in [&alice, &bob] {
        assert!(restored.signed_device_set(&request.principal_commitment).is_some());
        assert!(restored.session(&request.target_delivery_id).is_some());
    }
    drop(store);
    clean(&path);
    Ok(())
}

#[test]
fn downgrade_snapshot_change_causes_typed_reupgrade_refusal_without_epoch_rollback() -> TestResult {
    let path = temp_store_path("registration-downgrade-fence")?;
    let router = RouterCore::new();
    let first = registration_request(&router, "alice", "phone", 1, None, "192.0.2.1")?;
    let store = RouterRedbStore::open(&path)?;
    router.register_identity_durable(&first, &store)?;
    drop(store);

    let downgraded = RouterCore::new();
    let old_first = registration_request(&downgraded, "alice", "phone", 1, None, "192.0.2.1")?;
    downgraded.mvp1_register_identity(&old_first)?;
    let old_second = registration_request(&downgraded, "alice", "tablet", 2, None, "192.0.2.2")?;
    downgraded.mvp1_register_identity(&old_second)?;
    let downgraded_snapshot = downgraded.mvp1_identities_snapshot();
    assert_eq!(
        downgraded_snapshot
            .signed_device_set(&first.principal_commitment)
            .ok_or("missing downgraded set")?
            .device_set_epoch,
        2
    );
    let downgraded_bytes = serde_json::to_vec(&downgraded_snapshot)?;
    {
        let db = redb::Database::open(&path)?;
        let txn = db.begin_write()?;
        txn.open_table(SNAPSHOTS)?.insert("identity_registry", downgraded_bytes.as_slice())?;
        txn.commit()?;
    }

    let Err(error) = RouterRedbStore::open(&path) else {
        return Err("stale admission journal replayed over downgraded snapshot".into());
    };
    assert!(matches!(error, NodeCoreError::IdentityAdmissionJournalBaseMismatch { .. }));
    let db = redb::Database::open(&path)?;
    let txn = db.begin_read()?;
    let snapshots = txn.open_table(SNAPSHOTS)?;
    let bytes = snapshots.get("identity_registry")?.ok_or("downgraded snapshot missing")?;
    let unchanged: IdentityRegistry = serde_json::from_slice(bytes.value())?;
    assert_eq!(
        unchanged
            .signed_device_set(&first.principal_commitment)
            .ok_or("latest set missing")?
            .device_set_epoch,
        2
    );
    drop(bytes);
    drop(snapshots);
    drop(txn);
    drop(db);
    clean(&path);
    Ok(())
}
#[test]
fn registration_delta_persists_pending_failed_source_charges_and_current_policy() -> TestResult {
    let path = temp_store_path("registration-budget-charges")?;
    let router = RouterCore::new();
    router.mvp6_set_registration_policy(RegistrationPolicy {
        per_source_ip_registration_limit: 3,
        ..RegistrationPolicy::default()
    });
    let mut failed = registration_request(&router, "failed", "phone", 1, None, "192.0.2.1")?;
    failed.root_public_key.clear();
    assert!(router.mvp1_register_identity(&failed).is_err());
    let store = RouterRedbStore::open(&path)?;
    let good = registration_request(&router, "good", "phone", 2, None, "192.0.2.2")?;
    router.register_identity_durable(&good, &store)?;
    assert_eq!(
        store.load_router()?.ok_or("router")?.mvp1_identities_snapshot(),
        router.mvp1_identities_snapshot()
    );
    drop(store);
    clean(&path);
    Ok(())
}
#[test]
fn configured_shared_nat_receipt_ceiling_is_enforced_without_evicting_live_fences() -> TestResult {
    for limit in ["1", "256", "1024", "0"] {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::registration_persistence::shared_nat_receipt_probe",
                "--nocapture",
            ])
            .env("RAMFLUX_TEST_RECEIPT_LIMIT_PROBE", "1")
            .env("RAMFLUX_REGISTRATION_SOURCE_RECEIPT_LIMIT", limit)
            .output()?;
        assert!(
            output.status.success(),
            "limit={limit}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
#[test]
fn shared_nat_receipt_probe() -> TestResult {
    if std::env::var("RAMFLUX_TEST_RECEIPT_LIMIT_PROBE").as_deref() != Ok("1") {
        return Ok(());
    }
    let router = RouterCore::new();
    let request = registration_request(&router, "new-root", "phone", 1, None, "192.0.2.1")?;
    let mut value = serde_json::to_value(IdentityRegistry::new())?;
    value["root_seen_proofs"] = serde_json::Value::Array(
        (0..256)
            .map(|n| {
                serde_json::json!({
                    "key":format!("existing-{n}"), "root":format!("existing-root-{n}"),
                    "source": request.source_ip_hash, "expires_at": request.now+3600
                })
            })
            .collect(),
    );
    let mut registry: IdentityRegistry = serde_json::from_value(value)?;
    let result = registry.register_identity(&request);
    let accepted =
        std::env::var("RAMFLUX_REGISTRATION_SOURCE_RECEIPT_LIMIT").as_deref() == Ok("1024");
    match std::env::var("RAMFLUX_REGISTRATION_SOURCE_RECEIPT_LIMIT").as_deref() {
        Ok("1024") => assert!(result.is_ok()),
        Ok("0") => assert!(matches!(
            result,
            Err(NodeCoreError::Unauthorized(message))
                if message == "invalid registration source receipt limit"
        )),
        Ok("1" | "256") => assert!(matches!(
            result,
            Err(NodeCoreError::Capacity { resource: "registration_proofs_per_source" })
        )),
        value => return Err(format!("unexpected receipt-limit probe value: {value:?}").into()),
    }
    let stored = serde_json::to_value(registry)?;
    let receipts = stored["root_seen_proofs"].as_array().ok_or("receipts")?;
    assert_eq!(receipts.len(), 256 + usize::from(accepted));
    for n in 0..256 {
        assert!(receipts.iter().any(|r| r["key"] == format!("existing-{n}")));
    }
    Ok(())
}
