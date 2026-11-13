// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retired foreign authority snapshots never enter current per-root storage.
use super::*;

#[test]
fn foreign_store_refuses_retired_tables_even_alongside_current_rows()
-> Result<(), Box<dyn std::error::Error>> {
    for name in ["federated_source_device_sets_v1", "bounded_foreign_device_heads_v1"] {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("store.redb");
        let db = redb::Database::create(&path)?;
        initialize(&db, Namespace::Router)?;
        initialize(&db, Namespace::Federation)?;
        let write = db.begin_write()?;
        let mut table = write.open_table(TableDefinition::<&str, &[u8]>::new(name))?;
        table.insert("retired", b"{}".as_slice())?;
        drop(table);
        write.commit()?;
        for namespace in [Namespace::Router, Namespace::Federation] {
            assert!(
                matches!(
                    initialize(&db, namespace),
                    Err(NodeCoreError::UnsupportedPersistedFormat("foreign authority store"))
                ),
                "retired table accepted: {name}"
            );
        }
        drop(db);
        let before = crate::tests::persisted_image::image(directory.path())?;
        assert!(
            matches!(
                crate::RouterRedbStore::open_without_wal(&path),
                Err(NodeCoreError::UnsupportedPersistedFormat(_))
            ),
            "router must refuse actual retired payloads before initialization"
        );
        assert_eq!(
            crate::tests::persisted_image::image(directory.path())?,
            before,
            "router foreign-format refusal changed disk state"
        );
        assert!(
            matches!(
                crate::FederationRedbStore::open(&path),
                Err(NodeCoreError::UnsupportedPersistedFormat(_))
            ),
            "federation must refuse actual retired payloads before initialization"
        );
        assert_eq!(
            crate::tests::persisted_image::image(directory.path())?,
            before,
            "federation foreign-format refusal changed disk state"
        );
    }
    Ok(())
}

#[test]
fn current_foreign_tables_with_base_bookkeeping_survive_real_service_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let open = crate::test_support::federation_fixtures::gateway_open_frame("device", "foreign");
    let old = crate::test_support::federation_fixtures::gateway_registered_key(&open)?
        .signed_device_set
        .ok_or("signed set")?;
    let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
    let current = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 2,
            devices: old.devices.clone(),
        },
    )?;
    for namespace in [Namespace::Router, Namespace::Federation] {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("store.redb");
        let db = redb::Database::create(&path)?;
        initialize(&db, namespace)?;
        observe(&db, namespace, &current)?.admitted()?;
        let expected = load(&db, namespace)?;
        let write = db.begin_write()?;
        write
            .open_table(TableDefinition::<&str, u8>::new("foreign_set_fence_migration_v1"))?
            .insert(
                match namespace {
                    Namespace::Router => "router",
                    Namespace::Federation => "federation",
                },
                1,
            )?;
        write.commit()?;
        drop(db);
        match namespace {
            Namespace::Router => {
                drop(crate::RouterRedbStore::open_without_wal(&path)?);
            }
            Namespace::Federation => {
                drop(crate::FederationRedbStore::open(&path)?);
            }
        }
        let db = redb::Database::open(&path)?;
        assert_eq!(
            load(&db, namespace)?,
            expected,
            "base-created bookkeeping must not erase or reject current fences/sets"
        );
        assert!(
            matches!(
                observe(&db, namespace, &old),
                Err(NodeCoreError::SourceAuthorityRefused { .. })
            ),
            "the preserved epoch fence must still refuse stale authority"
        );
    }
    Ok(())
}

#[test]
fn serialized_foreign_head_fields_are_refused_in_every_router_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let mut identity = serde_json::to_value(crate::mvp1_registry::IdentityRegistry::default())?;
    identity["foreign_device_heads"] = serde_json::json!({"records":[],"fences":{}});
    assert!(serde_json::from_value::<crate::mvp1_registry::IdentityRegistry>(identity).is_err());
    let mut control = serde_json::to_value(crate::router::RouterControlState::default())?;
    assert!(control.get("foreign_device_heads").is_none());
    control["foreign_device_heads"] = serde_json::json!({"records":[],"fences":{}});
    assert!(serde_json::from_value::<crate::router::RouterControlState>(control).is_err());
    let mut snapshot = serde_json::to_value(crate::router::RouterCoreSnapshot::default())?;
    assert!(snapshot.get("foreign_device_heads").is_none());
    snapshot["foreign_device_heads"] = serde_json::json!({"records":[],"fences":{}});
    assert!(serde_json::from_value::<crate::router::RouterCoreSnapshot>(snapshot).is_err());
    Ok(())
}
