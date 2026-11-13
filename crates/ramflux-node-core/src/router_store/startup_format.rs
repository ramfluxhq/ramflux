// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only format checks shared by ordinary startup and offline maintenance.
use super::{
    IdentityRegistry, NodeCoreError, NodeReplayGuardState, OpaqueDeviceInbox,
    ROUTER_CURSOR_STATE_TABLE, ROUTER_IDENTITY_REGISTRY_KEY, ROUTER_INBOX_ENTRY_TABLE,
    ROUTER_INBOX_SLICE_KEY, ROUTER_REPLAY_GUARD_STATE_KEY, ROUTER_SNAPSHOT_TABLE, ReadableDatabase,
    ReadableTable, TableDefinition, expiry_index, identity_registry, incarnation,
    incarnation_state, mailbox_keys, tuple_format,
};

fn error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

pub(super) fn validate(db: &redb::Database) -> Result<(), NodeCoreError> {
    let mut registry = validate_row_formats(db)?;
    identity_registry::replay(db, &mut registry)
}

// Maintenance may repair a stale journal base, but may never decode retired rows.
pub(super) fn validate_formats(db: &redb::Database) -> Result<(), NodeCoreError> {
    validate_row_formats(db).map(|_| ())
}

fn validate_row_formats(db: &redb::Database) -> Result<IdentityRegistry, NodeCoreError> {
    tuple_format::validate(db)?;
    crate::foreign_device_store::validate(db)?;
    let read = db.begin_read().map_err(error)?;
    let mut registry = IdentityRegistry::default();
    match read.open_table(ROUTER_SNAPSHOT_TABLE) {
        Ok(table) => {
            if let Some(bytes) = table.get(ROUTER_IDENTITY_REGISTRY_KEY).map_err(error)? {
                registry = serde_json::from_slice(bytes.value())
                    .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))?;
            }
            if let Some(bytes) = table.get(ROUTER_INBOX_SLICE_KEY).map_err(error)? {
                let _: OpaqueDeviceInbox = serde_json::from_slice(bytes.value()).map_err(error)?;
            }
            if let Some(bytes) = table.get(crate::ROUTER_HOME_NODE_MIGRATION_KEY).map_err(error)? {
                let _: std::collections::BTreeMap<String, crate::HomeNodeMigrationRecord> =
                    serde_json::from_slice(bytes.value()).map_err(error)?;
            }
            if let Some(bytes) = table.get(ROUTER_REPLAY_GUARD_STATE_KEY).map_err(error)? {
                let _: NodeReplayGuardState =
                    serde_json::from_slice(bytes.value()).map_err(error)?;
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    for (definition, identity) in
        [(ROUTER_CURSOR_STATE_TABLE, false), (incarnation_state::TABLE, true)]
    {
        match read.open_table(definition) {
            Ok(table) => {
                for row in table.iter().map_err(error)? {
                    let (_, bytes) = row.map_err(error)?;
                    if identity {
                        incarnation_state::decode(bytes.value())?;
                    } else {
                        let cursor: incarnation::StoredCursor =
                            serde_json::from_slice(bytes.value()).map_err(error)?;
                        if let Some(id) = cursor.inbox_incarnation_id {
                            incarnation::validate(&id)?;
                        }
                    }
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(source) => return Err(error(source)),
        }
    }
    identity_registry::validate_formats(db)?;
    crate::router_wal::identity::maintenance::validate_pending_formats(db)?;
    let marker =
        match read.open_table(TableDefinition::<&str, u8>::new("router_mailbox_key_format_v1")) {
            Ok(table) => table.get("version").map_err(error)?.map(|value| value.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(source) => return Err(error(source)),
        };
    if marker.is_some_and(|version| version != 1) {
        return Err(NodeCoreError::UnsupportedPersistedFormat("router mailbox keys"));
    }
    match read.open_table(ROUTER_INBOX_ENTRY_TABLE) {
        Ok(table) => {
            for row in table.iter().map_err(error)? {
                let (key, bytes) = row.map_err(error)?;
                if marker.is_none() {
                    return Err(NodeCoreError::UnsupportedPersistedFormat("router mailbox keys"));
                }
                let (entry, _) = expiry_index::decode_entry(bytes.value())?;
                if key.value()
                    != mailbox_keys::storage_key(&entry.target_delivery_id, entry.inbox_seq)
                {
                    return Err(NodeCoreError::UnsupportedPersistedFormat("router mailbox keys"));
                }
            }
        }
        Err(redb::TableError::TableDoesNotExist(_)) => {}
        Err(source) => return Err(error(source)),
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::persisted_image::image;
    use crate::{InboxEntry, RouterRedbStore};
    #[test]
    fn current_markers_cannot_hide_a_missing_mailbox_deadline_on_startup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("router.redb");
        drop(RouterRedbStore::open_without_wal(&path)?);
        let entry = InboxEntry {
            inbox_seq: 1,
            target_delivery_id: "target".into(),
            envelope: crate::test_support::federation_fixtures::envelope(
                "row",
                "target",
                ramflux_protocol::DeliveryClass::OpaqueEvent,
            ),
        };
        let db = redb::Database::open(&path)?;
        let write = db.begin_write()?;
        write.open_table(ROUTER_INBOX_ENTRY_TABLE)?.insert(
            mailbox_keys::storage_key("target", entry.inbox_seq).as_str(),
            serde_json::to_vec(&entry)?.as_slice(),
        )?;
        write.commit()?;
        drop(db);
        let before = image(directory.path())?;
        assert!(
            matches!(
                RouterRedbStore::open_without_wal(&path),
                Err(NodeCoreError::UnsupportedPersistedFormat("router inbox deadline"))
            ),
            "current markers must not bypass deadline validation"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "ordinary refusal changed schema or incarnation authority"
        );
        assert!(
            RouterRedbStore::rotate_inbox_incarnations_at(&path, None, None).is_err(),
            "maintenance must validate deadlines before committing its prelude"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "maintenance refusal changed schema or incarnation authority"
        );
        Ok(())
    }
    #[test]
    fn missing_home_migration_version_refuses_before_ordinary_and_maintenance_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("router.redb");
        drop(RouterRedbStore::open_without_wal(&path)?);
        let db = redb::Database::open(&path)?;
        let current = serde_json::json!({"format_version":1,"identity_commitment":"root","old_home_node":"old","new_home_node":"new","new_home_node_key_hash":"key","route_record_hash":"route","effective_at":100,"issued_at":90,"migration_proof_hash":"proof","migrated_at":100});
        let mut retired = current.clone();
        retired.as_object_mut().ok_or("migration record")?.remove("format_version");
        let bytes = serde_json::to_vec(&serde_json::json!({"current":current,"retired":retired}))?;
        let write = db.begin_write()?;
        write
            .open_table(ROUTER_SNAPSHOT_TABLE)?
            .insert(crate::ROUTER_HOME_NODE_MIGRATION_KEY, bytes.as_slice())?;
        write.commit()?;
        drop(db);
        let before = image(directory.path())?;
        assert!(
            RouterRedbStore::open_without_wal(&path).is_err(),
            "missing migration versions must not default during startup"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "migration format refusal changed ordinary startup state"
        );
        assert!(
            RouterRedbStore::rotate_inbox_incarnations_at(&path, None, None).is_err(),
            "maintenance must validate migration snapshots before writes"
        );
        assert_eq!(
            image(directory.path())?,
            before,
            "migration format refusal changed maintenance state"
        );
        Ok(())
    }
}
