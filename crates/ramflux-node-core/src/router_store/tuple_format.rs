// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Refuse retired replay and local-delivery receipt formats without rewriting authority.
use super::{NodeCoreError, ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE, ROUTER_REPLAY_TUPLE_TABLE};
use redb::{ReadableDatabase, ReadableTable};

fn error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

pub(super) fn validate(db: &redb::Database) -> Result<(), NodeCoreError> {
    let txn = db.begin_read().map_err(error)?;
    let replay = match txn.open_table(ROUTER_REPLAY_TUPLE_TABLE) {
        Ok(table) => Some(table),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(source) => return Err(error(source)),
    };
    for row in
        replay.as_ref().map(|table| table.iter().map_err(error)).transpose()?.into_iter().flatten()
    {
        let (key, _) = row.map_err(error)?;
        if !crate::replay_guard::key_format::is_current_key(key.value()) {
            return Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"));
        }
    }
    let deliveries = match txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE) {
        Ok(table) => Some(table),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(source) => return Err(error(source)),
    };
    for row in deliveries
        .as_ref()
        .map(|table| table.iter().map_err(error))
        .transpose()?
        .into_iter()
        .flatten()
    {
        let (key, _) = row.map_err(error)?;
        let Some(tail) = key.value().strip_prefix("v3/") else {
            return Err(NodeCoreError::UnsupportedPersistedFormat("router local delivery receipt"));
        };
        let parts = tail.split('/').collect::<Vec<_>>();
        if parts.len() != 3
            || parts.iter().any(|part| ramflux_protocol::decode_base64url(part).is_err())
        {
            return Err(NodeCoreError::UnsupportedPersistedFormat("router local delivery receipt"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router_store::{RouterRedbStore, local_delivery_storage_key};

    #[test]
    fn retired_tuple_rows_are_refused_even_with_current_rows_and_old_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        for (table, key) in [
            (ROUTER_REPLAY_TUPLE_TABLE, "envelope/v2/source/id"),
            (ROUTER_REPLAY_TUPLE_TABLE, "legacy/replay/aWQ"),
            (ROUTER_REPLAY_TUPLE_TABLE, "unqualified-replay"),
            (ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE, "s:4:rootid"),
            (ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE, "4:rootid"),
            (ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE, "unqualified-delivery"),
        ] {
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("store.redb");
            let db = redb::Database::create(&path)?;
            RouterRedbStore::initialize_mailbox_schema(&db)?;
            let txn = db.begin_write()?;
            txn.open_table(super::super::ROUTER_SNAPSHOT_TABLE)?
                .insert("router_envelope_tuple_v3", b"3".as_slice())?;
            txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)?.insert(
                format!("request/v2/{}", ramflux_protocol::encode_base64url([1; 32])).as_str(),
                b"200".as_slice(),
            )?;
            txn.open_table(table)?.insert(key, b"200".as_slice())?;
            txn.commit()?;
            assert!(matches!(validate(&db), Err(NodeCoreError::UnsupportedPersistedFormat(_))));
            assert!(
                db.begin_read()?.open_table(table)?.get(key)?.is_some(),
                "refusal must not migrate/delete rows"
            );
            drop(db);
            let before = crate::tests::persisted_image::image(directory.path())?;
            assert!(matches!(
                RouterRedbStore::open_without_wal(&path),
                Err(NodeCoreError::UnsupportedPersistedFormat(_))
            ));
            assert_eq!(
                crate::tests::persisted_image::image(directory.path())?,
                before,
                "tuple refusal must preserve every table and marker"
            );
            assert!(
                RouterRedbStore::rotate_inbox_incarnations_at(&path, None, None).is_err(),
                "maintenance must refuse retired tuples before schema writes"
            );
            assert_eq!(
                crate::tests::persisted_image::image(directory.path())?,
                before,
                "maintenance tuple refusal changed authority"
            );
        }
        Ok(())
    }

    #[test]
    fn current_tuple_rows_survive_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let path = directory.path().join("store.redb");
        let db = redb::Database::create(&path)?;
        RouterRedbStore::initialize_mailbox_schema(&db)?;
        let key = local_delivery_storage_key("root", "envelope", "target");
        let txn = db.begin_write()?;
        let record = super::super::LocalDeliveryEnvelopeRecord {
            assignment: None,
            target_delivery_id: "target".into(),
            expires_at: 200,
        };
        txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?
            .insert(key.as_str(), serde_json::to_vec(&record)?.as_slice())?;
        txn.commit()?;
        validate(&db)?;
        drop(db);
        let store = RouterRedbStore::open_without_wal(&path)?;
        assert!(store.has_local_delivery_envelope("root", "envelope", "target", 100)?);
        assert!(!store.has_local_delivery_envelope("root", "envelope", "other", 100)?);
        drop(store);
        Ok(())
    }
    #[test]
    fn retired_tuple_writes_cannot_poison_redb_or_wal() -> Result<(), Box<dyn std::error::Error>> {
        for wal in [false, true] {
            let directory = tempfile::TempDir::new()?;
            let path = directory.path().join("store.redb");
            let wal_root = path.with_extension("wal");
            let store = if wal {
                RouterRedbStore::open_with_wal(&path, &wal_root)?
            } else {
                RouterRedbStore::open_without_wal(&path)?
            };
            for key in ["envelope/v2/source/id", "legacy/replay/aWQ", "unqualified"] {
                assert!(matches!(
                    store.record_submission_increment(key, 2000, None),
                    Err(NodeCoreError::UnsupportedPersistedFormat("router replay identity"))
                ));
            }
            let current = format!("request/v2/{}", ramflux_protocol::encode_base64url([1; 32]));
            store.record_submission_increment(&current, i64::MAX, None)?;
            drop(store);
            let store = if wal {
                RouterRedbStore::open_with_wal(&path, &wal_root)?
            } else {
                RouterRedbStore::open_without_wal(&path)?
            };
            assert_eq!(store.load_delivery_state(0)?.1.len(), 1);
            drop(store);
        }
        Ok(())
    }
}
