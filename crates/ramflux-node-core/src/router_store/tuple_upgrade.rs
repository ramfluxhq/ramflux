// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic, restart-safe conversion of recoverable local delivery receipts.
use super::{
    BTreeMap, LocalDeliveryEnvelopeRecord, NodeCoreError, ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE,
    ROUTER_REPLAY_TUPLE_TABLE, ROUTER_SNAPSHOT_TABLE, ReadableTable, expiry_index,
    local_delivery_storage_key,
};
const MARKER: &str = "router_envelope_tuple_v3";

pub(super) fn upgrade(db: &redb::Database) -> Result<(), NodeCoreError> {
    upgrade_transaction(db, false)
}
fn upgrade_transaction(db: &redb::Database, interrupt: bool) -> Result<(), NodeCoreError> {
    let txn = db.begin_write().map_err(redb_error)?;
    {
        let mut markers = txn.open_table(ROUTER_SNAPSHOT_TABLE).map_err(redb_error)?;
        if markers.get(MARKER).map_err(redb_error)?.is_some() {
            return Ok(());
        }
        let mut deliveries =
            txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE).map_err(redb_error)?;
        let rows = deliveries
            .iter()
            .map_err(redb_error)?
            .map(|row| {
                let (key, value) = row.map_err(redb_error)?;
                Ok((key.value().to_owned(), value.value().to_vec()))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let mut recovered = BTreeMap::new();
        for (key, bytes) in rows {
            let tail = key.strip_prefix("s:").unwrap_or(&key);
            let Some((len, rest)) = tail.split_once(':') else {
                continue;
            };
            let Ok(len) = len.parse::<usize>() else {
                continue;
            };
            if !rest.is_char_boundary(len) {
                continue;
            }
            let (root, envelope) = rest.split_at(len);
            let record: LocalDeliveryEnvelopeRecord = serde_json::from_slice(&bytes)
                .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
            recovered.insert(
                (root.to_owned(), ramflux_protocol::encode_base64url(envelope)),
                record.target_delivery_id.clone(),
            );
            let new_key = local_delivery_storage_key(root, envelope, &record.target_delivery_id);
            deliveries.insert(new_key.as_str(), bytes.as_slice()).map_err(redb_error)?;
            deliveries.remove(key.as_str()).map_err(redb_error)?;
            expiry_index::index_local_delivery_row(&txn, &new_key, record.expires_at)?;
        }
        let mut replay = txn.open_table(ROUTER_REPLAY_TUPLE_TABLE).map_err(redb_error)?;
        let rows = replay
            .iter()
            .map_err(redb_error)?
            .map(|row| {
                let (key, value) = row.map_err(redb_error)?;
                Ok((key.value().to_owned(), value.value().to_vec()))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        for (key, bytes) in rows {
            if key.starts_with("envelope/v2/") {
                let target = key
                    .strip_prefix("envelope/v2/")
                    .and_then(|tail| tail.split_once('/'))
                    .and_then(|(source, envelope)| {
                        let (root, _) =
                            ramflux_protocol::parse_qualified_device_id(source).ok()??;
                        recovered.get(&(root, envelope.to_owned())).map(|target| {
                            format!(
                                "envelope/v3/{source}/{envelope}/{}",
                                ramflux_protocol::encode_base64url(target)
                            )
                        })
                    });
                let new_key = target.unwrap_or_else(|| {
                    format!("legacy/replay/{}", ramflux_protocol::encode_base64url(&key))
                });
                replay.insert(new_key.as_str(), bytes.as_slice()).map_err(redb_error)?;
                replay.remove(key.as_str()).map_err(redb_error)?;
                let expiry: i64 = serde_json::from_slice(&bytes)
                    .map_err(|e| NodeCoreError::SnapshotSerialization(e.to_string()))?;
                expiry_index::index_replay_row(&txn, &new_key, expiry)?;
            }
        }
        if interrupt {
            return Err(NodeCoreError::Redb("interrupted tuple upgrade".into()));
        }
        markers.insert(MARKER, b"3".as_slice()).map_err(redb_error)?;
    }
    txn.commit().map_err(redb_error)
}
fn redb_error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::{ReadableDatabase, ReadableTableMetadata};
    fn fixture() -> Result<(std::path::PathBuf, redb::Database, String), Box<dyn std::error::Error>>
    {
        let path = std::env::temp_dir().join(format!(
            "tuple-upgrade-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let db = redb::Database::create(&path)?;
        super::super::RouterRedbStore::initialize_mailbox_schema(&db)?;
        let source = ramflux_protocol::qualified_device_id("root", "device")?;
        let key = format!("envelope/v2/{source}/{}", ramflux_protocol::encode_base64url("id"));
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?;
            table.insert(
                "s:4:rootid",
                serde_json::to_vec(&LocalDeliveryEnvelopeRecord {
                    assignment: None,
                    target_delivery_id: "target".into(),
                    expires_at: 200,
                })?
                .as_slice(),
            )?;
            let mut replay = txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)?;
            replay.insert(key.as_str(), b"200".as_slice())?;
            replay.insert("envelope/v2/unrecoverable/id", b"150".as_slice())?;
        }
        txn.commit()?;
        Ok((path, db, source))
    }
    #[test]
    fn upgraded_v2_replay_row_still_suppresses_duplicate_through_replay_guard()
    -> Result<(), Box<dyn std::error::Error>> {
        let (path, db, _) = fixture()?;
        let root = ramflux_crypto::create_identity_root("alice", [0x91; 32]);
        let branch = ramflux_crypto::create_device_branch(
            "alice",
            "device",
            1,
            ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
        );
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
        let txn = db.begin_write()?;
        {
            let mut replay = txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)?;
            for id in ["recoverable", "unrecoverable"] {
                let key = format!(
                    "envelope/v2/{}/{}",
                    source.storage_key(),
                    ramflux_protocol::encode_base64url(id)
                );
                replay.insert(key.as_str(), b"200".as_slice())?;
            }
            let key = format!(
                "s:{}:{}recoverable",
                source.root_commitment().len(),
                source.root_commitment()
            );
            txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?.insert(
                key.as_str(),
                serde_json::to_vec(&LocalDeliveryEnvelopeRecord {
                    assignment: None,
                    target_delivery_id: "target".into(),
                    expires_at: 200,
                })?
                .as_slice(),
            )?;
        }
        txn.commit()?;
        upgrade(&db)?;
        drop(db);
        let store = super::super::RouterRedbStore::open_without_wal(&path)?;
        let (_, mut guard) = store.load_delivery_state(100)?;
        let mut envelope = ramflux_protocol::Envelope {
            schema: ramflux_protocol::domain::ENVELOPE.into(),
            version: 1,
            domain: ramflux_protocol::domain::ENVELOPE.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "test".into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "signature".into(),
            },
            envelope_id: "recoverable".into(),
            source_principal_id: "alice".into(),
            source_device_id: source.device_id().into(),
            target_delivery_id: "target".into(),
            routing_set_id: None,
            delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
            priority: ramflux_protocol::Priority::Normal,
            ttl: 100,
            created_at: 100,
            encrypted_payload: "ciphertext".into(),
            payload_hash: "hash".into(),
            delivery_mode: None,
            collapse_tag: None,
        };
        assert!(!guard.accept_envelope_once(&source, &envelope, 100)?);
        assert!(store.has_local_delivery_envelope(
            source.root_commitment(),
            "recoverable",
            "target",
            100
        )?);
        envelope.target_delivery_id = "other".into();
        assert!(guard.accept_envelope_once(&source, &envelope, 100)?);
        envelope.envelope_id = "unrecoverable".into();
        assert!(!guard.accept_envelope_once(&source, &envelope, 100)?);
        envelope.target_delivery_id = "target".into();
        assert!(!guard.accept_envelope_once(&source, &envelope, 100)?);
        envelope.envelope_id = "new".into();
        assert!(guard.accept_envelope_once(&source, &envelope, 100)?);
        drop(store);
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn v2_replay_and_local_delivery_rows_remain_readable_and_dedup_after_upgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let (path, db, source) = fixture()?;
        upgrade(&db)?;
        drop(db);
        let db = redb::Database::open(&path)?;
        upgrade(&db)?;
        let txn = db.begin_read()?;
        let deliveries = txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?;
        assert!(
            deliveries.get(local_delivery_storage_key("root", "id", "target").as_str())?.is_some()
        );
        let replay = txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)?;
        let key = format!(
            "envelope/v3/{source}/{}/{}",
            ramflux_protocol::encode_base64url("id"),
            ramflux_protocol::encode_base64url("target")
        );
        assert_eq!(replay.get(key.as_str())?.ok_or("missing tuple")?.value(), b"200");
        let legacy = format!(
            "legacy/replay/{}",
            ramflux_protocol::encode_base64url("envelope/v2/unrecoverable/id")
        );
        assert_eq!(replay.get(legacy.as_str())?.ok_or("missing legacy")?.value(), b"150");
        drop(replay);
        drop(deliveries);
        drop(txn);
        drop(db);
        std::fs::remove_file(path)?;
        Ok(())
    }
    #[test]
    fn store_upgrade_interrupted_midway_reruns_idempotently()
    -> Result<(), Box<dyn std::error::Error>> {
        let (path, db, _) = fixture()?;
        assert!(upgrade_transaction(&db, true).is_err());
        drop(db);
        let db = redb::Database::open(&path)?;
        {
            let txn = db.begin_read()?;
            assert!(txn.open_table(ROUTER_SNAPSHOT_TABLE)?.get(MARKER)?.is_none());
            assert!(
                txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?.get("s:4:rootid")?.is_some()
            );
        }
        upgrade(&db)?;
        upgrade(&db)?;
        let txn = db.begin_read()?;
        assert_eq!(txn.open_table(ROUTER_LOCAL_DELIVERY_ENVELOPE_TABLE)?.len()?, 1);
        assert_eq!(txn.open_table(ROUTER_REPLAY_TUPLE_TABLE)?.len()?, 2);
        drop(txn);
        drop(db);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
