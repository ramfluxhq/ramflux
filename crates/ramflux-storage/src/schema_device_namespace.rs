// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomically separate legacy literal names from root-qualified durable device keys.
use crate::{StorageError, database::Connection};
use rusqlite::params;
use serde_json::{Value, json};

pub(crate) fn legacy_address(raw: &str) -> String {
    format!("legacy~{}", ramflux_protocol::encode_base64url(raw.as_bytes()))
}

pub(crate) fn upgrade(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS device_namespace_upgrade (singleton INTEGER PRIMARY KEY CHECK(singleton=1));")?;
    if connection.query_row("SELECT EXISTS(SELECT 1 FROM device_namespace_upgrade)", [], |row| {
        row.get::<_, bool>(0)
    })? {
        return Ok(());
    }
    let transaction = connection.immediate_transaction()?;
    metadata(connection)?;
    directory(connection)?;
    pins(connection)?;
    connection.execute("UPDATE group_member_projection SET principal_commitment=(SELECT MIN(k.principal_commitment) FROM group_member_device_key k WHERE k.group_id=group_member_projection.group_id AND COALESCE(k.raw_device_id,k.member_id)=group_member_projection.member_id HAVING COUNT(*)=1 AND COUNT(k.principal_commitment)=1) WHERE principal_commitment IS NULL",[])?;
    // An unscoped secret cannot be attributed to a root by guessing from a raw name.
    // Archive unscoped secrets without granting them live authority. Drop old pointers and
    // recovery work; authenticated bootstrap establishes a new scoped pair. An upgraded
    // account never repeats this migration. Archive collisions abort rather than overwrite.
    connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) SELECT 'legacy-device-pair/session/' || substr(state_kind,length('dm-pair/session/')+1),state_json FROM runtime_actor_state WHERE state_kind GLOB 'dm-pair/session/*' AND COALESCE(json_extract(CAST(state_json AS TEXT),'$.root_addressed'),0)<>1",[])?;
    connection.execute("DELETE FROM runtime_actor_state WHERE state_kind GLOB 'dm-pair/*' AND (state_kind NOT GLOB 'dm-pair/session/*' OR COALESCE(json_extract(CAST(state_json AS TEXT),'$.root_addressed'),0)<>1)",[])?;
    connection.execute("INSERT INTO device_namespace_upgrade VALUES(1)", [])?;
    transaction.commit()?;
    Ok(())
}

fn metadata(connection: &Connection) -> Result<(), StorageError> {
    let rows = {
        let mut query = connection.prepare("SELECT state_kind,state_json FROM runtime_actor_state WHERE state_kind GLOB 'directory/device/*' ORDER BY state_kind")?;
        query
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut migrated = std::collections::BTreeMap::new();
    for (key, bytes) in rows {
        let mut value: Value = serde_json::from_slice(&bytes)?;
        if !value.is_object() {
            return Err(StorageError::AuthorizationRejected);
        }
        let raw =
            value["device_id"].as_str().unwrap_or(&key["directory/device/".len()..]).to_owned();
        let address = match value["principal_commitment"].as_str().filter(|root| !root.is_empty()) {
            Some(root) => ramflux_protocol::qualified_device_id(root, &raw)?,
            None => legacy_address(&raw),
        };
        value["device_id"] = json!(raw);
        value["qualified_device_id"] = json!(address);
        migrated.insert(format!("directory/device/{address}"), serde_json::to_vec(&value)?);
    }
    connection.execute(
        "DELETE FROM runtime_actor_state WHERE state_kind GLOB 'directory/device/*'",
        [],
    )?;
    for (key, bytes) in migrated {
        connection.execute(
            "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![key, bytes],
        )?;
    }
    Ok(())
}

fn directory(connection: &Connection) -> Result<(), StorageError> {
    let rows = {
        let mut query = connection.prepare("SELECT COALESCE(raw_device_id,device_id),principal_commitment,source,verified_at FROM device_directory")?;
        query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    connection.execute("DELETE FROM device_directory", [])?;
    for (raw, root, source, time) in rows {
        let address = ramflux_protocol::qualified_device_id(&root, &raw)?;
        connection.execute("INSERT OR REPLACE INTO device_directory(device_id,principal_commitment,source,verified_at,raw_device_id) VALUES(?1,?2,?3,?4,?5)",params![address,root,source,time,raw])?;
    }
    Ok(())
}

fn pins(connection: &Connection) -> Result<(), StorageError> {
    let rows = {
        let mut query = connection.prepare("SELECT group_id,COALESCE(raw_device_id,member_id),device_signing_public_key,verified_at,member_principal_id,principal_commitment FROM group_member_device_key")?;
        query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    connection.execute("DELETE FROM group_member_device_key", [])?;
    for (group, raw, key, time, principal, root) in rows {
        let address = match &root {
            Some(root) => ramflux_protocol::qualified_device_id(root, &raw)?,
            None => legacy_address(&raw),
        };
        connection.execute("INSERT OR REPLACE INTO group_member_device_key(group_id,member_id,device_signing_public_key,verified_at,member_principal_id,principal_commitment,raw_device_id) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![group,address,key,time,principal,root,raw])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::*;
    use serde_json::{Value, json};
    #[test]
    fn legacy_address_shaped_names_cannot_alias_another_roots_rows() -> Result<(), StorageError> {
        let (path, db) = crate::tests::test_db("device-namespace-upgrade")?;
        let address = ramflux_protocol::qualified_device_id("bob-root", "phone")?;
        db.connection.execute("DELETE FROM device_namespace_upgrade", [])?;
        db.persist_actor_state(
            &format!("directory/device/{address}"),
            &json!({"principal_commitment":"mallory-root","signing_public_key":"mallory"}),
        )?;
        db.connection.execute(
            "INSERT INTO device_directory VALUES(?1,'mallory-root','legacy',1,?1)",
            rusqlite::params![address],
        )?;
        db.create_group("legacy-group", &address)?;
        db.connection.execute("INSERT INTO group_member_device_key(group_id,member_id,device_signing_public_key,verified_at,member_principal_id,principal_commitment,raw_device_id) VALUES('legacy-group',?1,'mallory',1,'mallory','mallory-root',?1)",rusqlite::params![address])?;
        db.persist_actor_state(
            "dm-pair/session/old",
            &json!({"local":"phone","remote":address,"snapshot":{"secret":"old"}}),
        )?;
        db.persist_actor_state(
            "dm-pair/session/scoped",
            &json!({"root_addressed":true,"snapshot":{"secret":"scoped"}}),
        )?;
        super::upgrade(&db.connection)?;
        assert!(!db.actor_state_exists("dm-pair/session/old")?);
        assert_eq!(
            db.load_actor_state::<Value>("legacy-device-pair/session/old")?
                .ok_or(StorageError::AuthorizationRejected)?["snapshot"]["secret"],
            "old"
        );
        assert!(db.actor_state_exists("dm-pair/session/scoped")?);
        db.persist_client_record("device", "phone", &json!({"device_id":"phone","principal_commitment":"bob-root","signing_public_key":"bob"}))?;
        db.upsert_device_directory_entry("phone", "bob-root", "verified", 2)?;
        assert_eq!(
            db.client_record("device", &address)?.ok_or(StorageError::AuthorizationRejected)?["signing_public_key"],
            "bob"
        );
        let nested = ramflux_protocol::qualified_device_id("mallory-root", &address)?;
        assert_eq!(
            db.client_record("device", &nested)?.ok_or(StorageError::AuthorizationRejected)?["signing_public_key"],
            "mallory"
        );
        assert_eq!(
            db.device_directory_entry(&nested)?
                .ok_or(StorageError::AuthorizationRejected)?
                .device_id,
            address
        );
        assert_eq!(
            db.group_member_identity_metadata("legacy-group", &address)?
                .ok_or(StorageError::AuthorizationRejected)?
                .principal_commitment
                .as_deref(),
            Some("mallory-root")
        );
        let live = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
            &ramflux_crypto::create_identity_root("bob", [41; 32]),
            "phone",
        )?;
        assert!(db.group_member_key_binding("legacy-group", &live)?.is_none());
        assert!(
            ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
                &ramflux_crypto::create_identity_root("mallory", [51; 32]),
                &address
            )
            .is_err()
        );
        db.persist_client_record("device", &address, &json!({"device_id":address,"principal_commitment":"bob-root","signing_public_key":"nested-bob"}))?;
        db.upsert_device_directory_entry(&address, "bob-root", "verified", 3)?;
        assert_eq!(
            db.client_record("device", &address)?.ok_or(StorageError::AuthorizationRejected)?["signing_public_key"],
            "bob"
        );
        assert_eq!(
            db.device_directory_entry(&address)?
                .ok_or(StorageError::AuthorizationRejected)?
                .device_id,
            "phone"
        );
        super::upgrade(&db.connection)?;
        assert_eq!(
            db.client_record("device", &nested)?.ok_or(StorageError::AuthorizationRejected)?["signing_public_key"],
            "mallory"
        );
        drop(db);
        std::fs::remove_dir_all(path)?;
        Ok(())
    }
}
