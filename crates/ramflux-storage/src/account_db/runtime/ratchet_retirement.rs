// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-scoped erasure of live and archived pairs without reauthorizing their peers.
use super::super::AccountDb;
use crate::StorageError;
use ramflux_crypto::RootQualifiedDeviceRef;
use rusqlite::params;

impl AccountDb {
    /// Erase private pairs and reset work naming this exact authenticated device namespace.
    /// Peer authority may already be retired or unavailable; erasure creates no identity or grant.
    /// Replay high-water marks and unrelated devices with the same literal name remain intact.
    /// # Errors
    /// Returns SQL/serialization failures. Callers checkpoint retired pages after outer commit.
    pub fn retire_device_pairs(
        &self,
        device: &RootQualifiedDeviceRef,
        at: i64,
        reason: &str,
    ) -> Result<u64, StorageError> {
        self.write_transaction(|| {
            let mut count = self.retire_device_pair_rows("runtime_actor_state", device, at, reason)?;
            let archived: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='backup_archived_actor_state')", [], |row|row.get(0),
            )?;
            if archived { count += self.retire_device_pair_rows("backup_archived_actor_state", device, at, reason)?; }
            loop {
                let mut query = self.connection.prepare("SELECT state_kind,CASE WHEN state_kind LIKE 'dm-pair/reset-work/%' THEN json_extract(CAST(state_json AS TEXT),'$.local') ELSE json_extract(CAST(state_json AS TEXT),'$.local_device_id') END,CASE WHEN state_kind LIKE 'dm-pair/reset-work/%' THEN json_extract(CAST(state_json AS TEXT),'$.remote') ELSE json_extract(CAST(state_json AS TEXT),'$.device_id') END FROM runtime_actor_state WHERE (state_kind LIKE 'dm-pair/reset-work/%' AND (json_extract(CAST(state_json AS TEXT),'$.local')=?1 OR json_extract(CAST(state_json AS TEXT),'$.remote')=?1)) OR (state_kind LIKE 'dm-pair/%/manual' AND (json_extract(CAST(state_json AS TEXT),'$.local_device_id')=?1 OR json_extract(CAST(state_json AS TEXT),'$.device_id')=?1)) LIMIT 64")?;
                let work = query.query_map(params![device.storage_key()], |row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
                if work.is_empty() { break; }
                for (key, local, remote) in work {
                    self.remove_actor_state(&key)?;
                    self.clear_retired_pair_heads(device, &local, &remote)?;
                }
            }
            self.prune_pair_metadata()?;
            Ok(count)
        })
    }

    fn retire_device_pair_rows(
        &self,
        table: &'static str,
        device: &RootQualifiedDeviceRef,
        at: i64,
        reason: &str,
    ) -> Result<u64, StorageError> {
        // The table is selected only by the two fixed internal call sites above.
        let sql = format!(
            "SELECT substr(state_kind,17),json_extract(CAST(state_json AS TEXT),'$.local'),json_extract(CAST(state_json AS TEXT),'$.remote') FROM {table} WHERE state_kind LIKE 'dm-pair/session/%' AND (json_extract(CAST(state_json AS TEXT),'$.local')=?1 OR json_extract(CAST(state_json AS TEXT),'$.remote')=?1) ORDER BY state_kind LIMIT 64"
        );
        let mut count = 0;
        loop {
            let mut query = self.connection.prepare(&sql)?;
            let rows = query
                .query_map(params![device.storage_key()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            if rows.is_empty() {
                break;
            }
            for (id, local, remote) in rows {
                let pair = retired_pair_key(device, &local, &remote)?;
                let successor = self.load_actor_state::<String>(&pair)?;
                self.erase_backup_pair(&id)?;
                self.persist_actor_state(
                    &format!("dm-pair/retired/{id}"),
                    &serde_json::json!({
                        "pair":pair,"superseded_by":successor,"retired_at":at,"reason":reason,
                    }),
                )?;
                for kind in ["session", "bootstrap"] {
                    self.remove_actor_state(&format!("dm-pair/{kind}/{id}"))?;
                }
                self.clear_retired_pair_heads(device, &local, &remote)?;
                self.persist_actor_state("secrets/retired", &true)?;
                count += 1;
            }
        }
        Ok(count)
    }

    fn clear_retired_pair_heads(
        &self,
        device: &RootQualifiedDeviceRef,
        local: &str,
        remote: &str,
    ) -> Result<(), StorageError> {
        let pair = retired_pair_key(device, local, remote)?;
        for key in [
            pair.clone(),
            format!("{pair}/archive"),
            format!("{pair}/reset-pending"),
            format!("{pair}/manual"),
            format!("dm-pair/reset-work/{pair}"),
        ] {
            self.remove_actor_state(&key)?;
        }
        Ok(())
    }
}

fn retired_pair_key(
    device: &RootQualifiedDeviceRef,
    local: &str,
    remote: &str,
) -> Result<String, StorageError> {
    // Stored peer metadata can be unavailable for authorization. It is used only to erase
    // pointers after the SQL selection names this authenticated denial target exactly.
    if local != device.storage_key() && remote != device.storage_key() {
        return Err(StorageError::AuthorizationRejected);
    }
    Ok(format!(
        "dm-pair/active/{}",
        ramflux_crypto::blake3_256_base64url(
            "ramflux.sdk.root_bound_dm_pair.v1",
            &ramflux_protocol::canonical_json_bytes(&(local, remote))?,
        )
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_retirement_erases_archives_and_reset_work_without_peer_authority_or_replay_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../ramflux-crypto/tests/fixtures/custody_v3.json"
        ))?;
        let record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet> =
            serde_json::from_value(vector["record"].clone())?;
        let verified =
            ramflux_crypto::custody::verify_record(&record, record.body.issued_at, None, None)?;
        let target = RootQualifiedDeviceRef::from_custody_record(&verified, "primary")?;
        let local_root = ramflux_crypto::create_identity_root("retirement-local", [73; 32]);
        let other_root = ramflux_crypto::create_identity_root("retirement-other", [74; 32]);
        let local = RootQualifiedDeviceRef::for_owned_account_device(&local_root, "local")?;
        let other = RootQualifiedDeviceRef::for_owned_account_device(&other_root, "primary")?;
        let root = std::env::temp_dir().join(format!(
            "rf-device-retirement-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let index = crate::AccountIndex::open(&root)?;
        index.create_account("local", local.root_commitment())?;
        let db = AccountDb::open(&index, "local", &crate::AccountDbKey::generate()?)?;
        let affected = serde_json::json!({"local":local.storage_key(),"remote":target.storage_key(),"secret":"retire this private state"});
        let unaffected = serde_json::json!({"local":local.storage_key(),"remote":other.storage_key(),"secret":"keep another root's private state"});
        db.persist_actor_state("dm-pair/session/affected", &affected)?;
        db.persist_actor_state("dm-pair/session/unaffected", &unaffected)?;
        assert!(retired_pair_key(&target, local.storage_key(), other.storage_key()).is_err());
        let pair = retired_pair_key(&target, local.storage_key(), target.storage_key())?;
        let other_pair = retired_pair_key(&other, local.storage_key(), other.storage_key())?;
        db.persist_actor_state(&pair, &"affected")?;
        db.persist_actor_state(&other_pair, &"unaffected")?;
        db.persist_actor_state(
            &format!("dm-pair/reset-work/{pair}"),
            &serde_json::json!({"local":local.storage_key(),"remote":target.storage_key()}),
        )?;
        db.persist_actor_state(&format!("{pair}/manual"), &serde_json::json!({"local_device_id":local.storage_key(),"device_id":target.storage_key()}))?;
        let floor = format!("{pair}/bootstrap-high-water/retained-owner");
        db.persist_actor_state(&floor, &912_u64)?;
        // A worker-owned archive may outlive its corresponding live session. Install the
        // archive table in this isolated fixture through the managed account writer.
        db.write_transaction(|| -> Result<(), StorageError> {
            db.connection.execute_batch("CREATE TABLE backup_archived_actor_state(source TEXT NOT NULL,state_kind TEXT NOT NULL,state_json BLOB NOT NULL,PRIMARY KEY(source,state_kind));")?;
            for (id, value) in [("affected", &affected),("archive-only", &affected),("unaffected", &unaffected)] {
                db.connection.execute("INSERT INTO backup_archived_actor_state VALUES('restore',?1,?2)", params![format!("dm-pair/session/{id}"),serde_json::to_vec(value)?])?;
            }
            Ok(())
        })?;
        assert_eq!(db.retire_device_pairs(&target, 100, "verified_native_revocation")?, 2);
        assert!(!db.actor_state_exists("dm-pair/session/affected")?);
        assert!(!db.actor_state_exists(&pair)?);
        assert!(!db.actor_state_exists(&format!("dm-pair/reset-work/{pair}"))?);
        assert!(!db.actor_state_exists(&format!("{pair}/manual"))?);
        assert!(db.actor_state_exists("dm-pair/session/unaffected")?);
        assert_eq!(db.load_actor_state::<u64>(&floor)?, Some(912));
        assert_eq!(db.connection.query_row("SELECT count(*) FROM backup_archived_actor_state WHERE state_kind<>'dm-pair/session/unaffected'",[],|row|row.get::<_,u64>(0))?,0);
        assert_eq!(db.retire_device_pairs(&target, 101, "repeat_denial")?, 0);
        assert_eq!(db.retire_device_pairs(&local, 102, "local_revocation")?, 1);
        assert!(!db.actor_state_exists("dm-pair/session/unaffected")?);
        assert_eq!(db.load_actor_state::<u64>(&floor)?, Some(912));
        drop(db);
        drop(index);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
