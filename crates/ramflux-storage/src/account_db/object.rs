#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub type StoredObjects<T> = (Vec<T>, BTreeMap<String, [u8; 32]>);

impl AccountDb {
    pub fn upsert_object<T>(&self, write: &ObjectWrite<'_, T>) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.connection.execute(
            "INSERT OR REPLACE INTO object_index (
                object_id, chunk_manifest_hash, object_created_group_key_epoch, object_state,
                total_cipher_size, chunk_count, created_at, updated_at, manifest_hash, nonce,
                ciphertext, plaintext_hash, tombstoned, backup_excluded, object_content_key,
                object_body
             ) VALUES (
                ?1, ?2, NULL, ?3, ?4, 1, ?5, ?5, ?2, ?6, ?7, ?8, ?9, ?10, ?11, ?12
             )",
            params![
                write.object_id,
                write.manifest_hash.as_bytes(),
                if write.tombstoned { "tombstoned" } else { "available" },
                i64::try_from(write.ciphertext.len()).unwrap_or(i64::MAX),
                write.updated_at,
                write.nonce,
                write.ciphertext,
                write.plaintext_hash,
                i64::from(write.tombstoned),
                i64::from(write.backup_excluded),
                write.content_key.map(<[u8; 32]>::as_slice),
                serde_json::to_vec(write.object)?
            ],
        )?;
        Ok(())
    }

    pub fn set_object_tombstoned(&self, object_id: &str) -> Result<(), StorageError> {
        let object_body = self
            .connection
            .query_row(
                "SELECT object_body FROM object_index WHERE object_id = ?1",
                params![object_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(object_body) = object_body else {
            return Ok(());
        };
        let mut body: serde_json::Value = serde_json::from_slice(&object_body)?;
        if let Some(object) = body.as_object_mut() {
            object.insert("tombstoned".to_owned(), serde_json::Value::Bool(true));
        }
        self.connection.execute(
            "UPDATE object_index
                SET tombstoned = 1, object_state = 'tombstoned', object_body = ?2
              WHERE object_id = ?1",
            params![object_id, serde_json::to_vec(&body)?],
        )?;
        Ok(())
    }

    pub fn load_objects<T>(&self) -> Result<StoredObjects<T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT object_id, object_body, object_content_key
               FROM object_index
              WHERE object_body IS NOT NULL
              ORDER BY object_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        let mut objects = Vec::new();
        let mut object_keys = BTreeMap::new();
        for row in rows {
            let (object_id, body, key) = row?;
            objects.push(serde_json::from_slice(&body)?);
            if let Some(key) = key {
                let key: [u8; 32] = key.try_into().map_err(|bad: Vec<u8>| {
                    StorageError::KeyWrappingFailed(format!(
                        "invalid object content key length for {object_id}: {}",
                        bad.len()
                    ))
                })?;
                object_keys.insert(object_id, key);
            }
        }
        Ok((objects, object_keys))
    }
}
