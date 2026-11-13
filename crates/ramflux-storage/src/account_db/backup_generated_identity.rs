// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable event sequence and HLC high-water marks merge by exact unsigned maximum.
use super::backup_database::BackupDatabase;
use crate::StorageError;
use ramflux_protocol::message as g;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

const COUNTER: &str = "message-identity/counter/";
const CLOCK: &str = "message-identity/hlc/";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Counter {
    conversation_id: String,
    author: g::QualifiedDevice,
    sequence: u64,
}
fn invalid() -> StorageError {
    StorageError::AuthorizationRejected
}
fn counter(key: &str, bytes: &[u8]) -> Result<Counter, StorageError> {
    let value: Counter = serde_json::from_slice(bytes)?;
    let suffix = key.strip_prefix(COUNTER).ok_or_else(invalid)?;
    let encoded = ramflux_protocol::decode_base64url(suffix).map_err(|_| invalid())?;
    let (author, conversation, private): (g::QualifiedDevice, String, bool) =
        serde_json::from_slice(&encoded)?;
    if author != value.author
        || conversation != value.conversation_id
        || value.sequence == 0
        || value.sequence >= 1 << 63
        || ramflux_protocol::canonical_json_bytes(&(&author, &conversation, private))? != encoded
        || ramflux_protocol::encode_base64url(&encoded) != suffix
    {
        return Err(invalid());
    }
    g::identity::derive(
        &author,
        &conversation,
        if private { value.sequence | (1 << 63) } else { value.sequence },
    )
    .map_err(|_| invalid())?;
    Ok(value)
}

impl BackupDatabase {
    pub(super) fn merge_generated_identity_floors(&self) -> Result<(), StorageError> {
        let rows = {
            let mut query = self.db.prepare("SELECT state_kind,state_json FROM incoming.runtime_actor_state WHERE state_kind LIKE 'message-identity/counter/%' OR state_kind LIKE 'message-identity/hlc/%'")?;
            query
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (key, bytes) in rows {
            let local = self
                .db
                .query_row(
                    "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                    [&key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            let replace = if key.starts_with(COUNTER) {
                let incoming = counter(&key, &bytes)?;
                let current = local.as_ref().map(|bytes| counter(&key, bytes)).transpose()?;
                current.is_none_or(|current| incoming.sequence > current.sequence)
            } else {
                let suffix = key.strip_prefix(CLOCK).ok_or_else(invalid)?;
                if ramflux_protocol::parse_qualified_device_id(suffix)?.is_none() {
                    return Err(invalid());
                }
                let incoming: u64 = serde_json::from_slice(&bytes)?;
                let current: Option<u64> =
                    local.as_ref().map(|bytes| serde_json::from_slice(bytes)).transpose()?;
                current.is_none_or(|current| incoming > current)
            };
            if replace {
                let updated = self.db.execute(
                    "UPDATE runtime_actor_state SET state_json=?2 WHERE state_kind=?1",
                    params![key, bytes],
                )?;
                if updated == 0 {
                    self.db.execute(
                        "INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
                        params![key, bytes],
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn restored_event_sequences_and_hlc_never_decrease_or_mix_private_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let (source_root, source) = crate::tests::test_db("identity-restore-source")?;
        let (target_root, target) = crate::tests::test_db("identity-restore-target")?;
        let author = g::QualifiedDevice {
            account_anchor: ramflux_protocol::encode_base64url([7; 32]),
            device_id: "phone".into(),
            device_epoch: 4,
        };
        let key = |private| -> Result<String, Box<dyn std::error::Error>> {
            Ok(format!(
                "{COUNTER}{}",
                ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&(
                    &author, "thread", private
                ))?)
            ))
        };
        for (private, old, incoming) in [(false, 9, 17), (true, 23, 8)] {
            target.persist_actor_state(
                &key(private)?,
                &json!({"author":author,"conversation_id":"thread","sequence":old}),
            )?;
            source.persist_actor_state(
                &key(private)?,
                &json!({"author":author,"conversation_id":"thread","sequence":incoming}),
            )?;
        }
        let clock = format!(
            "{CLOCK}{}",
            ramflux_protocol::qualified_device_id(&author.account_anchor, &author.device_id)?
        );
        source.persist_actor_state(&clock, &(u64::MAX - 1))?;
        target.persist_actor_state(&clock, &u64::MAX)?;
        let newer_clock = format!(
            "{CLOCK}{}",
            ramflux_protocol::qualified_device_id(&author.account_anchor, "tablet")?
        );
        source.persist_actor_state(&newer_clock, &u64::MAX)?;
        target.persist_actor_state(&newer_clock, &(u64::MAX - 2))?;
        let incoming = source_root.join("incoming.db");
        let first = source.write_backup_snapshot(&incoming)?;
        let path = target_root.join("merged.db");
        let second = target.write_backup_snapshot(&path)?;
        let mut merged = BackupDatabase::open(&path, &second.key)?;
        merged.merge_backup(&incoming, &first.key, || Ok(()))?;
        let read = |key: &str| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
            let bytes: Vec<u8> = merged.db.query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                [key],
                |row| row.get(0),
            )?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        assert_eq!(read(&key(false)?)?["sequence"], 17);
        assert_eq!(read(&key(true)?)?["sequence"], 23);
        assert_eq!(read(&clock)?, json!(u64::MAX));
        assert_eq!(read(&newer_clock)?, json!(u64::MAX));
        drop((merged, source, target));
        std::fs::remove_dir_all(source_root)?;
        std::fs::remove_dir_all(target_root)?;
        Ok(())
    }
}
