// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded durable historical public authority for delayed contact consent only.
use crate::{CustodyPublication, NodeCoreError, RouterRedbStore};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};

const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("custody_consent_history_v1");
const EXPIRY: TableDefinition<&str, &str> =
    TableDefinition::new("custody_consent_history_expiry_v1");
const USAGE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("custody_consent_history_usage_v1");
const RETENTION: u64 = 604_800 + 900;
const ACCOUNT_BYTES: u64 = 64 * 1024 * 1024;
const GLOBAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
struct Usage {
    rows: u64,
    bytes: u64,
}
#[derive(Serialize, Deserialize)]
struct Historical {
    expires_at: u64,
    publication: CustodyPublication,
}

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
fn capacity() -> NodeCoreError {
    NodeCoreError::Capacity { resource: "custody consent authority history" }
}
fn hash(publication: &CustodyPublication) -> Result<String, NodeCoreError> {
    ramflux_protocol::custody::object_hash(&publication.record).map_err(error)
}
fn key(anchor: &str, hash: &str) -> String {
    format!("{anchor}/{hash}")
}
fn expiry_key(expires: u64, key: &str) -> String {
    format!("{expires:020}/{key}")
}

pub(super) fn retain(
    tx: &WriteTransaction,
    previous: &CustodyPublication,
    next: &CustodyPublication,
    now: u64,
) -> Result<(), NodeCoreError> {
    let old_hash = hash(previous)?;
    if old_hash == hash(next)? {
        return Ok(());
    }
    let anchor = &previous.record.body.account_anchor;
    let key = key(anchor, &old_hash);
    let mut records = tx.open_table(RECORDS).map_err(error)?;
    if records.get(key.as_str()).map_err(error)?.is_some() {
        return Ok(());
    }
    let expires_at = now.checked_add(RETENTION).ok_or_else(capacity)?;
    let bytes = serde_json::to_vec(&Historical { expires_at, publication: previous.clone() })
        .map_err(error)?;
    let size = u64::try_from(bytes.len()).map_err(error)?;
    let mut usage = tx.open_table(USAGE).map_err(error)?;
    for (scope, max_rows, max_bytes) in
        [(anchor.as_str(), 4096, ACCOUNT_BYTES), ("", 65_536, GLOBAL_BYTES)]
    {
        let mut value: Usage = usage
            .get(scope)
            .map_err(error)?
            .map(|row| serde_json::from_slice(row.value()).map_err(error))
            .transpose()?
            .unwrap_or_default();
        if value.rows >= max_rows || value.bytes.saturating_add(size) > max_bytes {
            return Err(capacity());
        }
        value.rows += 1;
        value.bytes += size;
        let encoded = serde_json::to_vec(&value).map_err(error)?;
        usage.insert(scope, encoded.as_slice()).map_err(error)?;
    }
    records.insert(key.as_str(), bytes.as_slice()).map_err(error)?;
    tx.open_table(EXPIRY)
        .map_err(error)?
        .insert(expiry_key(expires_at, &key).as_str(), key.as_str())
        .map_err(error)?;
    Ok(())
}

impl RouterRedbStore {
    pub(super) fn prune_custody_history(&self, now: u64) -> Result<(), NodeCoreError> {
        let cutoff = format!("{now:020}/~");
        // Inspect the ordered expiry index first; routine publication adds no maintenance write.
        let expired = {
            let read = self.db.begin_read().map_err(error)?;
            let table = match read.open_table(EXPIRY) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                Err(e) => return Err(error(e)),
            };
            table
                .range(..cutoff.as_str())
                .map_err(error)?
                .take(256)
                .map(|entry| {
                    entry
                        .map(|(expires, key)| (expires.value().to_owned(), key.value().to_owned()))
                        .map_err(error)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        if expired.is_empty() {
            return Ok(());
        }
        let tx = self.db.begin_write().map_err(error)?;
        {
            let mut records = tx.open_table(RECORDS).map_err(error)?;
            let mut expiry = tx.open_table(EXPIRY).map_err(error)?;
            let mut usage = tx.open_table(USAGE).map_err(error)?;
            for (expires, key) in expired {
                let removed = records.remove(key.as_str()).map_err(error)?;
                if let Some(row) = removed {
                    let anchor =
                        key.split_once('/').ok_or_else(|| error("invalid custody history key"))?.0;
                    let size = u64::try_from(row.value().len()).map_err(error)?;
                    for scope in [anchor, ""] {
                        let mut value: Usage = usage
                            .get(scope)
                            .map_err(error)?
                            .map(|row| serde_json::from_slice(row.value()).map_err(error))
                            .transpose()?
                            .ok_or_else(|| error("custody history usage absent"))?;
                        value.rows = value
                            .rows
                            .checked_sub(1)
                            .ok_or_else(|| error("custody history usage underflow"))?;
                        value.bytes = value
                            .bytes
                            .checked_sub(size)
                            .ok_or_else(|| error("custody history usage underflow"))?;
                        let encoded = serde_json::to_vec(&value).map_err(error)?;
                        usage.insert(scope, encoded.as_slice()).map_err(error)?;
                    }
                }
                expiry.remove(expires.as_str()).map_err(error)?;
            }
        }
        tx.commit().map_err(error)
    }

    pub(crate) fn custody_historical_publication(
        &self,
        anchor: &str,
        hash: &str,
        now: u64,
    ) -> Result<Option<CustodyPublication>, NodeCoreError> {
        for value in [anchor, hash] {
            if !ramflux_protocol::decode_base64url(value).is_ok_and(|bytes| {
                bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value
            }) {
                return Err(error("invalid custody history selector"));
            }
        }
        let tx = self.db.begin_read().map_err(error)?;
        let table = match tx.open_table(RECORDS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(error(e)),
        };
        let Some(row) = table.get(key(anchor, hash).as_str()).map_err(error)? else {
            return Ok(None);
        };
        let record: Historical = serde_json::from_slice(row.value()).map_err(error)?;
        Ok((now < record.expires_at).then_some(record.publication))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RouterCore;
    use ramflux_crypto::custody::SelfSigningKey;
    use zeroize::Zeroizing;

    #[test]
    fn full_consent_history_refuses_publication_atomically_without_evicting_unexpired_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "rf-custody-history-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../ramflux-crypto/tests/fixtures/custody_v3.json"
        ))?;
        let original = CustodyPublication {
            record: serde_json::from_value(vector["record"].clone())?,
            compacted_ids: None,
        };
        let now = original.record.body.issued_at;
        let anchor = original.record.body.account_anchor.clone();
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
        {
            let store = RouterRedbStore::open_without_wal(&path)?;
            let router = RouterCore::new();
            store.save_router(&router)?;
            router.publish_custody_record(&original, now, &store)?;
            let mut next = original.clone();
            let mut body = original.record.body.clone();
            body.device_set_epoch += 1;
            body.issued_at += 1;
            body.profile.display_name = "First rename".into();
            body.previous_record_hash = Some(hash(&original)?);
            next.record = primary.sign_record(body)?;
            router.publish_custody_record(&next, now + 1, &store)?;
            // Simulate occupied durable admission counters instead of generating thousands
            // of expensive signed heads; the actual publication transaction remains unchanged.
            let tx = store.db.begin_write()?;
            {
                let mut usage = tx.open_table(USAGE)?;
                let mut occupied: Usage =
                    serde_json::from_slice(usage.get(anchor.as_str())?.ok_or("usage")?.value())?;
                occupied.rows = 4096;
                let bytes = serde_json::to_vec(&occupied)?;
                usage.insert(anchor.as_str(), bytes.as_slice())?;
            }
            tx.commit()?;
            let mut rejected = next.clone();
            let mut body = next.record.body.clone();
            body.device_set_epoch += 1;
            body.issued_at += 1;
            body.profile.display_name = "Refused rename".into();
            body.previous_record_hash = Some(hash(&next)?);
            rejected.record = primary.sign_record(body)?;
            let writes = store.custody_publication_write_count();
            assert!(matches!(
                router.publish_custody_record(&rejected, now + 2, &store),
                Err(NodeCoreError::Capacity { .. })
            ));
            assert_eq!(store.custody_publication_write_count(), writes);
            assert_eq!(router.custody_record(&anchor, now + 2)?, Some(next.clone()));
            assert_eq!(
                store.custody_historical_publication(&anchor, &hash(&original)?, now + 2)?,
                Some(original)
            );
            assert!(
                store.custody_historical_publication(&anchor, &hash(&next)?, now + 2)?.is_none()
            );
            assert!(
                store
                    .custody_historical_publication(&anchor, &hash(&rejected)?, now + 2)?
                    .is_none()
            );
        }
        std::fs::remove_file(path)?;
        Ok(())
    }
}
