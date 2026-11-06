// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Persistent native type markers prevent generic-route downgrade, including after cleanup.
use super::{
    AttachmentLedgerError, AttachmentReservation, RECORDS, ReadableDatabase, ReadableTable, decode,
    store,
};
use redb::TableDefinition;
pub(super) const NATIVE: TableDefinition<&[u8], &str> =
    TableDefinition::new("native_attachment_payload_format_v1");
pub(super) const SCHEMA: TableDefinition<&str, u64> =
    TableDefinition::new("native_attachment_format_schema_v1");
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(NATIVE).map_err(store)?;
    let mut schema = tx.open_table(SCHEMA).map_err(store)?;
    if schema.get("indexed").map_err(store)?.is_some() {
        return Ok(());
    }
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let rows = tx.open_table(RECORDS).map_err(store)?;
        let start = cursor.as_deref().map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let page = rows
            .range::<&[u8]>((start, std::ops::Bound::Unbounded))
            .map_err(store)?
            .take(64)
            .map(|e| {
                let (k, v) = e.map_err(store)?;
                Ok((k.value().to_vec(), decode::<AttachmentReservation>(v.value())?))
            })
            .collect::<Result<Vec<_>, AttachmentLedgerError>>()?;
        drop(rows);
        if page.is_empty() {
            break;
        }
        for (k, r) in page {
            bind(tx, &r)?;
            cursor = Some(k);
        }
    }
    schema.insert("indexed", 1).map_err(store)?;
    Ok(())
}
pub(super) fn bind(
    tx: &redb::WriteTransaction,
    record: &AttachmentReservation,
) -> Result<(), AttachmentLedgerError> {
    let Some(hash) = record.manifest_hash else {
        return Ok(());
    };
    let mut native_key = record.object_id.to_vec();
    native_key.extend(hash);
    // A type-denial marker is retained with the backend's terminal object tombstone.
    tx.open_table(NATIVE)
        .map_err(store)?
        .insert(native_key.as_slice(), "segmented_attachment_v1")
        .map_err(store)?;
    Ok(())
}
fn identifier(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 {
        let mut bytes = [0; 32];
        for (i, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        return Some(bytes);
    }
    ramflux_protocol::decode_base64url(s).ok()?.try_into().ok()
}
impl crate::RelayRedbStore {
    /// Generic routes may never dispatch a native stored payload, including cache hits.
    /// # Errors
    /// Refuses native identities and unavailable format persistence.
    pub fn ensure_generic_attachment_format(
        &self,
        object: &str,
        manifest: Option<&str>,
    ) -> Result<(), crate::NodeCoreError> {
        let Some(object) = identifier(object) else {
            return Ok(());
        };
        let tx = self
            .attachment_ledger(super::AttachmentPolicy::default())
            .map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?
            .db
            .begin_read()
            .map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
        let table = tx.open_table(NATIVE).map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?;
        let _ = manifest;
        let native = table
            .range(object.as_slice()..)
            .map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?
            .next()
            .transpose()
            .map_err(|e| crate::NodeCoreError::Redb(e.to_string()))?
            .is_some_and(|(k, _)| k.value().starts_with(&object));
        if native {
            return Err(crate::NodeCoreError::Unauthorized(
                "native attachment requires scoped dispatch".into(),
            ));
        }
        Ok(())
    }
}
