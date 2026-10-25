// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real federation GC enforces envelope expiry and retires forward replay receipts.
use super::{
    FEDERATION_INBOUND_FORWARD_SEEN_TABLE, FEDERATION_OUTBOUND_SPOOL_TABLE, FederationRedbStore,
    NodeCoreError, deserialize_inbound_forward_seen_record, deserialize_spool_entry,
};
use redb::ReadableTable;
impl FederationRedbStore {
    /// Keep only the public discovery identity in redb; a changed secret requires explicit rotation.
    /// # Errors
    /// Rejects replacing a persisted node identity with a different mounted secret.
    pub fn verify_mounted_signing_identity(&self, seed: [u8; 32]) -> Result<(), NodeCoreError> {
        let public = ramflux_crypto::public_key_base64url_from_seed(seed);
        let txn = self.db.begin_write().map_err(error)?;
        {
            let mut table = txn.open_table(super::FEDERATION_STATE_TABLE).map_err(error)?;
            let old = table
                .get("node_signing_public_key_v1")
                .map_err(error)?
                .map(|value| value.value().to_vec());
            if old.as_deref().is_some_and(|old| old != public.as_bytes()) {
                return Err(NodeCoreError::Unauthorized(
                    "mounted federation identity changed".into(),
                ));
            }
            table.insert("node_signing_public_key_v1", public.as_bytes()).map_err(error)?;
        }
        txn.commit().map_err(error)
    }
    /// # Errors
    /// Returns decoding or durable storage errors. A dry run does not remove rows.
    pub fn sweep_delivery_retention(
        &self,
        now: u64,
        dry_run: bool,
    ) -> Result<usize, NodeCoreError> {
        let txn = self.db.begin_write().map_err(error)?;
        let mut removed = 0;
        {
            let mut table = txn.open_table(FEDERATION_OUTBOUND_SPOOL_TABLE).map_err(error)?;
            let mut keys = Vec::new();
            for row in table.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let entry = deserialize_spool_entry(value.value())?;
                let envelope = &entry.forward.envelope;
                let deadline =
                    envelope.created_at.saturating_add(i64::from(envelope.ttl.min(604_800)));
                if entry.expires_at <= now || deadline <= i64::try_from(now).unwrap_or(i64::MAX) {
                    keys.push(key.value().to_owned());
                }
            }
            removed += keys.len();
            if !dry_run {
                for key in keys {
                    table.remove(key.as_str()).map_err(error)?;
                }
            }
        }
        {
            let mut table = txn.open_table(FEDERATION_INBOUND_FORWARD_SEEN_TABLE).map_err(error)?;
            let mut keys = Vec::new();
            for row in table.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let entry = deserialize_inbound_forward_seen_record(value.value())?;
                if entry.expires_at <= now {
                    keys.push(key.value().to_owned());
                }
            }
            removed += keys.len();
            if !dry_run {
                for key in keys {
                    table.remove(key.as_str()).map_err(error)?;
                }
            }
        }
        if dry_run {
            txn.abort().map_err(error)?;
        } else {
            txn.commit().map_err(error)?;
        }
        Ok(removed)
    }
}
fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}
