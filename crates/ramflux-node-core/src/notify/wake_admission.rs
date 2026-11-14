// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fund first-admission memory and retain its budget across uncertain origin lookups.

use super::{
    Deserialize, NodeCoreError, NotifyRedbStore, Read, ReadableDatabase, ReadableTable, Serialize,
    TableDefinition,
};
use crate::send_authority::{AuthorityCallState, AuthorityRecord, SendAuthorityError, reservation};

const PENDING: TableDefinition<(&str, &str), &[u8]> =
    TableDefinition::new("notify_pending_wake_admission_v1");
const DUE: TableDefinition<(u64, &str), &str> =
    TableDefinition::new("notify_pending_wake_admission_due_v1");
const STARTS: TableDefinition<(&str, &str), &str> =
    TableDefinition::new("notify_pending_wake_start_v1");
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingWake {
    pub digest: String,
    pub start: Option<String>,
    pub expiry: u64,
    pub until: u64,
}
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
fn slot(root: &str, start: Option<&str>) -> Result<Option<String>, NodeCoreError> {
    start
        .map(|start| {
            Ok(ramflux_crypto::blake3_256_base64url(
                "ramflux.notification.call_slot.v1\0",
                &ramflux_protocol::canonical_json_bytes(
                    &serde_json::json!({"recipient_root":root,"start_digest":start}),
                )
                .map_err(error)?,
            ))
        })
        .transpose()
}
pub(super) fn target_root(target: &str) -> Result<String, NodeCoreError> {
    Ok(ramflux_protocol::parse_qualified_device_id(target)
        .map_err(error)?
        .map_or_else(reservation::system_root, |(root, _)| root))
}
pub(super) fn initialize(tx: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    tx.open_table(PENDING).map_err(error)?;
    tx.open_table(DUE).map_err(error)?;
    tx.open_table(STARTS).map_err(error)?;
    Ok(())
}
pub(super) fn read(
    db: &redb::Database,
    root: &str,
    key: &str,
) -> Result<Option<PendingWake>, NodeCoreError> {
    let tx = db.begin_read().map_err(error)?;
    let table = tx.open_table(PENDING).map_err(error)?;
    table
        .get((root, key))
        .map_err(error)?
        .map(|value| {
            if value.value().len() > 8192 {
                return Err(SendAuthorityError::Capacity.into());
            }
            ramflux_protocol::parse_i_json(value.value()).map_err(error)
        })
        .transpose()
}
pub(super) fn nonempty(tx: &redb::ReadTransaction, root: &str) -> Result<bool, NodeCoreError> {
    Ok(tx
        .open_table(PENDING)
        .map_err(error)?
        .range((root, "")..=(root, "\u{10ffff}"))
        .map_err(error)?
        .next()
        .transpose()
        .map_err(error)?
        .is_some())
}
pub(super) fn remove(
    tx: &redb::WriteTransaction,
    root: &str,
    key: &str,
) -> Result<(), NodeCoreError> {
    let bytes = tx
        .open_table(PENDING)
        .map_err(error)?
        .remove((root, key))
        .map_err(error)?
        .map(|v| v.value().to_vec());
    if let Some(bytes) = bytes {
        let row: PendingWake = ramflux_protocol::parse_i_json(&bytes).map_err(error)?;
        tx.open_table(DUE).map_err(error)?.remove((row.until, key)).map_err(error)?;
        if let Some(start) = &row.start {
            tx.open_table(STARTS).map_err(error)?.remove((start.as_str(), key)).map_err(error)?;
        }
        crate::send_authority::uncharge_resource(
            tx,
            root,
            slot(root, row.start.as_deref())?.as_deref(),
            true,
            &format!("pending-wake:{key}"),
        )?;
    }
    Ok(())
}

pub(super) fn retire_call(
    tx: &redb::WriteTransaction,
    start: &str,
    now: u64,
) -> Result<Vec<String>, NodeCoreError> {
    let keys = tx
        .open_table(STARTS)
        .map_err(error)?
        .range((start, "")..=(start, "\u{10ffff}"))
        .map_err(error)?
        .take(129)
        .map(|entry| {
            entry
                .map(|(key, root)| (root.value().to_owned(), key.value().1.to_owned()))
                .map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.len() > 128 {
        return Err(SendAuthorityError::Capacity.into());
    }
    for (root, key) in &keys {
        let bytes = tx
            .open_table(PENDING)
            .map_err(error)?
            .get((root.as_str(), key.as_str()))
            .map_err(error)?
            .map(|v| v.value().to_vec())
            .ok_or(SendAuthorityError::Invalid)?;
        let row: PendingWake = ramflux_protocol::parse_i_json(&bytes).map_err(error)?;
        if row.until > now {
            return Err(SendAuthorityError::Closed.into());
        }
        remove(tx, root, key)?;
    }
    Ok(keys.into_iter().map(|(_, key)| key).collect())
}
pub(super) fn prune(tx: &redb::WriteTransaction, now: u64) -> Result<usize, NodeCoreError> {
    let keys = tx
        .open_table(DUE)
        .map_err(error)?
        .range(..=(now, "\u{10ffff}"))
        .map_err(error)?
        .take(128)
        .map(|entry| {
            entry
                .map(|(key, root)| (root.value().to_owned(), key.value().1.to_owned()))
                .map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (root, key) in &keys {
        remove(tx, root, key)?;
    }
    Ok(keys.len())
}
impl NotifyRedbStore {
    pub(super) fn reserve_pending_wake(
        &self,
        root: &str,
        key: &str,
        digest: &str,
        start: Option<&str>,
        expiry: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.db.begin_write().map_err(error)?;
        let existing = tx
            .open_table(PENDING)
            .map_err(error)?
            .get((root, key))
            .map_err(error)?
            .map(|v| v.value().to_vec());
        let row = if let Some(bytes) = existing {
            let row: PendingWake = ramflux_protocol::parse_i_json(&bytes).map_err(error)?;
            if row.digest != digest || row.start.as_deref() != start || row.expiry != expiry {
                return Err(SendAuthorityError::Conflict.into());
            }
            row
        } else {
            PendingWake {
                digest: digest.into(),
                start: start.map(str::to_owned),
                expiry,
                until: expiry
                    .checked_add(ramflux_protocol::CLOCK_UNCERTAINTY_SECONDS)
                    .ok_or(SendAuthorityError::Invalid)?,
            }
        };
        let bytes = ramflux_protocol::canonical_json_bytes(&row).map_err(error)?;
        crate::send_authority::charge_resource(
            &tx,
            root,
            slot(root, start)?.as_deref(),
            true,
            &format!("pending-wake:{key}"),
            (2 * bytes.len() + root.len() + 3 * key.len() + 128, 3 + u64::from(start.is_some())),
        )?;
        tx.open_table(PENDING)
            .map_err(error)?
            .insert((root, key), bytes.as_slice())
            .map_err(error)?;
        tx.open_table(DUE).map_err(error)?.insert((row.until, key), root).map_err(error)?;
        if let Some(start) = start {
            tx.open_table(STARTS).map_err(error)?.insert((start, key), root).map_err(error)?;
        }
        self.send_authority.persist_clock(&tx)?;
        tx.commit().map_err(error)
    }

    pub(super) fn local_call_mapping(
        &self,
        signed: &ramflux_protocol::SignedWakeV2,
    ) -> Result<(), NodeCoreError> {
        let Some(digest) = signed.body.call_intent_digest.as_deref() else { return Ok(()) };
        let AuthorityRecord::Call {
            signed_start: Some(start),
            state: AuthorityCallState::Ringing,
            ..
        } = self.send_authority.current_boot_call(digest)?
        else {
            return Err(SendAuthorityError::Closed.into());
        };
        if start.body.target_delivery_id != signed.body.target_delivery_id
            || start.body.target_epoch != signed.body.target_owner_epoch
            || start.body.expires_at != signed.body.expires_at
        {
            return Err(SendAuthorityError::Conflict.into());
        }
        Ok(())
    }
}
