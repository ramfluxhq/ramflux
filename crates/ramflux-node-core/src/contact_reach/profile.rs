// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent home profile publication; no live centre response gates serving.
use super::{
    ReachError, ReachOwner, Result, refuse, storage,
    store::{self, encoded, row},
};
use crate::RouterRedbStore;
use ramflux_protocol::{
    contact_reach::{
        Applied, OPERATION_HASH_DOMAIN, Operation, OperationResult, Reason,
        directory::{PROFILE_HASH_DOMAIN, Profile},
    },
    custody::{self, Envelope as Signed},
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

const PROFILES: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_reach_profile_v1");
const OPERATIONS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_profile_operations_v1");
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileOperation {
    hash: String,
    result: OperationResult,
}

impl RouterRedbStore {
    /// Atomically publish signed profile/epoch/suppression and the original operation result.
    /// # Errors
    /// Refuses wrong primary, stale CAS, terminal deletion and operation-id substitution.
    pub fn reach_publish_profile(
        &self,
        owner: ReachOwner<'_>,
        operation_id: &str,
        expected_epoch: u64,
        update: &Signed<Profile>,
        now: u64,
    ) -> Result<OperationResult> {
        if ramflux_protocol::decode_base64url(operation_id).map_or(true, |v| {
            v.len() != 32 || ramflux_protocol::encode_base64url(v) != operation_id
        }) || expected_epoch.checked_add(1) != Some(update.body.epoch)
        {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let _home_gate = self.acquire_home_operation(owner.recipient_root)?;
        let tx = self.begin_write()?;
        let now = store::clock(&tx, now)?;
        let authority = store::authority(&tx, owner.recipient_root, now)?;
        authority.authorize_primary_management(owner.actor, "profile", now)?;
        let home = store::home(&tx, owner.recipient_root)?;
        let home_hash = ramflux_protocol::home_migration::record_hash(&home.record)?;
        ramflux_crypto::contact_reach::directory::verify_profile(update, &authority, &home_hash)?;
        if update.body.issued_at
            > now.checked_add(60).ok_or_else(|| refuse(Reason::ForeignUnavailable))?
        {
            return Err(refuse(Reason::ForeignInvalidFrame));
        }
        let operation = Operation::ProfilePublish {
            operation_id: operation_id.into(),
            expected_epoch,
            update: update.clone(),
        };
        let hash = custody::framed_hash(OPERATION_HASH_DOMAIN, &operation)?;
        let key = serde_json::to_string(&(owner.recipient_root, operation_id)).map_err(storage)?;
        let mut operations = tx.open_table(OPERATIONS).map_err(storage)?;
        if let Some(old) = operations
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<ProfileOperation>(v.value()))
            .transpose()?
        {
            if old.hash != hash {
                return Err(refuse(Reason::IdempotencyConflict));
            }
            return Ok(old.result);
        }
        if operations.len().map_err(storage)? >= 65_536 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let mut profiles = tx.open_table(PROFILES).map_err(storage)?;
        let old = profiles
            .get(owner.recipient_root)
            .map_err(storage)?
            .map(|v| row::<Signed<Profile>>(v.value()))
            .transpose()?;
        let epoch = old.as_ref().map_or(0, |p| p.body.epoch);
        if expected_epoch != epoch {
            return Err(ReachError::Revision(epoch));
        }
        if old.as_ref().is_some_and(|p| p.body.deleted) {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let result = OperationResult::ProfilePublish {
            epoch: update.body.epoch,
            profile_hash: custody::framed_hash(PROFILE_HASH_DOMAIN, update)?,
            outcome: Applied::Applied,
        };
        profiles.insert(owner.recipient_root, encoded(update)?.as_slice()).map_err(storage)?;
        operations
            .insert(
                key.as_str(),
                encoded(&ProfileOperation { hash, result: result.clone() })?.as_slice(),
            )
            .map_err(storage)?;
        drop(profiles);
        drop(operations);
        tx.commit()?;
        Ok(result)
    }

    /// Read the current signed independent profile, without contacting the directory centre.
    /// # Errors
    /// Returns storage/decode errors. Suppressed profiles are absent from public snapshots.
    pub fn reach_profile(&self, root: &str, public: bool) -> Result<Option<Signed<Profile>>> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(PROFILES) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(storage(e)),
        };
        let value: Option<Signed<Profile>> =
            table.get(root).map_err(storage)?.map(|v| row(v.value())).transpose()?;
        Ok(value.filter(|p| !public || p.body.discoverable && !p.body.deleted))
    }
}
