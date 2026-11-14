// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operation-owned notification authority. Durable work never runs under the send gate.

mod budget;
#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;
pub(crate) use budget::{charge as charge_resource, uncharge as uncharge_resource};
pub(crate) use budget::{
    origin_rows as charge_origin_rows, retire_origin_rows as retire_origin_call_rows,
};
mod issuance;
pub use issuance::{ProviderPreparation, WakeAdmission, WakeIssuance};
mod retirement;
mod wire;
pub use wire::*;
mod origin;
pub use origin::{AuthorityOrigin, OriginIntent, PendingAuthority};
pub mod reservation;
mod rpc;
pub use rpc::{AuthorityClient, AuthorityRpc, AuthorityUpdate, PreparedAuthority};
mod config;
mod server;
pub use config::AuthorityConfiguration;

use crate::NodeCoreError;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const CLOCK: TableDefinition<&str, u64> = TableDefinition::new("notify_send_clock_v1");
const ROWS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_send_authority_v1");
const RECEIPT_SCOPES: TableDefinition<(&str, &str), u8> =
    TableDefinition::new("notify_send_authority_receipt_scopes_v1");
const MAX_SCOPE_BYTES: usize = 65536;
const MAX_MIRRORS: usize = 4096;
const MAX_MIRROR_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SendAuthorityError {
    #[error("call_authority_busy")]
    Busy,
    #[error("send_authority_conflict")]
    Conflict,
    #[error("send_authority_closed")]
    Closed,
    #[error("send_authority_invalid")]
    Invalid,
    #[error("call_authority_capacity")]
    Capacity,
    #[error("send_authority_storage: {0}")]
    Storage(String),
}

impl From<SendAuthorityError> for NodeCoreError {
    fn from(error: SendAuthorityError) -> Self {
        Self::SendAuthority(error)
    }
}

fn storage(error: impl std::fmt::Display) -> SendAuthorityError {
    SendAuthorityError::Storage(error.to_string())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMutation {
    pub version: u32,
    pub operation_id: String,
    pub reservation_id: String,
    pub reservation_generation: u64,
    pub origin_incarnation: String,
    pub expected_generation: u64,
    pub generation: u64,
    pub notify_boot: String,
    pub desired_record_hash: String,
    pub phase: AuthorityPhase,
    pub result: Option<AuthorityMutationResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityMutationResult {
    pub generation: u64,
    pub outcome: AuthorityApplied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityApplied {
    Applied,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableScope {
    mutation: AuthorityMutation,
    desired: AuthorityRecord,
    prior_result: Option<AuthorityMutation>,
    #[serde(default)]
    shared_retire_after: Option<u64>,
    #[serde(default)]
    admitted_boot: String,
}

struct Mirror {
    scope: DurableScope,
    open: bool,
    retiring: bool,
    encoded_bytes: usize,
}

/// One per exclusive store incarnation; all provider workers share this gate.
pub struct SendAuthorityStore {
    db: Arc<redb::Database>,
    boot: String,
    local_identity: Mutex<String>,
    preparations: Arc<std::sync::atomic::AtomicUsize>,
    gate: Mutex<issuance::GateState>,
}

impl SendAuthorityStore {
    /// # Errors
    /// Refuses invalid random boot identifiers or unavailable storage.
    pub fn new(db: Arc<redb::Database>, boot: String) -> Result<Self, SendAuthorityError> {
        validate_digest(&boot)?;
        let tx = db.begin_write().map_err(storage)?;
        {
            tx.open_table(ROWS).map_err(storage)?;
            tx.open_table(RECEIPT_SCOPES).map_err(storage)?;
            tx.open_table(retirement::SHARED_DUE).map_err(storage)?;
            tx.open_table(retirement::SHARED_TIMES).map_err(storage)?;
            tx.open_table(retirement::LOCAL_DUE).map_err(storage)?;
            tx.open_table(retirement::LOCAL_TIMES).map_err(storage)?;
        }
        let floor = tx
            .open_table(CLOCK)
            .map_err(storage)?
            .get("utc_nanoseconds")
            .map_err(storage)?
            .map_or(0, |v| v.value());
        tx.commit().map_err(storage)?;
        // Mirrors start absent/closed even if durable rows were stable in another boot.
        Ok(Self {
            db,
            boot,
            local_identity: Mutex::new("spiffe://notify-local/ramflux-notify".into()),
            preparations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            gate: Mutex::new(issuance::GateState {
                utc_floor: u128::from(floor),
                ..Default::default()
            }),
        })
    }

    #[must_use]
    pub fn boot(&self) -> &str {
        &self.boot
    }

    /// Durable high-water only; this read does not install a sending mirror.
    /// # Errors
    /// Returns malformed-history or storage errors.
    pub fn state(&self, scope: &AuthorityScope) -> Result<AuthorityState, SendAuthorityError> {
        let key = scope.key()?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROWS).map_err(storage)?;
        let row = read_scope(&table, &key)?;
        Ok(match row {
            Some(row) => AuthorityState {
                generation: row.mutation.generation,
                operation_id: Some(row.mutation.operation_id),
                phase: row.mutation.phase,
                record_hash: Some(row.mutation.desired_record_hash),
            },
            None => AuthorityState {
                generation: 0,
                operation_id: None,
                phase: AuthorityPhase::Stable,
                record_hash: None,
            },
        })
    }

    /// Close before persistence, then commit the operation-owned fence outside the gate.
    /// `verified` is the exact authenticated origin read, verified before entry.
    /// # Errors
    /// Refuses a conflicting operation, generation, boot, hash, or exhausted mirror budget.
    pub fn fence(
        &self,
        scope: &AuthorityScope,
        verified: &AuthorityMutation,
        desired: AuthorityRecord,
        observed: &AuthorityState,
        resync: bool,
    ) -> Result<(), SendAuthorityError> {
        validate_mutation(scope, verified, &desired, &self.boot)?;
        if verified.phase != AuthorityPhase::Closing {
            return Err(SendAuthorityError::Invalid);
        }
        let key = scope.key()?;
        let durable = self.load(&key)?;
        let duplicate = durable.as_ref().is_some_and(|row| same_operation(&row.mutation, verified));
        let next = observed.generation.checked_add(1).ok_or(SendAuthorityError::Invalid)?;
        if !duplicate
            && (verified.expected_generation != observed.generation
                || (!resync && verified.generation != next)
                || (resync && verified.generation < next))
        {
            return Err(SendAuthorityError::Conflict);
        }
        let prior_result = durable.as_ref().map(|row| row.mutation.clone());
        let shared_retire_after = retirement::shared_deadline(
            &desired,
            durable.as_ref().and_then(|row| row.shared_retire_after),
        )?;
        let candidate = DurableScope {
            admitted_boot: durable
                .as_ref()
                .map_or_else(|| self.boot.clone(), |row| row.admitted_boot.clone()),
            mutation: verified.clone(),
            desired,
            prior_result,
            shared_retire_after,
        };
        let encoded = encode(&candidate)?;
        {
            let mut gate = self.gate.lock().map_err(storage)?;
            if let Some(current) = gate.get(&key) {
                if current.retiring {
                    return Err(SendAuthorityError::Closed);
                }
                if same_operation(&current.scope.mutation, verified) {
                    if current.scope.mutation.phase == AuthorityPhase::Closing {
                        // Retry below verifies/persists a previously uncertain fence.
                    } else {
                        return Ok(());
                    }
                } else if !current.open || current.scope.mutation.generation >= verified.generation
                {
                    return Err(SendAuthorityError::Conflict);
                }
            }
            gate.loading.remove(&key);
            issuance::cache_room(&mut gate, &key, encoded.len())?;
            gate.insert(
                key.clone(),
                Mirror {
                    scope: candidate.clone(),
                    open: false,
                    retiring: false,
                    encoded_bytes: encoded.len(),
                },
            );
        }
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let mut table = tx.open_table(ROWS).map_err(storage)?;
            let current = read_scope(&table, &key)?;
            let matches_observed = match current.as_ref() {
                Some(row) => observed.matches(&row.mutation),
                None => observed.is_empty(),
            };
            if current.as_ref().is_some_and(|row| same_operation(&row.mutation, verified)) {
                return Ok(());
            }
            if !matches_observed {
                return Err(SendAuthorityError::Conflict);
            }
            charge_scope(&tx, &key, &candidate, encoded.len())?;
            retirement::index_shared(&tx, &key, candidate.shared_retire_after)?;
            table.insert(key.as_str(), encoded.as_slice()).map_err(storage)?;
            tx.open_table(RECEIPT_SCOPES)
                .map_err(storage)?
                .insert((verified.reservation_id.as_str(), key.as_str()), 0)
                .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// Persist publication, then open only the same operation/generation/boot/hash.
    /// # Errors
    /// Conflicting or old completions leave the mirror closed and unchanged.
    pub fn publish(
        &self,
        scope: &AuthorityScope,
        verified: &AuthorityMutation,
        desired: &AuthorityRecord,
    ) -> Result<(), SendAuthorityError> {
        validate_mutation(scope, verified, desired, &self.boot)?;
        if verified.phase != AuthorityPhase::Committed {
            return Err(SendAuthorityError::Invalid);
        }
        let key = scope.key()?;
        let mut candidate = self.load(&key)?.ok_or(SendAuthorityError::Closed)?;
        if !same_operation(&candidate.mutation, verified) {
            return Err(SendAuthorityError::Conflict);
        }
        {
            let gate = self.gate.lock().map_err(storage)?;
            let mirror = gate.get(&key).ok_or(SendAuthorityError::Closed)?;
            if mirror.retiring {
                return Err(SendAuthorityError::Closed);
            }
            if !same_operation(&mirror.scope.mutation, verified) {
                return Err(SendAuthorityError::Conflict);
            }
        }
        candidate.mutation.phase = AuthorityPhase::Stable;
        candidate.mutation.result = Some(AuthorityMutationResult {
            generation: verified.generation,
            outcome: AuthorityApplied::Applied,
        });
        let encoded = encode(&candidate)?;
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let mut table = tx.open_table(ROWS).map_err(storage)?;
            let current = read_scope(&table, &key)?.ok_or(SendAuthorityError::Closed)?;
            if !same_operation(&current.mutation, verified) {
                return Err(SendAuthorityError::Conflict);
            }
            charge_scope(&tx, &key, &candidate, encoded.len())?;
            table.insert(key.as_str(), encoded.as_slice()).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        let mut gate = self.gate.lock().map_err(storage)?;
        let mirror = gate.get_mut(&key).ok_or(SendAuthorityError::Closed)?;
        if mirror.retiring {
            return Err(SendAuthorityError::Closed);
        }
        if !same_operation(&mirror.scope.mutation, verified) {
            return Err(SendAuthorityError::Conflict);
        }
        mirror.scope = candidate;
        mirror.encoded_bytes = encoded.len();
        mirror.open = true;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<DurableScope>, SendAuthorityError> {
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(ROWS).map_err(storage)?;
        read_scope(&table, key)
    }
}

fn same_operation(a: &AuthorityMutation, b: &AuthorityMutation) -> bool {
    a.reservation_id == b.reservation_id
        && a.reservation_generation == b.reservation_generation
        && a.origin_incarnation == b.origin_incarnation
        && a.operation_id == b.operation_id
        && a.expected_generation == b.expected_generation
        && a.generation == b.generation
        && a.notify_boot == b.notify_boot
        && a.desired_record_hash == b.desired_record_hash
}

fn encode(row: &DurableScope) -> Result<Vec<u8>, SendAuthorityError> {
    let bytes = ramflux_protocol::canonical_json_bytes(row).map_err(storage)?;
    if bytes.len() > MAX_SCOPE_BYTES {
        return Err(SendAuthorityError::Capacity);
    }
    Ok(bytes)
}

fn read_scope(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<DurableScope>, SendAuthorityError> {
    let Some(row) = table.get(key).map_err(storage)? else { return Ok(None) };
    if row.value().len() > MAX_SCOPE_BYTES {
        return Err(SendAuthorityError::Invalid);
    }
    ramflux_protocol::parse_i_json(row.value()).map(Some).map_err(storage)
}

fn validate_mutation(
    scope: &AuthorityScope,
    mutation: &AuthorityMutation,
    desired: &AuthorityRecord,
    boot: &str,
) -> Result<(), SendAuthorityError> {
    validate_digest(&mutation.operation_id)?;
    validate_digest(&mutation.reservation_id)?;
    validate_digest(&mutation.origin_incarnation)?;
    if mutation.version != 1
        || mutation.notify_boot != boot
        || mutation.generation == 0
        || mutation.generation > MAX_AUTHORITY_GENERATION
        || mutation.expected_generation >= mutation.generation
        || mutation.desired_record_hash != desired.record_hash()?
        || desired.scope()? != *scope
        || ramflux_protocol::canonical_json_bytes(mutation).map_err(storage)?.len() > 8192
    {
        return Err(SendAuthorityError::Invalid);
    }
    Ok(())
}

fn charge_scope(
    tx: &redb::WriteTransaction,
    key: &str,
    row: &DurableScope,
    bytes: usize,
) -> Result<(), SendAuthorityError> {
    let (root, slot) = match &row.desired {
        AuthorityRecord::Call { recipient_root, start_digest, .. } => {
            let body =
                serde_json::json!({"recipient_root":recipient_root,"start_digest":start_digest});
            (
                recipient_root.clone(),
                Some(ramflux_crypto::blake3_256_base64url(
                    "ramflux.notification.call_slot.v1\0",
                    &ramflux_protocol::canonical_json_bytes(&body).map_err(storage)?,
                )),
            )
        }
        AuthorityRecord::Owner { target_delivery_id, .. }
        | AuthorityRecord::LocalRows {
            resource: LocalAuthorityResource::TargetRoutes,
            scope_key: target_delivery_id,
            ..
        } => (
            ramflux_protocol::parse_qualified_device_id(target_delivery_id)
                .map_err(storage)?
                .map_or_else(reservation::system_root, |(root, _)| root),
            None,
        ),
        AuthorityRecord::LocalRows { resource: LocalAuthorityResource::Credential, .. } => {
            (reservation::system_root(), None)
        }
    };
    // The durable desired tuple includes its high-water; charge the receipt index and mirror.
    budget::charge(
        tx,
        &root,
        slot.as_deref(),
        true,
        &format!("scope:{key}"),
        (
            2 * bytes + 2 * key.len() + row.mutation.reservation_id.len() + 16,
            3 + 2 * u64::from(row.shared_retire_after.is_some()),
        ),
    )
}
