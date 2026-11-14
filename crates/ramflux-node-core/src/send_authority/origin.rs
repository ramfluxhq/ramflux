// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable origin half of fence → authoritative commit → publication → stable.

use super::{
    AuthorityApplied, AuthorityMutation, AuthorityMutationResult, AuthorityPhase,
    AuthorityReadPurpose, AuthorityReadRefusal, AuthorityReadResult, AuthorityRecord,
    AuthorityScope, AuthorityState, MAX_AUTHORITY_GENERATION, SendAuthorityError, same_operation,
    storage, validate_mutation,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const ORIGIN: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notification_authority_origin_v1");

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginRow {
    mutation: AuthorityMutation,
    desired: AuthorityRecord,
    desired_payload: String,
    reservation: super::reservation::ReservationReply,
    previous: Option<AuthorityMutation>,
    #[serde(default)]
    shared_retire_after: Option<u64>,
    #[serde(default)]
    parent_anchor: Option<String>,
}

pub struct OriginIntent<'a> {
    pub scope: &'a AuthorityScope,
    pub desired: AuthorityRecord,
    pub notify_boot: &'a str,
    pub notify_state: &'a AuthorityState,
    pub operation_id: &'a str,
    pub reservation: &'a super::reservation::ReservationReply,
    pub desired_payload: &'a [u8],
}

pub struct PendingAuthority {
    pub mutation: AuthorityMutation,
    pub record: AuthorityRecord,
    pub payload: Vec<u8>,
    pub reservation: super::reservation::ReservationReply,
}

const RECEIPT_INDEX: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notification_origin_receipt_index_v1");

/// Origin transactions share the exact database holding the authoritative records.
const RECEIPT_SCOPES: TableDefinition<(&str, &str), u8> =
    TableDefinition::new("notification_origin_receipt_scopes_v1");
const PARENTS: TableDefinition<(&str, &str), u8> =
    TableDefinition::new("notification_origin_custodian_scopes_v1");

fn parent(record: &AuthorityRecord) -> Option<&str> {
    match record {
        AuthorityRecord::Owner { custody_authority: Some(evidence), .. } => evidence
            .custodian_publication
            .as_ref()
            .map(|publication| publication.record.body.account_anchor.as_str()),
        _ => None,
    }
}

pub struct AuthorityOrigin;

const SHARED_DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("notification_origin_shared_due_v1");

impl AuthorityOrigin {
    /// # Errors
    /// Returns storage errors without resetting existing scope history.
    pub fn initialize(db: &redb::Database) -> Result<(), SendAuthorityError> {
        let tx = db.begin_write().map_err(storage)?;
        {
            tx.open_table(ORIGIN).map_err(storage)?;
            tx.open_table(RECEIPT_INDEX).map_err(storage)?;
            tx.open_table(RECEIPT_SCOPES).map_err(storage)?;
            tx.open_table(PARENTS).map_err(storage)?;
            tx.open_table(SHARED_DUE).map_err(storage)?;
        }
        tx.commit().map_err(storage)
    }

    /// # Errors
    /// Reads the stored binding from the caller's authoritative read transaction.
    pub fn binding(
        tx: &redb::ReadTransaction,
        scope: &AuthorityScope,
    ) -> Result<Option<AuthorityMutation>, SendAuthorityError> {
        let table = tx.open_table(ORIGIN).map_err(storage)?;
        read(&table, &scope.key()?).map(|row| row.map(|row| row.mutation))
    }

    /// # Errors
    /// Returns the receipt persisted atomically with this component's first charged intent.
    pub fn receipt(
        db: &redb::Database,
        root: &str,
        slot: Option<&str>,
    ) -> Result<Option<super::reservation::ReservationReply>, SendAuthorityError> {
        let key = receipt_key(root, slot)?;
        let tx = db.begin_read().map_err(storage)?;
        let table = tx.open_table(RECEIPT_INDEX).map_err(storage)?;
        let Some(bytes) = table.get(key.as_str()).map_err(storage)? else { return Ok(None) };
        if bytes.value().len() > 8192 {
            return Err(SendAuthorityError::Capacity);
        }
        ramflux_protocol::parse_i_json(bytes.value()).map(Some).map_err(storage)
    }

    /// Prove absence using the index committed with every first charged scope intent.
    /// # Errors
    /// Missing/corrupt indexes never confer an empty-component proof.
    pub fn reservation_nonempty(db: &redb::Database, id: &str) -> Result<bool, SendAuthorityError> {
        let tx = db.begin_read().map_err(storage)?;
        let table = tx.open_table(RECEIPT_SCOPES).map_err(storage)?;
        Ok(table
            .range((id, "")..=(id, "\u{10ffff}"))
            .map_err(storage)?
            .next()
            .transpose()
            .map_err(storage)?
            .is_some())
    }

    /// Retire only after the caller has passed every fixed signed-request denial horizon.
    /// # Errors
    /// The exact committed tuple and all charged origin indexes must retire together.
    pub fn retire(
        tx: &redb::WriteTransaction,
        scope: &AuthorityScope,
        owning: &AuthorityMutation,
    ) -> Result<(), SendAuthorityError> {
        let key = scope.key()?;
        let mut table = tx.open_table(ORIGIN).map_err(storage)?;
        let row = read(&table, &key)?.ok_or(SendAuthorityError::Closed)?;
        if row.mutation.phase != AuthorityPhase::Stable || !same_operation(&row.mutation, owning) {
            return Err(SendAuthorityError::Conflict);
        }
        table.remove(key.as_str()).map_err(storage)?;
        if let Some(parent) = row.parent_anchor.as_deref() {
            tx.open_table(PARENTS)
                .map_err(storage)?
                .remove((parent, key.as_str()))
                .map_err(storage)?;
        }
        if let Some(at) = row.shared_retire_after {
            tx.open_table(SHARED_DUE)
                .map_err(storage)?
                .remove((at, key.as_str()))
                .map_err(storage)?;
        }
        let mut index = tx.open_table(RECEIPT_SCOPES).map_err(storage)?;
        index.remove((owning.reservation_id.as_str(), key.as_str())).map_err(storage)?;
        let nonempty = index
            .range(
                (owning.reservation_id.as_str(), "")
                    ..=(owning.reservation_id.as_str(), "\u{10ffff}"),
            )
            .map_err(storage)?
            .next()
            .transpose()
            .map_err(storage)?
            .is_some();
        let root = &row.reservation.recipient_root;
        let slot = row.reservation.slot_id.as_deref();
        super::budget::uncharge(tx, root, slot, false, &format!("scope:{key}"))?;
        super::budget::uncharge(tx, root, slot, false, &format!("index:{key}"))?;
        if !nonempty {
            tx.open_table(RECEIPT_INDEX)
                .map_err(storage)?
                .remove(receipt_key(root, slot)?.as_str())
                .map_err(storage)?;
            super::budget::uncharge(tx, root, slot, false, "receipt")?;
        }
        Ok(())
    }

    /// Exact retained desired state for idempotent phase resumption after restart.
    /// # Errors
    /// Returns corrupt/oversized history errors; it never invents missing pending data.
    pub fn pending(
        db: &redb::Database,
        scope: &AuthorityScope,
    ) -> Result<Option<PendingAuthority>, SendAuthorityError> {
        let key = scope.key()?;
        let tx = db.begin_read().map_err(storage)?;
        let table = tx.open_table(ORIGIN).map_err(storage)?;
        let Some(row) = read(&table, &key)? else { return Ok(None) };
        if row.desired_payload.len() > 87384 {
            return Err(SendAuthorityError::Capacity);
        }
        let payload = ramflux_protocol::decode_base64url(&row.desired_payload).map_err(storage)?;
        if payload.len() > 64 * 1024 {
            return Err(SendAuthorityError::Capacity);
        }
        Ok(Some(PendingAuthority {
            mutation: row.mutation,
            record: row.desired,
            payload,
            reservation: row.reservation,
        }))
    }

    /// Reserve a new operation only when the previous operation is stable.
    /// # Errors
    /// Refuses concurrent distinct work, changed desired records and unsafe generations.
    pub fn begin(
        db: &redb::Database,
        intent: OriginIntent<'_>,
    ) -> Result<AuthorityMutation, SendAuthorityError> {
        let OriginIntent {
            scope,
            desired,
            notify_boot,
            notify_state,
            operation_id,
            reservation,
            desired_payload,
        } = intent;
        if reservation.phase != super::reservation::ReservationPhase::Active {
            return Err(SendAuthorityError::Closed);
        }
        if desired_payload.len() > 64 * 1024 {
            return Err(SendAuthorityError::Capacity);
        }
        let key = scope.key()?;
        let hash = desired.record_hash()?;
        let tx = db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(ORIGIN).map_err(storage)?;
        let previous = read(&table, &key)?;
        if let Some(previous) = previous.as_ref()
            && previous.mutation.phase != AuthorityPhase::Stable
        {
            if previous.mutation.notify_boot == notify_boot
                && previous.mutation.operation_id == operation_id
                && previous.mutation.desired_record_hash == hash
            {
                return Ok(previous.mutation.clone());
            }
            return Err(SendAuthorityError::Conflict);
        }
        // A new mutation is ordinary: current origin and notify must agree first.
        let high_water = previous.as_ref().map_or(0, |row| row.mutation.generation);
        if high_water != notify_state.generation {
            return Err(SendAuthorityError::Conflict);
        }
        if let Some(previous) = previous.as_ref()
            && !notify_state.matches(&previous.mutation)
        {
            return Err(SendAuthorityError::Conflict);
        }
        if previous.is_none() && !notify_state.is_empty() {
            return Err(SendAuthorityError::Conflict);
        }
        let generation = next_generation(high_water, notify_state.generation)?;
        let mutation = AuthorityMutation {
            version: 1,
            operation_id: operation_id.to_owned(),
            reservation_id: reservation.reservation_id.clone().ok_or(SendAuthorityError::Closed)?,
            reservation_generation: reservation
                .reservation_generation
                .ok_or(SendAuthorityError::Closed)?,
            origin_incarnation: reservation.origin_incarnation.clone(),
            expected_generation: notify_state.generation,
            generation,
            notify_boot: notify_boot.to_owned(),
            desired_record_hash: hash,
            phase: AuthorityPhase::Closing,
            result: None,
        };
        validate_mutation(scope, &mutation, &desired, notify_boot)?;
        let shared_retire_after = super::retirement::shared_deadline(
            &desired,
            previous.as_ref().and_then(|row| row.shared_retire_after),
        )?;
        let parent_anchor = parent(&desired).map(str::to_owned).or_else(|| {
            matches!(desired, AuthorityRecord::Owner { revoked: true, .. })
                .then(|| previous.as_ref().and_then(|row| row.parent_anchor.clone()))
                .flatten()
        });
        if let Some(at) = previous.as_ref().and_then(|row| row.shared_retire_after) {
            tx.open_table(SHARED_DUE)
                .map_err(storage)?
                .remove((at, key.as_str()))
                .map_err(storage)?;
        }
        let row = OriginRow {
            mutation: mutation.clone(),
            desired,
            desired_payload: ramflux_protocol::encode_base64url(desired_payload),
            reservation: reservation.clone(),
            previous: previous.map(|row| row.mutation),
            shared_retire_after,
            parent_anchor,
        };
        write(&tx, &mut table, &key, &row)?;
        tx.open_table(RECEIPT_SCOPES)
            .map_err(storage)?
            .insert((mutation.reservation_id.as_str(), key.as_str()), 0)
            .map_err(storage)?;
        let receipt_key = receipt_key(&reservation.recipient_root, reservation.slot_id.as_deref())?;
        let bytes = ramflux_protocol::canonical_json_bytes(reservation).map_err(storage)?;
        tx.open_table(RECEIPT_INDEX)
            .map_err(storage)?
            .insert(receipt_key.as_str(), bytes.as_slice())
            .map_err(storage)?;
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(mutation)
    }

    /// Bounded retirement inventory; an uncertain mutation remains charged.
    /// # Errors
    /// Rejects corrupt indexes and missing retained authority.
    pub fn closed_shared_due(
        db: &redb::Database,
        now: u64,
    ) -> Result<Vec<(AuthorityScope, PendingAuthority)>, SendAuthorityError> {
        let tx = db.begin_read().map_err(storage)?;
        let due = tx.open_table(SHARED_DUE).map_err(storage)?;
        let keys = due
            .range(..=(now, "\u{10ffff}"))
            .map_err(storage)?
            .take(128)
            .map(|entry| entry.map(|(key, _)| key.value().1.to_owned()).map_err(storage))
            .collect::<Result<Vec<_>, _>>()?;
        drop(due);
        drop(tx);
        let mut rows = Vec::new();
        for key in keys {
            let scope: AuthorityScope =
                ramflux_protocol::parse_i_json(key.as_bytes()).map_err(storage)?;
            let row = Self::pending(db, &scope)?.ok_or(SendAuthorityError::Invalid)?;
            if row.mutation.phase == AuthorityPhase::Stable
                && super::retirement::shared_closed(&row.record)
            {
                rows.push((scope, row));
            }
        }
        Ok(rows)
    }

    /// Active derived owner scopes that must close before their custodian changes.
    /// # Errors
    /// Oversized dependency transitions and corrupt scope keys refuse before publication.
    pub fn dependent_owner_scopes(
        db: &redb::Database,
        anchor: &str,
    ) -> Result<Vec<AuthorityScope>, SendAuthorityError> {
        let tx = db.begin_read().map_err(storage)?;
        let table = tx.open_table(PARENTS).map_err(storage)?;
        let rows = table
            .range((anchor, "")..=(anchor, "\u{10ffff}"))
            .map_err(storage)?
            .take(4097)
            .map(|entry| {
                entry.map_err(storage).and_then(|(key, _)| {
                    ramflux_protocol::parse_i_json(key.value().1.as_bytes()).map_err(storage)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > 4096 {
            return Err(SendAuthorityError::Capacity);
        }
        Ok(rows)
    }

    /// Rebind the retained owning operation at max(origin, notify)+1 after boot change.
    /// # Errors
    /// Inconsistent history never resets or substitutes the desired operation/hash.
    pub fn recover(
        db: &redb::Database,
        scope: &AuthorityScope,
        notify_boot: &str,
        observed: &AuthorityState,
    ) -> Result<AuthorityMutation, SendAuthorityError> {
        let key = scope.key()?;
        let tx = db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(ORIGIN).map_err(storage)?;
        let mut row = read(&table, &key)?.ok_or(SendAuthorityError::Closed)?;
        let current = &row.mutation;
        let recognized = (observed.is_empty()
            && current.phase == AuthorityPhase::Closing
            && current.expected_generation == 0
            && row.previous.is_none())
            || (observed.operation_id.as_ref() == Some(&current.operation_id)
                && observed.record_hash.as_ref() == Some(&current.desired_record_hash)
                && observed.generation <= current.generation)
            || row.previous.as_ref().is_some_and(|prior| observed.matches(prior));
        if !recognized {
            return Err(SendAuthorityError::Conflict);
        }
        let generation = next_generation(current.generation, observed.generation)?;
        if current.phase == AuthorityPhase::Stable {
            row.previous = Some(current.clone());
            row.mutation.operation_id =
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(storage)?);
        }
        row.mutation.generation = generation;
        row.mutation.expected_generation = observed.generation;
        notify_boot.clone_into(&mut row.mutation.notify_boot);
        row.mutation.phase = AuthorityPhase::Closing;
        row.mutation.result = None;
        validate_mutation(scope, &row.mutation, &row.desired, notify_boot)?;
        write(&tx, &mut table, &key, &row)?;
        let mutation = row.mutation.clone();
        drop(table);
        tx.commit().map_err(storage)?;
        Ok(mutation)
    }

    /// The caller must have verified the durable notify fence ACK for this exact tuple.
    /// Authoritative writes and committed phase occupy this SAME transaction.
    /// # Errors
    /// A stale completion cannot apply the authoritative delta or lower a generation.
    pub fn commit(
        db: &redb::Database,
        scope: &AuthorityScope,
        owning: &AuthorityMutation,
        apply: impl FnOnce(&redb::WriteTransaction) -> Result<(), crate::NodeCoreError>,
    ) -> Result<AuthorityMutation, crate::NodeCoreError> {
        let tx = db.begin_write().map_err(storage)?;
        let row = {
            let table = tx.open_table(ORIGIN).map_err(storage)?;
            read(&table, &scope.key()?)?.ok_or(SendAuthorityError::Closed)?
        };
        if !same_operation(&row.mutation, owning) {
            return Err(SendAuthorityError::Conflict.into());
        }
        if row.mutation.phase != AuthorityPhase::Closing {
            tx.abort().map_err(storage)?;
            return Ok(row.mutation);
        }
        apply(&tx)?;
        let mutation = Self::commit_in_transaction(&tx, scope, owning)?;
        tx.commit().map_err(storage)?;
        Ok(mutation)
    }

    /// Mark an exactly fenced mutation committed in the authoritative writer's transaction.
    /// # Errors
    /// Refuses stale operation ownership; aborting the transaction aborts both writes.
    pub fn commit_in_transaction(
        tx: &redb::WriteTransaction,
        scope: &AuthorityScope,
        owning: &AuthorityMutation,
    ) -> Result<AuthorityMutation, SendAuthorityError> {
        let key = scope.key()?;
        let mut table = tx.open_table(ORIGIN).map_err(storage)?;
        let mut row = read(&table, &key)?.ok_or(SendAuthorityError::Closed)?;
        if !same_operation(&row.mutation, owning) {
            return Err(SendAuthorityError::Conflict);
        }
        if row.mutation.phase != AuthorityPhase::Closing {
            return Ok(row.mutation);
        }
        row.mutation.phase = AuthorityPhase::Committed;
        write(tx, &mut table, &key, &row)?;
        Ok(row.mutation)
    }

    /// ACK completion changes phase without another generation increment.
    /// # Errors
    /// Refuses publication completion for any other operation or boot.
    pub fn published(
        db: &redb::Database,
        scope: &AuthorityScope,
        owning: &AuthorityMutation,
    ) -> Result<(), SendAuthorityError> {
        let key = scope.key()?;
        let tx = db.begin_write().map_err(storage)?;
        let mut table = tx.open_table(ORIGIN).map_err(storage)?;
        let mut row = read(&table, &key)?.ok_or(SendAuthorityError::Closed)?;
        if !same_operation(&row.mutation, owning)
            || !matches!(row.mutation.phase, AuthorityPhase::Committed | AuthorityPhase::Stable)
        {
            return Err(SendAuthorityError::Conflict);
        }
        row.mutation.phase = AuthorityPhase::Stable;
        row.mutation.result = Some(AuthorityMutationResult {
            generation: row.mutation.generation,
            outcome: AuthorityApplied::Applied,
        });
        write(&tx, &mut table, &key, &row)?;
        drop(table);
        tx.commit().map_err(storage)
    }

    /// Read desired record and coordination metadata in one durable transaction.
    /// `current_record` must come from this same authoritative database snapshot.
    /// # Errors
    /// Returns storage or invalid-history errors; absence is never positive authority.
    pub fn read(
        tx: &redb::ReadTransaction,
        scope: &AuthorityScope,
        boot: &str,
        purpose: AuthorityReadPurpose,
        operation: Option<&str>,
        current_record: Option<&AuthorityRecord>,
    ) -> Result<AuthorityReadResult, SendAuthorityError> {
        let key = scope.key()?;
        let table = tx.open_table(ORIGIN).map_err(storage)?;
        let Some(row) = read(&table, &key)? else {
            return Ok(AuthorityReadResult::Refused { reason: AuthorityReadRefusal::Missing });
        };
        if row.mutation.notify_boot != boot {
            return Ok(AuthorityReadResult::Refused {
                reason: AuthorityReadRefusal::ResyncRequired,
            });
        }
        let allowed = match purpose {
            AuthorityReadPurpose::Current => {
                operation.is_none()
                    && row.mutation.phase == AuthorityPhase::Stable
                    && current_record.map(AuthorityRecord::record_hash).transpose()?.as_ref()
                        == Some(&row.mutation.desired_record_hash)
            }
            AuthorityReadPurpose::FenceCheck => {
                operation == Some(row.mutation.operation_id.as_str())
                    && row.mutation.phase == AuthorityPhase::Closing
            }
            AuthorityReadPurpose::PublishCheck => {
                operation == Some(row.mutation.operation_id.as_str())
                    && row.mutation.phase == AuthorityPhase::Committed
                    && current_record.map(AuthorityRecord::record_hash).transpose()?.as_ref()
                        == Some(&row.mutation.desired_record_hash)
            }
        };
        if !allowed {
            return Ok(AuthorityReadResult::Refused { reason: AuthorityReadRefusal::Closing });
        }
        Ok(AuthorityReadResult::Record {
            reservation_id: row.mutation.reservation_id,
            reservation_generation: row.mutation.reservation_generation,
            origin_incarnation: row.mutation.origin_incarnation,
            operation_id: row.mutation.operation_id,
            phase: row.mutation.phase,
            expected_generation: row.mutation.expected_generation,
            generation: row.mutation.generation,
            record_hash: row.mutation.desired_record_hash,
            record: Box::new(row.desired),
        })
    }
}

fn next_generation(origin: u64, notify: u64) -> Result<u64, SendAuthorityError> {
    origin
        .max(notify)
        .checked_add(1)
        .filter(|next| *next <= MAX_AUTHORITY_GENERATION)
        .ok_or(SendAuthorityError::Invalid)
}

fn read(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<OriginRow>, SendAuthorityError> {
    let Some(row) = table.get(key).map_err(storage)? else { return Ok(None) };
    if row.value().len() > 128 * 1024 {
        return Err(SendAuthorityError::Capacity);
    }
    ramflux_protocol::parse_i_json(row.value()).map(Some).map_err(storage)
}

fn write(
    tx: &redb::WriteTransaction,
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &str,
    row: &OriginRow,
) -> Result<(), SendAuthorityError> {
    if let Some(previous) = read(table, key)?
        && let Some(parent) = previous.parent_anchor.as_deref()
    {
        tx.open_table(PARENTS).map_err(storage)?.remove((parent, key)).map_err(storage)?;
    }
    if let Some(parent) = row.parent_anchor.as_deref() {
        tx.open_table(PARENTS).map_err(storage)?.insert((parent, key), 0).map_err(storage)?;
    }
    let bytes = ramflux_protocol::canonical_json_bytes(row).map_err(storage)?;
    if let Some(at) = row.shared_retire_after {
        tx.open_table(SHARED_DUE).map_err(storage)?.insert((at, key), 0).map_err(storage)?;
    }
    if bytes.len() > 128 * 1024 {
        return Err(SendAuthorityError::Capacity);
    }
    super::budget::charge(
        tx,
        &row.reservation.recipient_root,
        row.reservation.slot_id.as_deref(),
        false,
        &format!("scope:{key}"),
        (
            bytes.len() + 4 * key.len() + 16 + row.parent_anchor.as_ref().map_or(0, String::len),
            2 + u64::from(row.shared_retire_after.is_some())
                + u64::from(row.parent_anchor.is_some()),
        ),
    )?;
    super::budget::charge(
        tx,
        &row.reservation.recipient_root,
        row.reservation.slot_id.as_deref(),
        false,
        &format!("index:{key}"),
        (row.mutation.reservation_id.len() + key.len() + 1, 1),
    )?;
    let receipt = ramflux_protocol::canonical_json_bytes(&row.reservation).map_err(storage)?;
    super::budget::charge(
        tx,
        &row.reservation.recipient_root,
        row.reservation.slot_id.as_deref(),
        false,
        "receipt",
        (
            receipt.len()
                + row.reservation.recipient_root.len()
                + row.reservation.slot_id.as_ref().map_or(0, String::len),
            1,
        ),
    )?;
    table.insert(key, bytes.as_slice()).map_err(storage)?;
    Ok(())
}

fn receipt_key(root: &str, slot: Option<&str>) -> Result<String, SendAuthorityError> {
    String::from_utf8(ramflux_protocol::canonical_json_bytes(&(root, slot)).map_err(storage)?)
        .map_err(storage)
}
