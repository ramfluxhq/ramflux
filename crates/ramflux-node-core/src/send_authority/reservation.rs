// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One durable global recipient admission ledger, owned exclusively by notify.

use super::{
    SendAuthorityError, storage,
    wire::{required_nullable, validate_digest},
};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

/// A reserved node-system share, separate from the R recipient shares.
#[must_use]
pub fn system_root() -> String {
    ramflux_crypto::blake3_256_base64url("ramflux.notification.system_share.v1\0", b"")
}

/// Notify's local writer reuses the existing component identity after restart.
/// # Errors
/// Conflicting or retired components refuse until their fixed horizon retires.
pub(super) fn local_receipt(
    db: &redb::Database,
    identity: &str,
    root: &str,
    boot: &str,
    now: u64,
) -> Result<ReservationReply, SendAuthorityError> {
    if let Some(reply) = local_existing(db, identity, root)? {
        return if reply.phase == ReservationPhase::Active {
            Ok(reply)
        } else {
            Err(SendAuthorityError::Closed)
        };
    }
    acquire_local(db, identity, root, boot, now)
}

pub(super) fn local_existing(
    db: &redb::Database,
    identity: &str,
    root: &str,
) -> Result<Option<ReservationReply>, SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let key = reservation_key(identity, root, None)?;
    let table = tx.open_table(KEYS).map_err(storage)?;
    let id = table.get(key.as_str()).map_err(storage)?.map(|v| v.value().to_owned());
    let existing = id
        .as_deref()
        .map(|id| read(&tx.open_table(RECEIPTS).map_err(storage)?, id))
        .transpose()?
        .flatten();
    drop(table);
    drop(tx);
    Ok(existing.map(|row| row.reply))
}

fn acquire_local(
    db: &redb::Database,
    identity: &str,
    root: &str,
    boot: &str,
    now: u64,
) -> Result<ReservationReply, SendAuthorityError> {
    let operation = super::rpc::random_id().map_err(storage)?;
    let mut request = ReservationRequest {
        version: 1,
        request_id: operation.clone(),
        operation_id: operation,
        recipient_root: root.into(),
        slot_id: None,
        reservation_id: None,
        reservation_generation: None,
        origin_incarnation: boot.into(),
        action: ReservationAction::Acquire,
    };
    let reply = apply(db, identity, &request, now)?;
    if reply.phase != ReservationPhase::Reserved {
        return Err(SendAuthorityError::Capacity);
    }
    request.reservation_id = reply.reservation_id;
    request.reservation_generation = reply.reservation_generation;
    request.action = ReservationAction::Activate;
    let reply = apply(db, identity, &request, now)?;
    if reply.phase != ReservationPhase::Active {
        return Err(SendAuthorityError::Closed);
    }
    Ok(reply)
}

pub const UNUSED_RESERVATION_TTL_SECONDS: u64 = 30;
pub const RESERVATION_PATH: &str = "/internal/notify/send-authority/reservation/v1";
pub const RESERVATIONS_PATH: &str = "/internal/notify/send-authority/reservations/v1";
pub const DEFAULT_RECIPIENT_ROOT_BUDGET: u64 = 4096;
const ROOTS: TableDefinition<&str, u64> = TableDefinition::new("notify_authority_roots_v1");
const RECEIPTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("notify_authority_reservations_v1");
const KEYS: TableDefinition<&str, &str> =
    TableDefinition::new("notify_authority_reservation_keys_v1");
const DUE: TableDefinition<(u64, &str), u8> =
    TableDefinition::new("notify_authority_reservation_due_v1");
const CONFIG: TableDefinition<&str, u64> = TableDefinition::new("notify_authority_budget_v1");
const ROOT_OWNERS: TableDefinition<&str, &str> =
    TableDefinition::new("notify_authority_root_owners_v1");
const ORIGINS: TableDefinition<&str, (u64, u64)> =
    TableDefinition::new("notify_authority_origin_quotas_v1");
const ORIGIN_INDEX: TableDefinition<(&str, u64), &str> =
    TableDefinition::new("notify_authority_origin_index_v1");
const SHARED_ROUTERS: TableDefinition<&str, &str> =
    TableDefinition::new("notify_authority_shared_router_v1");
const SLOTS: TableDefinition<(&str, &str), &str> =
    TableDefinition::new("notify_authority_slot_components_v1");
const CALL_COUNTS: TableDefinition<&str, u64> =
    TableDefinition::new("notify_authority_call_counts_v1");
const CLEANUP_LIMIT: usize = 128;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationAction {
    Acquire,
    Activate,
    Retire,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationPhase {
    Reserved,
    Active,
    Retiring,
    Retired,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRequest {
    pub version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub recipient_root: String,
    #[serde(deserialize_with = "required_nullable")]
    pub slot_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub reservation_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub reservation_generation: Option<u64>,
    pub origin_incarnation: String,
    pub action: ReservationAction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationReply {
    pub version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub recipient_root: String,
    #[serde(deserialize_with = "required_nullable")]
    pub slot_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub reservation_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub reservation_generation: Option<u64>,
    pub origin_incarnation: String,
    pub phase: ReservationPhase,
    #[serde(deserialize_with = "required_nullable")]
    pub expires_at: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub reason: Option<ReservationRefusal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationRefusal {
    Capacity,
    Busy,
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationListRequest {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    #[serde(deserialize_with = "required_nullable")]
    pub after_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationListReply {
    pub version: u32,
    pub request_id: String,
    pub notify_boot: String,
    pub rows: Vec<ReservationRow>,
    #[serde(deserialize_with = "required_nullable")]
    pub next_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationRow {
    pub operation_id: String,
    pub recipient_root: String,
    #[serde(deserialize_with = "required_nullable")]
    pub slot_id: Option<String>,
    pub reservation_id: String,
    pub reservation_generation: u64,
    pub origin_incarnation: String,
    pub phase: ReservationPhase,
    #[serde(deserialize_with = "required_nullable")]
    pub expires_at: Option<u64>,
}

/// Enumerate the authenticated origin's durable tuples after lost ACKs or restart.
/// # Errors
/// Refuses wrong boot/correlation and never exposes another origin's reservations.
pub fn list(
    db: &redb::Database,
    identity: &str,
    notify_boot: &str,
    request: &ReservationListRequest,
) -> Result<ReservationListReply, SendAuthorityError> {
    validate_digest(&request.request_id)?;
    validate_digest(&request.notify_boot)?;
    if request.version != 1 || request.notify_boot != notify_boot {
        return Err(SendAuthorityError::Invalid);
    }
    let tx = db.begin_read().map_err(storage)?;
    if tx.open_table(ORIGINS).map_err(storage)?.get(identity).map_err(storage)?.is_none() {
        return Err(SendAuthorityError::Closed);
    }
    let start =
        request.after_generation.unwrap_or(0).checked_add(1).ok_or(SendAuthorityError::Invalid)?;
    let index = tx.open_table(ORIGIN_INDEX).map_err(storage)?;
    let receipts = tx.open_table(RECEIPTS).map_err(storage)?;
    let mut rows = Vec::new();
    let mut has_next = false;
    for item in index
        .range((identity, start)..=(identity, super::MAX_AUTHORITY_GENERATION))
        .map_err(storage)?
        .take(5)
    {
        let (_, id) = item.map_err(storage)?;
        if rows.len() == 4 {
            has_next = true;
            break;
        }
        let row = read(&receipts, id.value())?.ok_or(SendAuthorityError::Invalid)?;
        if row.origin_identity != identity || row.reply.phase == ReservationPhase::Refused {
            return Err(SendAuthorityError::Invalid);
        }
        rows.push(ReservationRow {
            operation_id: row.reply.operation_id,
            recipient_root: row.reply.recipient_root,
            slot_id: row.reply.slot_id,
            reservation_id: row.reply.reservation_id.ok_or(SendAuthorityError::Invalid)?,
            reservation_generation: row
                .reply
                .reservation_generation
                .ok_or(SendAuthorityError::Invalid)?,
            origin_incarnation: row.reply.origin_incarnation,
            phase: row.reply.phase,
            expires_at: row.reply.expires_at,
        });
    }
    let next_generation =
        if has_next { rows.last().map(|row| row.reservation_generation) } else { None };
    let reply = ReservationListReply {
        version: 1,
        request_id: request.request_id.clone(),
        notify_boot: notify_boot.to_owned(),
        rows,
        next_generation,
    };
    if ramflux_protocol::canonical_json_bytes(&reply).map_err(storage)?.len() > 8192 {
        return Err(SendAuthorityError::Capacity);
    }
    Ok(reply)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    reply: ReservationReply,
    origin_identity: String,
    acquired_at: u64,
    origin_retired: bool,
    notify_retired: bool,
    #[serde(deserialize_with = "required_nullable")]
    collect_after: Option<u64>,
}

/// Initialize without changing occupancy or resetting the global receipt high-water.
/// # Errors
/// Refuses invalid budgets and reductions below occupied roots.
pub fn initialize(
    db: &redb::Database,
    root_budget: u64,
    identities: &[String],
) -> Result<(), SendAuthorityError> {
    if root_budget == 0
        || root_budget
            .checked_add(1)
            .and_then(|r| r.checked_mul(32 * 1024 * 1024))
            .is_none_or(|n| n > super::MAX_AUTHORITY_GENERATION)
    {
        return Err(SendAuthorityError::Invalid);
    }
    let mut identities = identities.to_vec();
    identities.sort();
    identities.dedup();
    let count = u64::try_from(identities.len()).map_err(storage)?;
    if count == 0
        || count > root_budget
        || identities.iter().any(|id| id.is_empty() || id.len() > 512)
    {
        return Err(SendAuthorityError::Invalid);
    }
    let tx = db.begin_write().map_err(storage)?;
    {
        let mut origins = tx.open_table(ORIGINS).map_err(storage)?;
        let old = origins
            .iter()
            .map_err(storage)?
            .map(|entry| entry.map(|(k, v)| (k.value().to_owned(), v.value())).map_err(storage))
            .collect::<Result<Vec<_>, _>>()?;
        for (identity, (_, occupied)) in old {
            if !identities.contains(&identity) && occupied != 0 {
                return Err(SendAuthorityError::Capacity);
            }
            if !identities.contains(&identity) {
                origins.remove(identity.as_str()).map_err(storage)?;
                super::budget::uncharge(
                    &tx,
                    &system_root(),
                    None,
                    true,
                    &format!("origin:{identity}"),
                )?;
            }
        }
        for (index, identity) in identities.iter().enumerate() {
            let quota = root_budget / count
                + u64::from(u64::try_from(index).map_err(storage)? < root_budget % count);
            let occupied =
                origins.get(identity.as_str()).map_err(storage)?.map_or(0, |v| v.value().1);
            if occupied > quota {
                return Err(SendAuthorityError::Capacity);
            }
            origins.insert(identity.as_str(), (quota, occupied)).map_err(storage)?;
            super::budget::charge(
                &tx,
                &system_root(),
                None,
                true,
                &format!("origin:{identity}"),
                (identity.len() + 2048, 4),
            )?;
        }
        tx.open_table(ROOT_OWNERS).map_err(storage)?;
        tx.open_table(ORIGIN_INDEX).map_err(storage)?;
        tx.open_table(CALL_COUNTS).map_err(storage)?;
        tx.open_table(SLOTS).map_err(storage)?;
        tx.open_table(SHARED_ROUTERS).map_err(storage)?;
        let mut config = tx.open_table(CONFIG).map_err(storage)?;
        let roots = tx.open_table(ROOTS).map_err(storage)?;
        let system_count = u64::from(roots.get(system_root().as_str()).map_err(storage)?.is_some());
        if roots.len().map_err(storage)?.saturating_sub(system_count) > root_budget {
            return Err(SendAuthorityError::Capacity);
        }
        config.insert("root_budget", root_budget).map_err(storage)?;
        tx.open_table(RECEIPTS).map_err(storage)?;
        tx.open_table(KEYS).map_err(storage)?;
        tx.open_table(DUE).map_err(storage)?;
    }
    tx.commit().map_err(storage)
}

/// The authenticated identity is supplied by the mTLS adapter, never deserialized.
/// # Errors
/// Refuses invalid correlation, stale receipts, exhausted shares and storage errors.
pub fn apply(
    db: &redb::Database,
    identity: &str,
    request: &ReservationRequest,
    now: u64,
) -> Result<ReservationReply, SendAuthorityError> {
    validate_request(identity, request)?;
    let key = reservation_key(identity, &request.recipient_root, request.slot_id.as_deref())?;
    let tx = db.begin_write().map_err(storage)?;
    let mut receipts = tx.open_table(RECEIPTS).map_err(storage)?;
    let current_id = {
        let keys = tx.open_table(KEYS).map_err(storage)?;
        keys.get(key.as_str()).map_err(storage)?.map(|v| v.value().to_owned())
    };
    let existing = current_id.as_deref().map(|id| read(&receipts, id)).transpose()?.flatten();
    let mut row = if let Some(row) = existing {
        if row.origin_identity != identity
            || row.reply.operation_id != request.operation_id
            || row.reply.origin_incarnation != request.origin_incarnation
        {
            return Ok(refused(
                request,
                if request.action == ReservationAction::Acquire {
                    ReservationRefusal::Busy
                } else {
                    ReservationRefusal::Conflict
                },
            ));
        }
        row
    } else {
        match create_reservation(&tx, identity, request, now, &key)? {
            Ok(row) => row,
            Err(reason) => return Ok(refused(request, reason)),
        }
    };
    if request.action != ReservationAction::Acquire
        && (request.reservation_id != row.reply.reservation_id
            || request.reservation_generation != row.reply.reservation_generation)
    {
        return Ok(refused(request, ReservationRefusal::Conflict));
    }
    if !transition(&tx, &mut row, request.action, now)? {
        return Ok(refused(request, ReservationRefusal::Conflict));
    }
    row.reply.request_id.clone_from(&request.request_id);
    let reply = row.reply.clone();
    let bytes = ramflux_protocol::canonical_json_bytes(&row).map_err(storage)?;
    let unit_count = if row.reply.phase == ReservationPhase::Reserved { 4 } else { 3 }
        + u64::from(
            row.reply.slot_id.is_some()
                || crate::parse_mesh_spiffe_uri(identity)
                    .is_ok_and(|peer| peer.service_id == "ramflux-router"),
        );
    super::budget::charge(
        &tx,
        &row.reply.recipient_root,
        row.reply.slot_id.as_deref(),
        true,
        &format!(
            "reservation:{}",
            row.reply.reservation_id.as_deref().ok_or(SendAuthorityError::Invalid)?
        ),
        (bytes.len() + key.len() + identity.len() + 128, unit_count),
    )?;
    super::budget::charge(
        &tx,
        &row.reply.recipient_root,
        None,
        true,
        "root_admission",
        (row.reply.recipient_root.len() * 3 + 128, 3),
    )?;
    write(&mut receipts, &row)?;
    drop(receipts);
    tx.commit().map_err(storage)?;
    Ok(reply)
}

fn transition(
    tx: &redb::WriteTransaction,
    row: &mut Reservation,
    action: ReservationAction,
    now: u64,
) -> Result<bool, SendAuthorityError> {
    match action {
        ReservationAction::Acquire => {}
        ReservationAction::Activate => {
            if row.reply.phase == ReservationPhase::Reserved {
                let expiry = row.reply.expires_at.ok_or(SendAuthorityError::Invalid)?;
                if now >= expiry {
                    return Ok(false);
                }
                if let Some(id) = row.reply.reservation_id.as_deref() {
                    tx.open_table(DUE).map_err(storage)?.remove((expiry, id)).map_err(storage)?;
                }
                row.reply.phase = ReservationPhase::Active;
                row.reply.expires_at = None;
            } else if row.reply.phase != ReservationPhase::Active {
                return Ok(false);
            }
        }
        ReservationAction::Retire => {
            row.origin_retired = true;
            row.reply.phase = ReservationPhase::Retiring;
            if row.notify_retired
                && let Some(horizon) = row.collect_after
            {
                tx.open_table(DUE)
                    .map_err(storage)?
                    .insert(
                        (
                            horizon,
                            row.reply
                                .reservation_id
                                .as_deref()
                                .ok_or(SendAuthorityError::Invalid)?,
                        ),
                        0,
                    )
                    .map_err(storage)?;
            }
        }
    }
    Ok(true)
}

fn validate_request(
    identity: &str,
    request: &ReservationRequest,
) -> Result<(), SendAuthorityError> {
    validate_digest(&request.request_id)?;
    validate_digest(&request.operation_id)?;
    validate_digest(&request.recipient_root)?;
    validate_digest(&request.origin_incarnation)?;
    if let Some(id) = &request.reservation_id {
        validate_digest(id)?;
    }
    if request.reservation_id.is_some() != request.reservation_generation.is_some()
        || request.reservation_generation.is_some_and(|generation| {
            generation == 0 || generation > super::MAX_AUTHORITY_GENERATION
        })
        || (request.action == ReservationAction::Acquire && request.reservation_id.is_some())
    {
        return Err(SendAuthorityError::Invalid);
    }
    if request.version != 1 || identity.is_empty() || identity.len() > 512 {
        return Err(SendAuthorityError::Invalid);
    }
    if let Some(slot) = &request.slot_id {
        validate_digest(slot)?;
    }
    Ok(())
}

fn create_reservation(
    tx: &redb::WriteTransaction,
    identity: &str,
    request: &ReservationRequest,
    now: u64,
    key: &str,
) -> Result<Result<Reservation, ReservationRefusal>, SendAuthorityError> {
    if request.action != ReservationAction::Acquire
        || request.reservation_id.is_some()
        || request.reservation_generation.is_some()
    {
        return Ok(Err(ReservationRefusal::Conflict));
    }
    if let Err(reason) = reserve_capacity(tx, identity, request)? {
        return Ok(Err(reason));
    }
    let mut config = tx.open_table(CONFIG).map_err(storage)?;
    let high = config.get("generation").map_err(storage)?.map_or(0, |v| v.value());
    let generation = high
        .checked_add(1)
        .filter(|n| *n <= super::MAX_AUTHORITY_GENERATION)
        .ok_or(SendAuthorityError::Invalid)?;
    config.insert("generation", generation).map_err(storage)?;
    let id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32().map_err(storage)?);
    let expires_at =
        now.checked_add(UNUSED_RESERVATION_TTL_SECONDS).ok_or(SendAuthorityError::Invalid)?;
    let reply = ReservationReply {
        version: 1,
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        recipient_root: request.recipient_root.clone(),
        slot_id: request.slot_id.clone(),
        reservation_id: Some(id.clone()),
        reservation_generation: Some(generation),
        origin_incarnation: request.origin_incarnation.clone(),
        phase: ReservationPhase::Reserved,
        expires_at: Some(expires_at),
        reason: None,
    };
    tx.open_table(KEYS).map_err(storage)?.insert(key, id.as_str()).map_err(storage)?;
    tx.open_table(ORIGIN_INDEX)
        .map_err(storage)?
        .insert((identity, generation), id.as_str())
        .map_err(storage)?;
    tx.open_table(DUE).map_err(storage)?.insert((expires_at, id.as_str()), 0).map_err(storage)?;
    Ok(Ok(Reservation {
        reply,
        origin_identity: identity.to_owned(),
        acquired_at: now,
        origin_retired: false,
        notify_retired: false,
        collect_after: None,
    }))
}

fn reserve_capacity(
    tx: &redb::WriteTransaction,
    identity: &str,
    request: &ReservationRequest,
) -> Result<Result<(), ReservationRefusal>, SendAuthorityError> {
    if request.slot_id.is_none()
        && crate::parse_mesh_spiffe_uri(identity)
            .is_ok_and(|peer| peer.service_id == "ramflux-router")
    {
        let mut routers = tx.open_table(SHARED_ROUTERS).map_err(storage)?;
        if routers.get(request.recipient_root.as_str()).map_err(storage)?.is_some() {
            return Ok(Err(ReservationRefusal::Busy));
        }
        routers.insert(request.recipient_root.as_str(), identity).map_err(storage)?;
    }
    let mut roots = tx.open_table(ROOTS).map_err(storage)?;
    let count = roots.get(request.recipient_root.as_str()).map_err(storage)?.map(|v| v.value());
    let config = tx.open_table(CONFIG).map_err(storage)?;
    let budget = config
        .get("root_budget")
        .map_err(storage)?
        .map(|v| v.value())
        .ok_or(SendAuthorityError::Closed)?;
    let system = request.recipient_root == system_root();
    let system_count = u64::from(roots.get(system_root().as_str()).map_err(storage)?.is_some());
    if !system
        && count.is_none()
        && roots.len().map_err(storage)?.saturating_sub(system_count) >= budget
    {
        return Ok(Err(ReservationRefusal::Capacity));
    }
    let mut origins = tx.open_table(ORIGINS).map_err(storage)?;
    let (quota, occupied) = origins
        .get(identity)
        .map_err(storage)?
        .map(|v| v.value())
        .ok_or(SendAuthorityError::Closed)?;
    if count.is_none() {
        if !system && occupied >= quota {
            return Ok(Err(ReservationRefusal::Capacity));
        }
        if !system {
            origins.insert(identity, (quota, occupied + 1)).map_err(storage)?;
        }
        tx.open_table(ROOT_OWNERS)
            .map_err(storage)?
            .insert(request.recipient_root.as_str(), identity)
            .map_err(storage)?;
    }
    if let Some(slot) = &request.slot_id {
        let mut slots = tx.open_table(SLOTS).map_err(storage)?;
        if slots.get((request.recipient_root.as_str(), slot.as_str())).map_err(storage)?.is_some() {
            return Ok(Err(ReservationRefusal::Busy));
        }
        let mut calls = tx.open_table(CALL_COUNTS).map_err(storage)?;
        let count =
            calls.get(request.recipient_root.as_str()).map_err(storage)?.map_or(0, |v| v.value());
        if count >= 64 {
            return Ok(Err(ReservationRefusal::Capacity));
        }
        calls.insert(request.recipient_root.as_str(), count + 1).map_err(storage)?;
        slots
            .insert((request.recipient_root.as_str(), slot.as_str()), identity)
            .map_err(storage)?;
    }
    roots.insert(request.recipient_root.as_str(), count.unwrap_or(0) + 1).map_err(storage)?;
    Ok(Ok(()))
}

/// Confirm notify's indexed cleanup and arm release after every denial has expired.
/// # Errors
/// Refuses stale tuples; unavailable origin acknowledgements retain their charges.
pub fn notify_retired(
    tx: &redb::WriteTransaction,
    reservation_id: &str,
    generation: u64,
    collect_after: u64,
) -> Result<(), SendAuthorityError> {
    let mut receipts = tx.open_table(RECEIPTS).map_err(storage)?;
    let mut row = read(&receipts, reservation_id)?.ok_or(SendAuthorityError::Closed)?;
    if row.reply.reservation_generation != Some(generation) {
        return Err(SendAuthorityError::Conflict);
    }
    row.notify_retired = true;
    let horizon = *row.collect_after.get_or_insert(collect_after);
    if row.origin_retired {
        tx.open_table(DUE)
            .map_err(storage)?
            .insert((horizon, reservation_id), 0)
            .map_err(storage)?;
    }
    write(&mut receipts, &row)
}

/// Bounded due-index cleanup releases only expired-unused or fully retired reservations.
/// # Errors
/// Returns storage/history errors without guessing uncertain components empty.
pub fn prune(db: &redb::Database, now: u64) -> Result<usize, SendAuthorityError> {
    let tx = db.begin_write().map_err(storage)?;
    let mut due = tx.open_table(DUE).map_err(storage)?;
    let candidates = due
        .iter()
        .map_err(storage)?
        .take(CLEANUP_LIMIT)
        .map(|entry| entry.map(|(k, _)| (k.value().0, k.value().1.to_owned())).map_err(storage))
        .collect::<Result<Vec<_>, _>>()?;
    let mut removed = 0;
    for (at, id) in candidates {
        if at > now {
            break;
        }
        let mut receipts = tx.open_table(RECEIPTS).map_err(storage)?;
        let row = read(&receipts, &id)?.ok_or(SendAuthorityError::Invalid)?;
        if (row.reply.phase == ReservationPhase::Reserved && row.reply.expires_at == Some(at))
            || (row.origin_retired && row.notify_retired && row.collect_after == Some(at))
        {
            let key = reservation_key(
                &row.origin_identity,
                &row.reply.recipient_root,
                row.reply.slot_id.as_deref(),
            )?;
            tx.open_table(KEYS).map_err(storage)?.remove(key.as_str()).map_err(storage)?;
            receipts.remove(id.as_str()).map_err(storage)?;
            super::budget::uncharge(
                &tx,
                &row.reply.recipient_root,
                row.reply.slot_id.as_deref(),
                true,
                &format!("reservation:{id}"),
            )?;
            tx.open_table(ORIGIN_INDEX)
                .map_err(storage)?
                .remove((
                    row.origin_identity.as_str(),
                    row.reply.reservation_generation.ok_or(SendAuthorityError::Invalid)?,
                ))
                .map_err(storage)?;
            release_slot(&tx, &row)?;
            if row.reply.slot_id.is_none()
                && crate::parse_mesh_spiffe_uri(&row.origin_identity)
                    .is_ok_and(|peer| peer.service_id == "ramflux-router")
            {
                tx.open_table(SHARED_ROUTERS)
                    .map_err(storage)?
                    .remove(row.reply.recipient_root.as_str())
                    .map_err(storage)?;
            }
            release_root(&tx, &row.reply.recipient_root)?;
            removed += 1;
        }
        due.remove((at, id.as_str())).map_err(storage)?;
    }
    drop(due);
    tx.commit().map_err(storage)?;
    Ok(removed)
}

fn release_slot(tx: &redb::WriteTransaction, row: &Reservation) -> Result<(), SendAuthorityError> {
    if let Some(slot) = &row.reply.slot_id {
        let mut slots = tx.open_table(SLOTS).map_err(storage)?;
        if slots
            .get((row.reply.recipient_root.as_str(), slot.as_str()))
            .map_err(storage)?
            .is_none_or(|value| value.value() != row.origin_identity)
        {
            return Err(SendAuthorityError::Invalid);
        }
        slots.remove((row.reply.recipient_root.as_str(), slot.as_str())).map_err(storage)?;
        let mut calls = tx.open_table(CALL_COUNTS).map_err(storage)?;
        let count = calls
            .get(row.reply.recipient_root.as_str())
            .map_err(storage)?
            .map(|v| v.value())
            .ok_or(SendAuthorityError::Invalid)?;
        if count == 1 {
            calls.remove(row.reply.recipient_root.as_str()).map_err(storage)?;
        } else {
            calls
                .insert(
                    row.reply.recipient_root.as_str(),
                    count.checked_sub(1).ok_or(SendAuthorityError::Invalid)?,
                )
                .map_err(storage)?;
        }
    }
    Ok(())
}

fn release_root(tx: &redb::WriteTransaction, root: &str) -> Result<(), SendAuthorityError> {
    let mut roots = tx.open_table(ROOTS).map_err(storage)?;
    let count =
        roots.get(root).map_err(storage)?.map(|v| v.value()).ok_or(SendAuthorityError::Invalid)?;
    if count == 1 {
        roots.remove(root).map_err(storage)?;
        super::budget::uncharge(tx, root, None, true, "root_admission")?;
        let mut owners = tx.open_table(ROOT_OWNERS).map_err(storage)?;
        let first = owners
            .get(root)
            .map_err(storage)?
            .map(|v| v.value().to_owned())
            .ok_or(SendAuthorityError::Invalid)?;
        let mut origins = tx.open_table(ORIGINS).map_err(storage)?;
        let (quota, occupied) = origins
            .get(first.as_str())
            .map_err(storage)?
            .map(|v| v.value())
            .ok_or(SendAuthorityError::Invalid)?;
        if root != system_root() {
            origins
                .insert(
                    first.as_str(),
                    (quota, occupied.checked_sub(1).ok_or(SendAuthorityError::Invalid)?),
                )
                .map_err(storage)?;
        }
        owners.remove(root).map_err(storage)?;
    } else {
        roots
            .insert(root, count.checked_sub(1).ok_or(SendAuthorityError::Invalid)?)
            .map_err(storage)?;
    }
    Ok(())
}

fn reservation_key(
    identity: &str,
    root: &str,
    slot: Option<&str>,
) -> Result<String, SendAuthorityError> {
    String::from_utf8(
        ramflux_protocol::canonical_json_bytes(&(identity, root, slot)).map_err(storage)?,
    )
    .map_err(storage)
}

pub(super) fn require_origin(
    db: &redb::Database,
    identity: &str,
) -> Result<(), SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    if tx.open_table(ORIGINS).map_err(storage)?.get(identity).map_err(storage)?.is_none() {
        return Err(SendAuthorityError::Closed);
    }
    Ok(())
}

pub(super) fn require_owner(
    db: &redb::Database,
    identity: &str,
    id: &str,
    generation: u64,
) -> Result<(), SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(RECEIPTS).map_err(storage)?;
    let row = read(&table, id)?.ok_or(SendAuthorityError::Closed)?;
    if row.origin_identity != identity
        || row.reply.reservation_generation != Some(generation)
        || row.reply.phase != ReservationPhase::Active
    {
        return Err(SendAuthorityError::Conflict);
    }
    Ok(())
}

/// Fixed orphan-denial horizon, preserved across activation, retries and restarts.
/// # Errors
/// Missing receipts and counter overflow refuse retirement.
pub fn orphan_horizon(db: &redb::Database, id: &str) -> Result<u64, SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(RECEIPTS).map_err(storage)?;
    let row = read(&table, id)?.ok_or(SendAuthorityError::Closed)?;
    row.acquired_at.checked_add(604_800 + 120).ok_or(SendAuthorityError::Invalid)
}

pub(super) fn owner(db: &redb::Database, id: &str) -> Result<String, SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(RECEIPTS).map_err(storage)?;
    Ok(read(&table, id)?.ok_or(SendAuthorityError::Closed)?.origin_identity)
}

pub(super) fn root(db: &redb::Database, id: &str) -> Result<String, SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(RECEIPTS).map_err(storage)?;
    Ok(read(&table, id)?.ok_or(SendAuthorityError::Closed)?.reply.recipient_root)
}

/// Verify the active coordinator receipt against the exact origin operation and resource.
/// # Errors
/// A foreign, expired, retired, wrong-root or substituted slot never authorizes a fence.
pub fn verify_active(
    db: &redb::Database,
    identity: &str,
    mutation: &super::AuthorityMutation,
    record: &super::AuthorityRecord,
) -> Result<(), SendAuthorityError> {
    let tx = db.begin_read().map_err(storage)?;
    let receipts = tx.open_table(RECEIPTS).map_err(storage)?;
    let row = read(&receipts, &mutation.reservation_id)?.ok_or(SendAuthorityError::Closed)?;
    if row.reply.phase != ReservationPhase::Active
        || row.origin_identity != identity
        || row.reply.origin_incarnation != mutation.origin_incarnation
        || row.reply.reservation_generation != Some(mutation.reservation_generation)
    {
        return Err(SendAuthorityError::Conflict);
    }
    match record {
        super::AuthorityRecord::Call { recipient_root, start_digest, .. } => {
            let body =
                serde_json::json!({"recipient_root":recipient_root,"start_digest":start_digest});
            let slot = ramflux_crypto::blake3_256_base64url(
                "ramflux.notification.call_slot.v1\0",
                &ramflux_protocol::canonical_json_bytes(&body).map_err(storage)?,
            );
            if row.reply.recipient_root != *recipient_root
                || row.reply.slot_id.as_ref() != Some(&slot)
            {
                return Err(SendAuthorityError::Conflict);
            }
        }
        super::AuthorityRecord::Owner { owner: Some(owner), .. } => {
            if row.reply.recipient_root != owner.account_anchor || row.reply.slot_id.is_some() {
                return Err(SendAuthorityError::Conflict);
            }
        }
        super::AuthorityRecord::Owner {
            owner: None, revoked: true, target_delivery_id, ..
        } => {
            let root = ramflux_protocol::parse_qualified_device_id(target_delivery_id)
                .map_err(storage)?
                .map(|(root, _)| root)
                .ok_or(SendAuthorityError::Invalid)?;
            if row.reply.slot_id.is_some() || row.reply.recipient_root != root {
                return Err(SendAuthorityError::Conflict);
            }
        }
        _ => return Err(SendAuthorityError::Invalid),
    }
    Ok(())
}

fn read(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    id: &str,
) -> Result<Option<Reservation>, SendAuthorityError> {
    let Some(row) = table.get(id).map_err(storage)? else { return Ok(None) };
    if row.value().len() > 8192 {
        return Err(SendAuthorityError::Invalid);
    }
    ramflux_protocol::parse_i_json(row.value()).map(Some).map_err(storage)
}

fn write(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    row: &Reservation,
) -> Result<(), SendAuthorityError> {
    let bytes = ramflux_protocol::canonical_json_bytes(row).map_err(storage)?;
    if bytes.len() > 8192 {
        return Err(SendAuthorityError::Capacity);
    }
    table
        .insert(
            row.reply.reservation_id.as_deref().ok_or(SendAuthorityError::Invalid)?,
            bytes.as_slice(),
        )
        .map_err(storage)?;
    Ok(())
}

fn refused(request: &ReservationRequest, reason: ReservationRefusal) -> ReservationReply {
    ReservationReply {
        version: 1,
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        recipient_root: request.recipient_root.clone(),
        slot_id: request.slot_id.clone(),
        reservation_id: request.reservation_id.clone(),
        reservation_generation: request.reservation_generation,
        origin_incarnation: request.origin_incarnation.clone(),
        phase: ReservationPhase::Refused,
        expires_at: None,
        reason: Some(reason),
    }
}
