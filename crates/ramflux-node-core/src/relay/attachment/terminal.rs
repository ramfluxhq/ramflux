// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Permanent terminal-object evidence and its admission-time budget (ATTACH-LARGE-01 §4).
//! A slot is charged when an object is admitted and is never refunded; the terminal
//! transition writes its row into the slot already charged, so it needs no capacity.
use super::{
    AttachmentLedgerError, AttachmentPolicy, AttachmentQuota, ReadableDatabase, ReadableTable,
    TOTALS, TableDefinition, decode, encode, store,
};

pub(super) const TERMINAL: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("native_attachment_terminal_objects_v1");
const SLOTS_KEY: &str = "terminal_slots_global";
const OWNERS_KEY: &str = "terminal_owners";
/// Immutable compiled hard maxima. Admission settings may be lowered below usage;
/// these bounds never move.
pub(super) const HARD_OWNERS: u64 = 1 << 20;
pub(super) const HARD_SLOTS_PER_OWNER: u64 = 1 << 22;
pub(super) const HARD_SLOTS_GLOBAL: u64 = 1 << 26;

type Config<'a> = redb::Table<'a, &'static str, &'static [u8]>;

fn counter(
    config: &impl ReadableTable<&'static str, &'static [u8]>,
    name: &str,
) -> Result<Option<u64>, AttachmentLedgerError> {
    config.get(name).map_err(store)?.map(|v| decode::<u64>(v.value())).transpose()
}

fn set(config: &mut Config<'_>, name: &str, value: u64) -> Result<(), AttachmentLedgerError> {
    config.insert(name, encode(&value)?.as_slice()).map_err(store)?;
    Ok(())
}

/// Complete bounded scan of owner rows: `(owner count, sum of terminal slots)`.
/// Fails closed when a row, the sum or the row count passes a hard maximum.
fn scan(
    totals: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<(u64, u64), AttachmentLedgerError> {
    let (mut owners, mut sum) = (0_u64, 0_u64);
    for entry in totals.iter().map_err(store)? {
        owners += 1;
        if owners > HARD_OWNERS {
            return Err(AttachmentLedgerError::State);
        }
        let (_, value) = entry.map_err(store)?;
        let quota: AttachmentQuota = decode(value.value())?;
        if quota.terminal_slots > HARD_SLOTS_PER_OWNER {
            return Err(AttachmentLedgerError::State);
        }
        sum += quota.terminal_slots;
        if sum > HARD_SLOTS_GLOBAL {
            return Err(AttachmentLedgerError::State);
        }
    }
    Ok((owners, sum))
}

/// Creates the table and seeds the counters once for a ledger that predates them.
/// A ledger that already holds counters is never repaired here.
pub(super) fn install(tx: &redb::WriteTransaction) -> Result<(), AttachmentLedgerError> {
    let _ = tx.open_table(TERMINAL).map_err(store)?;
    let totals = tx.open_table(TOTALS).map_err(store)?;
    let mut config = tx.open_table(super::grants::CONFIG).map_err(store)?;
    if counter(&config, SLOTS_KEY)?.is_none() && counter(&config, OWNERS_KEY)?.is_none() {
        let (owners, sum) = scan(&totals)?;
        set(&mut config, OWNERS_KEY, owners)?;
        set(&mut config, SLOTS_KEY, sum)?;
    }
    Ok(())
}

fn counters(config: &Config<'_>) -> Result<(u64, u64), AttachmentLedgerError> {
    match (counter(config, OWNERS_KEY)?, counter(config, SLOTS_KEY)?) {
        (Some(owners), Some(slots)) => Ok((owners, slots)),
        _ => Err(AttachmentLedgerError::State),
    }
}

/// Admission of a new reservation: owner budget (new owners only), then the per-owner
/// and global slot budgets. Mutates only `total` and the two counters, and only on success.
pub(super) fn admit(
    tx: &redb::WriteTransaction,
    policy: &AttachmentPolicy,
    new_owner: bool,
    total: &mut AttachmentQuota,
) -> Result<(), AttachmentLedgerError> {
    let mut config = tx.open_table(super::grants::CONFIG).map_err(store)?;
    let (owners, slots) = counters(&config)?;
    if new_owner && owners >= policy.max_terminal_owners {
        return Err(AttachmentLedgerError::TerminalOwnerCapacity);
    }
    if total.terminal_slots >= policy.max_terminal_objects_per_owner
        || slots >= policy.max_terminal_objects_global
    {
        return Err(AttachmentLedgerError::TerminalEvidenceCapacity);
    }
    total.terminal_slots += 1;
    set(&mut config, SLOTS_KEY, slots + 1)?;
    if new_owner {
        set(&mut config, OWNERS_KEY, owners + 1)?;
    }
    Ok(())
}

/// Whether the object id has reached a terminal state, for any owner.
pub(super) fn is_terminal(
    tx: &redb::WriteTransaction,
    object_id: &[u8; 32],
) -> Result<bool, AttachmentLedgerError> {
    Ok(tx.open_table(TERMINAL).map_err(store)?.get(object_id.as_slice()).map_err(store)?.is_some())
}

/// Frozen 40-byte value: `BLAKE3(owner anchor) || terminal_at` (storage index only).
pub(super) fn record(
    tx: &redb::WriteTransaction,
    owner: &str,
    object_id: &[u8; 32],
    terminal_at: u64,
) -> Result<(), AttachmentLedgerError> {
    let mut value = blake3::hash(owner.as_bytes()).as_bytes().to_vec();
    value.extend_from_slice(&terminal_at.to_be_bytes());
    tx.open_table(TERMINAL)
        .map_err(store)?
        .insert(object_id.as_slice(), value.as_slice())
        .map_err(store)?;
    Ok(())
}

/// Counter pair read at the start of a maintenance turn.
pub(super) fn snapshot(tx: &redb::WriteTransaction) -> Result<(u64, u64), AttachmentLedgerError> {
    counters(&tx.open_table(super::grants::CONFIG).map_err(store)?)
}

/// Identity prune never deletes owner rows or touches the global counter.
pub(super) fn verify_after_prune(
    tx: &redb::WriteTransaction,
    before: (u64, u64),
) -> Result<(), AttachmentLedgerError> {
    let (owners, slots) = snapshot(tx)?;
    let rows =
        redb::ReadableTableMetadata::len(&tx.open_table(TOTALS).map_err(store)?).map_err(store)?;
    if (owners, slots) != before || rows != owners {
        return Err(AttachmentLedgerError::State);
    }
    Ok(())
}

/// Open-time recount against the compiled hard maxima, never the current settings.
pub(super) fn recount(db: &redb::Database) -> Result<(), AttachmentLedgerError> {
    let tx = db.begin_read().map_err(store)?;
    let totals = tx.open_table(TOTALS).map_err(store)?;
    let config = tx.open_table(super::grants::CONFIG).map_err(store)?;
    let (owners, slots) = scan(&totals)?;
    let stored = (counter(&config, OWNERS_KEY)?, counter(&config, SLOTS_KEY)?);
    if stored != (Some(owners), Some(slots)) {
        return Err(AttachmentLedgerError::State);
    }
    Ok(())
}
