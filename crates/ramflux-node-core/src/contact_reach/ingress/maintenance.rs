// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded expiry-index maintenance; payload removal and counter release share the writer.
use super::{
    COUNTERS, Counter, DEDUP, Dedup, ReachClass, Result, encoded, remove_payload, row, storage,
};
use redb::{ReadableTable, TableDefinition};
const DEDUP_EXPIRY: TableDefinition<&str, &str> =
    TableDefinition::new("contact_reach_dedup_expiry_v1");
const COUNTER_EXPIRY: TableDefinition<&str, &str> =
    TableDefinition::new("contact_reach_counter_expiry_v1");
const BATCH: usize = 128;
fn index_key(until: u64, key: &str) -> String {
    format!("{until:020}/{key}")
}
pub(super) fn metadata(class: ReachClass) -> Vec<(&'static str, (u64, u64))> {
    if class == ReachClass::Unsolicited {
        vec![("metadata-unsolicited", (65_536, 32 * 1024 * 1024))]
    } else {
        let mut compartments = vec![("metadata-accepted", (65_536, 32 * 1024 * 1024))];
        if class == ReachClass::Replied {
            compartments.push(("metadata-replied", (32_768, 16 * 1024 * 1024)));
        }
        compartments
    }
}
pub(super) fn remember_dedup(tx: &redb::WriteTransaction, key: &str, until: u64) -> Result<()> {
    tx.open_table(DEDUP_EXPIRY)
        .map_err(storage)?
        .insert(index_key(until, key).as_str(), key)
        .map_err(storage)?;
    Ok(())
}
pub(super) fn remember_counter(tx: &redb::WriteTransaction, key: &str, until: u64) -> Result<()> {
    tx.open_table(COUNTER_EXPIRY)
        .map_err(storage)?
        .insert(index_key(until, key).as_str(), key)
        .map_err(storage)?;
    Ok(())
}
fn expired(
    tx: &redb::WriteTransaction,
    definition: TableDefinition<&str, &str>,
    now: u64,
) -> Result<Vec<(String, String)>> {
    let upper = format!("{now:020}0");
    tx.open_table(definition)
        .map_err(storage)?
        .range(..upper.as_str())
        .map_err(storage)?
        .take(BATCH)
        .map(|row| {
            let (index, key) = row.map_err(storage)?;
            Ok((index.value().into(), key.value().into()))
        })
        .collect()
}
pub(super) fn clean(tx: &redb::WriteTransaction, now: u64) -> Result<()> {
    for (index, key) in expired(tx, DEDUP_EXPIRY, now)? {
        let mut table = tx.open_table(DEDUP).map_err(storage)?;
        let value = table
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<Dedup>(v.value()))
            .transpose()?;
        if let Some(value) = value
            && value.until <= now
        {
            table.remove(key.as_str()).map_err(storage)?;
            drop(table);
            remove_payload(tx, value.seq)?;
            let mut counters = tx.open_table(COUNTERS).map_err(storage)?;
            let bytes = u64::try_from(key.len() + encoded(&value)?.len()).map_err(storage)?;
            for (metadata, _) in metadata(value.class) {
                let mut count: Counter = counters
                    .get(metadata)
                    .map_err(storage)?
                    .map(|v| row(v.value()))
                    .transpose()?
                    .ok_or_else(|| storage("missing dedup metadata charge"))?;
                count.entries = count
                    .entries
                    .checked_sub(1)
                    .ok_or_else(|| storage("dedup metadata entry underflow"))?;
                count.bytes = count
                    .bytes
                    .checked_sub(bytes)
                    .ok_or_else(|| storage("dedup metadata byte underflow"))?;
                counters.insert(metadata, encoded(&count)?.as_slice()).map_err(storage)?;
            }
        }
        tx.open_table(DEDUP_EXPIRY).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
    }
    for (index, key) in expired(tx, COUNTER_EXPIRY, now)? {
        let mut table = tx.open_table(COUNTERS).map_err(storage)?;
        let until = table
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<Counter>(v.value()))
            .transpose()?
            .map(|v| v.until);
        if until.is_some_and(|until| until <= now) {
            table.remove(key.as_str()).map_err(storage)?;
        }
        drop(table);
        tx.open_table(COUNTER_EXPIRY).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
