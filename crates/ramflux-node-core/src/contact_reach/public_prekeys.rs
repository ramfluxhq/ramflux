// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit public allocation quotas use server-qualified targets; aliases cannot reset them.
use super::{
    Result, refuse, storage,
    store::{encoded, row},
};
use ramflux_protocol::contact_reach::Reason;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
const ROWS: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_public_prekey_rates_v1");
const EXPIRY: TableDefinition<&str, &str> = TableDefinition::new("contact_public_prekey_expiry_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("contact_public_prekey_budget_v1");
const MAX_ROWS: u64 = 65_536;
const MAX_BYTES: u64 = 32 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Events {
    times: Vec<u64>,
    until: u64,
}
fn expiry(until: u64, key: &str) -> String {
    format!("{until:020}/{key}")
}
fn size(key: &str, value: &[u8]) -> Result<u64> {
    u64::try_from(key.len() * 2 + 21 + value.len()).map_err(storage)
}
fn clean(tx: &redb::WriteTransaction, now: u64) -> Result<()> {
    let upper = format!("{now:020}0");
    let expired = tx
        .open_table(EXPIRY)
        .map_err(storage)?
        .range(..upper.as_str())
        .map_err(storage)?
        .take(128)
        .map(|row| {
            let (index, key) = row.map_err(storage)?;
            Ok((index.value().to_owned(), key.value().to_owned()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut rows = tx.open_table(ROWS).map_err(storage)?;
    let mut meta = tx.open_table(META).map_err(storage)?;
    let mut total = meta.get("bytes").map_err(storage)?.map_or(0, |v| v.value());
    for (index, key) in expired {
        let value = rows.get(key.as_str()).map_err(storage)?.map(|v| v.value().to_vec());
        if let Some(value) = value {
            let events: Events = row(&value)?;
            if events.until <= now {
                rows.remove(key.as_str()).map_err(storage)?;
                total = total
                    .checked_sub(size(&key, &value)?)
                    .ok_or_else(|| storage("prekey quota underflow"))?;
            }
        }
        tx.open_table(EXPIRY).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
    }
    meta.insert("bytes", total).map_err(storage)?;
    Ok(())
}
fn charge(tx: &redb::WriteTransaction, key: &str, now: u64, window: u64, cap: usize) -> Result<()> {
    let mut rows = tx.open_table(ROWS).map_err(storage)?;
    let old = rows.get(key).map_err(storage)?.map(|v| v.value().to_vec());
    let mut events: Events = old
        .as_ref()
        .map(|v| row(v))
        .transpose()?
        .unwrap_or(Events { times: Vec::new(), until: now });
    if events.times.len() > 20 || events.times.iter().any(|time| *time > now) {
        return Err(refuse(Reason::ForeignRateLimited));
    }
    events.times.retain(|time| now < time.saturating_add(window));
    if events.times.len() >= cap {
        return Err(refuse(Reason::ForeignRateLimited));
    }
    if old.is_none() && rows.len().map_err(storage)? >= MAX_ROWS {
        return Err(refuse(Reason::ForeignCapacity));
    }
    let previous_until = events.until;
    events.times.push(now);
    events.until = now
        .checked_add(window.checked_mul(2).ok_or_else(|| refuse(Reason::ForeignCapacity))?)
        .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    let bytes = encoded(&events)?;
    let mut meta = tx.open_table(META).map_err(storage)?;
    let total = meta.get("bytes").map_err(storage)?.map_or(0, |v| v.value());
    let old_size = old.as_ref().map(|v| size(key, v)).transpose()?.unwrap_or(0);
    let total = total
        .checked_sub(old_size)
        .and_then(|n| n.checked_add(size(key, &bytes).ok()?))
        .filter(|n| *n <= MAX_BYTES)
        .ok_or_else(|| refuse(Reason::ForeignCapacity))?;
    rows.insert(key, bytes.as_slice()).map_err(storage)?;
    meta.insert("bytes", total).map_err(storage)?;
    let mut index = tx.open_table(EXPIRY).map_err(storage)?;
    index.remove(expiry(previous_until, key).as_str()).map_err(storage)?;
    index.insert(expiry(events.until, key).as_str(), key).map_err(storage)?;
    Ok(())
}
/// Caller has authenticated the peer, checked target eligibility/current native bundle and
/// acquired the same writer that will publish the snapshot. Ordinary snapshots never call this.
pub(super) fn reserve(
    tx: &redb::WriteTransaction,
    peer: &str,
    target: &str,
    now: u64,
) -> Result<()> {
    if peer.is_empty() || peer.len() > 253 || target.len() > 256 {
        return Err(refuse(Reason::ForeignInvalidFrame));
    }
    clean(tx, now)?;
    let peer_key = serde_json::to_string(&("peer-target", peer, target)).map_err(storage)?;
    let target_key = serde_json::to_string(&("global-target", target)).map_err(storage)?;
    charge(tx, &peer_key, now, 60, 1)?;
    charge(tx, &target_key, now, 3600, 20)
}

#[cfg(test)]
mod tests;

impl crate::RouterRedbStore {
    /// Expose one current published native bundle under persistent public allocation limits.
    /// Every selector is normalized to its server-qualified target before charging.
    /// # Errors
    /// Refuses disabled capability, wrong/moved home, stale branches, quotas and storage failure.
    pub fn reach_public_prekey(
        &self,
        router: &crate::RouterCore,
        node: &crate::MigrationNode,
        peer: &str,
        device: &ramflux_protocol::custody::DeviceRef,
        now: u64,
    ) -> Result<crate::PrekeyResponse> {
        if !ramflux_protocol::contact_reach::enabled() {
            return Err(refuse(Reason::ForeignCapabilityMissing));
        }
        let now = self.reach_fenced_now(now)?;
        let target =
            ramflux_protocol::qualified_device_id(&device.account_anchor, &device.device_id)?;
        let response = router
            .custody_prekey_response(&target, now, self)?
            .ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
        let bundle = response.bundle.as_ref().ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
        let (tx, now) = self.begin_reach_write(now)?;
        let authority = super::store::authority(&tx, &device.account_anchor, now)?;
        let home = super::store::home(&tx, &device.account_anchor)?;
        if home.record.home() != (node.node_id(), node.public_key()) {
            return Err(refuse(Reason::HomeRollback));
        }
        super::profile::public_profile(&tx, &device.account_anchor)?;
        let state = super::store::load(&tx, &device.account_anchor)?;
        let policy = state.policy.as_ref().ok_or_else(|| refuse(Reason::ReachPolicyRequired))?;
        ramflux_crypto::contact_reach::verify_retained_policy(policy, &authority, now)?;
        if policy.body.home_head_hash
            != ramflux_protocol::home_migration::record_hash(&home.record)?
        {
            return Err(refuse(Reason::HomeRollback));
        }
        ramflux_crypto::contact_reach::verify_native_prekey(&authority, device, bundle, now)?;
        ramflux_protocol::contact_reach::original_document(&response, 512 * 1024)?;
        reserve(&tx, peer, &target, now)?;
        tx.commit()?;
        Ok(response)
    }
}
