// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Redb state for the node push policy (CENTRAL P2b, K9-K12). Device policy, holds,
//! clears and hourly stats are durable; presence is in memory only, so a restart reads
//! every device as unknown and sends at once (spec rule 5).

use super::policy::{
    DeviceClass, DevicePolicyRecord, HoldDecision, HoldState, POLICY_CLEAR_TTL_S, PolicyHoldRow,
    PolicyStatsHour, PushPolicy, decide_wake, is_call_class, utc_hour_start_ms,
};
use super::{NodeCoreError, NotifyQueueEntry, NotifyRedbStore};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_DEVICE: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_policy_device_v1");
const POLICY_HOLDS: TableDefinition<&str, &[u8]> = TableDefinition::new("notify_policy_holds_v1");
const POLICY_STATS: TableDefinition<u64, &[u8]> = TableDefinition::new("notify_policy_stats_v1");
const POLICY_NOTIFIED: TableDefinition<&str, u64> =
    TableDefinition::new("notify_policy_notified_v1");
const POLICY_CLEARS: TableDefinition<&str, u64> = TableDefinition::new("notify_policy_clears_v1");
const HOUR_MS: u64 = 3_600_000;

/// Stored hour row: the public counters plus whether the centre acknowledged them.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct PolicyStatsRow {
    hour: PolicyStatsHour,
    acked: bool,
}

/// Result of one clear, for logs and tests of the real run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyClearOutcome {
    pub held_dropped: u64,
    pub clears_pending: u64,
    pub clears_conn: u64,
    pub muted: u64,
}

pub(crate) fn initialize(write_txn: &WriteTransaction) -> Result<(), NodeCoreError> {
    write_txn.open_table(POLICY_DEVICE).map_err(redb_error)?;
    write_txn.open_table(POLICY_HOLDS).map_err(redb_error)?;
    write_txn.open_table(POLICY_STATS).map_err(redb_error)?;
    write_txn.open_table(POLICY_NOTIFIED).map_err(redb_error)?;
    write_txn.open_table(POLICY_CLEARS).map_err(redb_error)?;
    Ok(())
}

fn redb_error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NodeCoreError> {
    serde_json::to_vec(value)
        .map_err(|source| NodeCoreError::SnapshotSerialization(source.to_string()))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, NodeCoreError> {
    serde_json::from_slice(bytes)
        .map_err(|_| NodeCoreError::UnsupportedPersistedFormat("notify policy row"))
}

/// Increment the counters of the UTC hour containing `now_ms`; any change makes the hour
/// unacknowledged again, so the next sync resends it (replace semantics on the centre).
fn bump_stats(
    write_txn: &WriteTransaction,
    now_ms: u64,
    change: impl FnOnce(&mut PolicyStatsHour),
) -> Result<(), NodeCoreError> {
    let from_ms = utc_hour_start_ms(now_ms);
    let mut table = write_txn.open_table(POLICY_STATS).map_err(redb_error)?;
    let mut row = match table.get(from_ms).map_err(redb_error)? {
        Some(value) => decode::<PolicyStatsRow>(value.value())?,
        None => PolicyStatsRow {
            hour: PolicyStatsHour { from_ms, to_ms: from_ms + HOUR_MS, ..Default::default() },
            acked: false,
        },
    };
    change(&mut row.hour);
    row.acked = false;
    table.insert(from_ms, encode(&row)?.as_slice()).map_err(redb_error)?;
    Ok(())
}

fn put_hold(
    write_txn: &WriteTransaction,
    queue_id: &str,
    row: &PolicyHoldRow,
) -> Result<(), NodeCoreError> {
    let mut table = write_txn.open_table(POLICY_HOLDS).map_err(redb_error)?;
    table.insert(queue_id, encode(row)?.as_slice()).map_err(redb_error)?;
    Ok(())
}

impl NotifyRedbStore {
    fn policy_write<R>(
        &self,
        apply: impl FnOnce(&WriteTransaction) -> Result<R, NodeCoreError>,
    ) -> Result<R, NodeCoreError> {
        let _writer =
            self.local_writer.lock().map_err(|_| NodeCoreError::Redb("writer poisoned".into()))?;
        let write_txn = self.db.begin_write().map_err(redb_error)?;
        let result = apply(&write_txn)?;
        write_txn.commit().map_err(redb_error)?;
        self.note_delivery_work();
        Ok(result)
    }

    /// The push policy in force. In memory only: before the first `ok` reply of a process
    /// it is `before_first_reply()` (`t_s` 0, `version` 0).
    #[must_use]
    pub fn push_policy(&self) -> PushPolicy {
        self.policy_applied
            .lock()
            .ok()
            .and_then(|applied| *applied)
            .unwrap_or_else(PushPolicy::before_first_reply)
    }

    /// `policy_version` for the request member (0 before the first reply).
    #[must_use]
    pub fn push_policy_version(&self) -> u64 {
        self.push_policy().version
    }

    /// Apply the newest `dir.policy` received (version 0 included). Out-of-bounds values are
    /// refused and the previous policy stays. A wake already held keeps its timer.
    /// Returns true when the policy was applied.
    pub fn set_push_policy(&self, policy: PushPolicy) -> bool {
        if !policy.in_bounds() {
            return false;
        }
        match self.policy_applied.lock() {
            Ok(mut applied) => {
                *applied = Some(policy);
                true
            }
            Err(_) => false,
        }
    }

    /// Record or replace one device's policy (class, mute, account group).
    ///
    /// # Errors
    /// Returns an error when the row cannot be written.
    pub fn set_device_policy(
        &self,
        device_delivery_id: &str,
        account_group: &str,
        device_class: DeviceClass,
        muted: bool,
    ) -> Result<(), NodeCoreError> {
        let record = DevicePolicyRecord {
            account_group: account_group.to_owned(),
            device_class,
            muted,
            updated_ms: now_unix_ms(),
        };
        self.policy_write(|txn| {
            let mut table = txn.open_table(POLICY_DEVICE).map_err(redb_error)?;
            table.insert(device_delivery_id, encode(&record)?.as_slice()).map_err(redb_error)?;
            Ok(())
        })
    }

    /// Device policy record, if the device sent one.
    ///
    /// # Errors
    /// Returns an error when the row cannot be read.
    pub fn device_policy(
        &self,
        device_delivery_id: &str,
    ) -> Result<Option<DevicePolicyRecord>, NodeCoreError> {
        let read_txn = self.db.begin_read().map_err(redb_error)?;
        let table = read_txn.open_table(POLICY_DEVICE).map_err(redb_error)?;
        match table.get(device_delivery_id).map_err(redb_error)? {
            Some(value) => decode(value.value()).map(Some),
            None => Ok(None),
        }
    }

    /// "User active now" from a device. In memory only (restart = unknown).
    pub fn note_device_activity(&self, device_delivery_id: &str, now_ms: u64) {
        if let Ok(mut presence) = self.policy_presence.lock() {
            presence.insert(device_delivery_id.to_owned(), now_ms);
        }
    }

    fn group_devices(
        &self,
        account_group: &str,
    ) -> Result<Vec<(String, DevicePolicyRecord)>, NodeCoreError> {
        let read_txn = self.db.begin_read().map_err(redb_error)?;
        let table = read_txn.open_table(POLICY_DEVICE).map_err(redb_error)?;
        let mut devices = Vec::new();
        for row in table.iter().map_err(redb_error)? {
            let (key, value) = row.map_err(redb_error)?;
            let record: DevicePolicyRecord = decode(value.value())?;
            if record.account_group == account_group {
                devices.push((key.value().to_owned(), record));
            }
        }
        Ok(devices)
    }

    fn peer_active(
        &self,
        device_delivery_id: &str,
        account_group: &str,
        now_ms: u64,
        n_s: u64,
    ) -> Result<bool, NodeCoreError> {
        let cutoff = now_ms.saturating_sub(n_s.saturating_mul(1_000));
        let presence = match self.policy_presence.lock() {
            Ok(presence) => presence.clone(),
            Err(_) => return Ok(false),
        };
        Ok(self.group_devices(account_group)?.into_iter().any(|(device, _)| {
            device != device_delivery_id && presence.get(&device).is_some_and(|at| *at >= cutoff)
        }))
    }

    fn hold_row(&self, queue_id: &str) -> Result<Option<PolicyHoldRow>, NodeCoreError> {
        let read_txn = self.db.begin_read().map_err(redb_error)?;
        let table = read_txn.open_table(POLICY_HOLDS).map_err(redb_error)?;
        match table.get(queue_id).map_err(redb_error)? {
            Some(value) => decode(value.value()).map(Some),
            None => Ok(None),
        }
    }

    /// Unix-millisecond time the hold of this queue entry ends, if it is still held.
    ///
    /// # Errors
    /// Returns an error when the hold row cannot be read.
    pub fn held_until_ms(&self, queue_id: &str) -> Result<Option<u64>, NodeCoreError> {
        Ok(self
            .hold_row(queue_id)?
            .filter(|row| row.state == HoldState::Held)
            .map(|row| row.not_before_ms))
    }

    /// Policy gate for one direct-mode provider push. Returns true when the normal send
    /// path may run now; false when the wake is held, muted or dropped (the decision and
    /// its counters are written here, once per wake).
    pub(super) fn policy_send_allowed(
        &self,
        entry: &NotifyQueueEntry,
    ) -> Result<bool, NodeCoreError> {
        let now = now_unix_ms();
        let device = entry.device_delivery_id.as_str();
        if let Some(row) = self.hold_row(&entry.queue_id)? {
            return match row.state {
                HoldState::Held if now >= row.not_before_ms => {
                    self.policy_write(|txn| {
                        let released = PolicyHoldRow { state: HoldState::Sent, ..row.clone() };
                        put_hold(txn, &entry.queue_id, &released)?;
                        bump_stats(txn, now, |hour| hour.held_sent += 1)?;
                        set_notified(txn, device)
                    })?;
                    Ok(true)
                }
                HoldState::Held | HoldState::Dropped | HoldState::Muted => Ok(false),
                HoldState::Sent => Ok(true),
            };
        }
        let record = self.device_policy(device)?;
        let is_call = is_call_class(&entry.wake.delivery_class);
        let policy = self.push_policy();
        let peer_active = match &record {
            Some(record) => self.peer_active(device, &record.account_group, now, policy.n_s)?,
            None => false,
        };
        let group = record.as_ref().map(|record| record.account_group.clone()).unwrap_or_default();
        let decision = decide_wake(record.as_ref(), is_call, peer_active, policy, now);
        let row = |state, not_before_ms| PolicyHoldRow {
            device_delivery_id: device.to_owned(),
            account_group: group.clone(),
            state,
            not_before_ms,
            expires_at_s: entry.expires_at,
        };
        match decision {
            HoldDecision::Muted => {
                self.policy_write(|txn| {
                    put_hold(txn, &entry.queue_id, &row(HoldState::Muted, 0))?;
                    bump_stats(txn, now, |hour| hour.muted += 1)
                })?;
                tracing::info!(target: "ramflux_notify_policy", event = "policy.muted", "wake dropped: device muted");
                Ok(false)
            }
            HoldDecision::Hold { not_before_ms } => {
                self.policy_write(|txn| {
                    put_hold(txn, &entry.queue_id, &row(HoldState::Held, not_before_ms))?;
                    set_notified(txn, device)
                })?;
                tracing::info!(target: "ramflux_notify_policy", event = "policy.hold", "wake held");
                Ok(false)
            }
            HoldDecision::SendNow => {
                if !is_call && record.is_some() {
                    self.policy_write(|txn| set_notified(txn, device))?;
                }
                Ok(true)
            }
        }
    }

    /// Filter pending candidates by policy: terminal holds (muted, dropped) leave the
    /// queue; held entries stay with `not_before_ms` set so `due()` reflects the hold.
    pub(super) fn apply_policy_to_pending(
        &self,
        entries: Vec<NotifyQueueEntry>,
    ) -> Result<Vec<NotifyQueueEntry>, NodeCoreError> {
        let mut kept = Vec::with_capacity(entries.len());
        for mut entry in entries {
            match self.hold_row(&entry.queue_id)? {
                Some(row) if matches!(row.state, HoldState::Muted | HoldState::Dropped) => {}
                Some(row) if row.state == HoldState::Held => {
                    entry.not_before_ms = row.not_before_ms;
                    kept.push(entry);
                }
                _ => kept.push(entry),
            }
        }
        Ok(kept)
    }

    /// Apply an in-band clear (wire class `x` origin) from `device_delivery_id`.
    /// `live_cleared` lists the account's devices that got the clear on a live session.
    ///
    /// # Errors
    /// Returns an error when the policy state cannot be read or written.
    pub fn apply_policy_clear(
        &self,
        device_delivery_id: &str,
        live_cleared: &[String],
    ) -> Result<PolicyClearOutcome, NodeCoreError> {
        let Some(record) = self.device_policy(device_delivery_id)? else {
            return Ok(PolicyClearOutcome::default());
        };
        let now = now_unix_ms();
        let group = record.account_group.clone();
        let devices = self.group_devices(&group)?;
        // Mute withholds `x` as well as `m`: a muted device gets no clear row.
        let muted_devices: BTreeSet<String> = devices
            .iter()
            .filter(|(_, record)| record.muted)
            .map(|(device, _)| device.clone())
            .collect();
        let group_members: BTreeSet<String> =
            devices.iter().map(|(device, _)| device.clone()).collect();
        let reached: BTreeSet<String> = live_cleared
            .iter()
            .filter(|device| group_members.contains(*device) && device.as_str() != device_delivery_id)
            .cloned()
            .collect();
        self.policy_write(|txn| {
            let mut outcome = PolicyClearOutcome::default();
            let mut drop_ids = Vec::new();
            {
                let table = txn.open_table(POLICY_HOLDS).map_err(redb_error)?;
                for row in table.iter().map_err(redb_error)? {
                    let (key, value) = row.map_err(redb_error)?;
                    let hold: PolicyHoldRow = decode(value.value())?;
                    if hold.state == HoldState::Held
                        && hold.account_group == group
                        && hold.device_delivery_id != device_delivery_id
                    {
                        drop_ids.push((key.value().to_owned(), hold));
                    }
                }
            }
            for (queue_id, hold) in drop_ids {
                put_hold(txn, &queue_id, &PolicyHoldRow { state: HoldState::Dropped, ..hold })?;
                outcome.held_dropped += 1;
            }
            {
                let mut notified = txn.open_table(POLICY_NOTIFIED).map_err(redb_error)?;
                let mut clears = txn.open_table(POLICY_CLEARS).map_err(redb_error)?;
                for (device, _) in &devices {
                    let was_notified = notified.remove(device.as_str()).map_err(redb_error)?;
                    if device == device_delivery_id || was_notified.is_none() {
                        continue;
                    }
                    if reached.contains(device) {
                        continue;
                    }
                    if muted_devices.contains(device) {
                        outcome.muted += 1;
                        continue;
                    }
                    clears.insert(device.as_str(), now).map_err(redb_error)?;
                    outcome.clears_pending += 1;
                }
            }
            outcome.clears_conn = u64::try_from(reached.len()).unwrap_or(u64::MAX);
            bump_stats(txn, now, |hour| {
                hour.held_dropped += outcome.held_dropped;
                hour.muted += outcome.muted;
                hour.clears_conn += outcome.clears_conn;
            })?;
            Ok(outcome)
        })
    }

    /// Devices owed an internal clear (wire class `x`) that are not yet acknowledged.
    ///
    /// # Errors
    /// Returns an error when the clear rows cannot be read.
    pub fn pending_policy_clears(&self, now_ms: u64) -> Result<Vec<String>, NodeCoreError> {
        let read_txn = self.db.begin_read().map_err(redb_error)?;
        let table = read_txn.open_table(POLICY_CLEARS).map_err(redb_error)?;
        let ttl_ms = POLICY_CLEAR_TTL_S.saturating_mul(1_000);
        let mut devices = Vec::new();
        for row in table.iter().map_err(redb_error)? {
            let (key, created) = row.map_err(redb_error)?;
            if created.value().saturating_add(ttl_ms) > now_ms {
                devices.push(key.value().to_owned());
            }
        }
        Ok(devices)
    }

    /// Remove a clear row once it was sent or expired.
    ///
    /// # Errors
    /// Returns an error when the row cannot be removed.
    pub fn ack_policy_clear(&self, device_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.policy_write(|txn| {
            let mut table = txn.open_table(POLICY_CLEARS).map_err(redb_error)?;
            table.remove(device_delivery_id).map_err(redb_error)?;
            Ok(())
        })
    }

    /// Newest unacknowledged COMPLETED hour (`to <= now_ms`), for `sync.stats`. Resend is
    /// allowed (replace semantics). Hours still in progress are never sent.
    ///
    /// # Errors
    /// Returns an error when the stats rows cannot be read.
    pub fn pending_policy_stats(
        &self,
        now_ms: u64,
    ) -> Result<Option<PolicyStatsHour>, NodeCoreError> {
        let read_txn = self.db.begin_read().map_err(redb_error)?;
        let table = read_txn.open_table(POLICY_STATS).map_err(redb_error)?;
        let mut newest: Option<PolicyStatsHour> = None;
        for row in table.iter().map_err(redb_error)? {
            let (_, value) = row.map_err(redb_error)?;
            let stored: PolicyStatsRow = decode(value.value())?;
            if !stored.acked && stored.hour.to_ms <= now_ms {
                newest = Some(stored.hour);
            }
        }
        Ok(newest)
    }

    /// Mark the hour starting at `from_ms` as acknowledged by the centre.
    ///
    /// # Errors
    /// Returns an error when the row cannot be written.
    pub fn ack_policy_stats(&self, from_ms: u64) -> Result<(), NodeCoreError> {
        self.policy_write(|txn| {
            let mut table = txn.open_table(POLICY_STATS).map_err(redb_error)?;
            let existing = match table.get(from_ms).map_err(redb_error)? {
                Some(value) => Some(decode::<PolicyStatsRow>(value.value())?),
                None => None,
            };
            if let Some(mut row) = existing {
                row.acked = true;
                table.insert(from_ms, encode(&row)?.as_slice()).map_err(redb_error)?;
            }
            Ok(())
        })
    }
}

fn set_notified(txn: &WriteTransaction, device_delivery_id: &str) -> Result<(), NodeCoreError> {
    let mut table = txn.open_table(POLICY_NOTIFIED).map_err(redb_error)?;
    table.insert(device_delivery_id, 1_u64).map_err(redb_error)?;
    Ok(())
}
