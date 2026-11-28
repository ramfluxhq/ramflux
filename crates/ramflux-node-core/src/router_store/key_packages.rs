// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The key package store of the home node (MLS-SPEC r1.1 3.5): per device, up to 100 one-time
//! key packages and one last-resort one. A fetch pops one one-time key package per device (or hands
//! out the last-resort one once the per-device pop budget is spent). The node cannot read a
//! key package; it bounds, stores, expires and hands out opaque blobs.
//!
//! Provisional bounds are named constants; none of them reads a clock for validity: `now` ages
//! stored rows and the pop budgets only.
use super::{NodeCoreError, ReadableDatabase, ReadableTable, RouterRedbStore, TableDefinition};
use crate::dm_order::{b64, b64_list};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

const ONE_TIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("key_package_one_time_v1");
const LAST_RESORT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("key_package_last_resort_v1");
const POPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("key_package_pops_v1");

/// One-time key packages in one publish.
pub const PUBLISH_ONE_TIME_MAX: usize = 50;
/// One-time key packages stored per device.
pub const ONE_TIME_STORED_MAX: usize = 100;
/// Largest key package blob.
pub const KEY_PACKAGE_MAX_BYTES: usize = 64 * 1024;
/// Stored key packages older than this are evicted (28 days).
pub const KEY_PACKAGE_MAX_AGE_SECS: u64 = 28 * 86_400;
/// `status` asks the device to top up below this many one-time key packages.
pub const TOP_UP_BELOW: usize = 20;
/// One-time pops per target device per hour.
pub const POPS_PER_HOUR: usize = 10;
/// One-time pops per target device per day.
pub const POPS_PER_DAY: usize = 100;
/// Fetches per source address per 10 minutes.
pub const FETCHES_PER_IP_10_MIN: usize = 60;
/// Fetches per authenticated anchor per 10 minutes.
pub const FETCHES_PER_ANCHOR_10_MIN: usize = 120;
/// Devices answered by one fetch.
pub const FETCH_DEVICES_MAX: usize = 64;
const FETCH_WINDOW_SECS: u64 = 600;
const HOUR_SECS: u64 = 3_600;
const DAY_SECS: u64 = 86_400;
const FETCH_KEYS_MAX: usize = 16_384;
const DEVICE_ID_MAX: usize = 128;
/// Anchors are 43 base64url characters.
const ANCHOR_BYTES: usize = 43;

fn error(source: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(source.to_string())
}

fn corrupt() -> NodeCoreError {
    NodeCoreError::UnsupportedPersistedFormat("key_package row")
}

/// Publish request of the authenticated device.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackagePublishRequest {
    /// One-time key packages (at most 50).
    #[serde(default, with = "b64_list")]
    pub one_time: Vec<Vec<u8>>,
    /// The device's last-resort key package; replaces the stored one.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_b64")]
    pub last_resort: Option<Vec<u8>>,
}

mod opt_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option, reason = "serde `with` hands the field by reference")]
    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_str(&ramflux_protocol::encode_base64url(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| ramflux_protocol::decode_base64url(&text).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Why a publish was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPackageRefusal {
    /// More than 50 one-time key packages in one publish, or nothing to store.
    BadCount,
    /// A key package is empty or over 64 KiB.
    BadSize,
    /// The device would hold more than 100 one-time key packages.
    Quota,
    /// Malformed anchor or device id.
    BadDevice,
}

/// What the device has stored.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackageStatusResponse {
    /// One-time key packages stored.
    pub one_time: u32,
    /// A last-resort key package is stored.
    pub last_resort: bool,
    /// Fewer than 20 one-time key packages: publish more.
    pub top_up: bool,
}

/// The answer to a publish.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum KeyPackagePublishOutcome {
    /// Stored.
    Stored {
        /// Stored state after the publish.
        status: KeyPackageStatusResponse,
    },
    /// Refused.
    Refused {
        /// Why.
        code: KeyPackageRefusal,
    },
}

/// One device's key package in a fetch answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FetchedKeyPackage {
    /// Device the key package belongs to.
    pub device_id: String,
    /// The key package (opaque).
    #[serde(with = "b64")]
    pub key_package: Vec<u8>,
    /// The last-resort key package (reusable) rather than a popped one-time one.
    pub last_resort: bool,
}

/// The answer to a fetch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyPackageFetchResponse {
    /// One key package per device that has any.
    pub key_packages: Vec<FetchedKeyPackage>,
}

#[derive(Default)]
struct FetchWindows {
    hits: HashMap<String, VecDeque<u64>>,
}

/// Fetch limits per source address and per authenticated anchor (in memory).
#[derive(Default)]
pub struct KeyPackageFetchLimits {
    windows: Mutex<FetchWindows>,
}

impl KeyPackageFetchLimits {
    /// Empty limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one fetch from `source` (an address string, public endpoint) and, when the caller is
    /// authenticated, `anchor`. `Err` carries the seconds to wait.
    ///
    /// # Errors
    /// The seconds until a retry may succeed.
    pub fn admit(&self, source: Option<&str>, anchor: Option<&str>, now: u64) -> Result<(), u64> {
        let mut windows = self.windows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut keys = Vec::with_capacity(2);
        if let Some(source) = source {
            keys.push((format!("ip/{source}"), FETCHES_PER_IP_10_MIN));
        }
        if let Some(anchor) = anchor {
            keys.push((format!("anchor/{anchor}"), FETCHES_PER_ANCHOR_10_MIN));
        }
        for (key, limit) in &keys {
            let hits = windows.hits.get_mut(key);
            if let Some(hits) = hits {
                while hits.front().is_some_and(|at| at.saturating_add(FETCH_WINDOW_SECS) <= now) {
                    hits.pop_front();
                }
                if hits.len() >= *limit {
                    let first = hits.front().copied().unwrap_or(now);
                    return Err(first.saturating_add(FETCH_WINDOW_SECS).saturating_sub(now).max(1));
                }
            }
        }
        if windows.hits.len() >= FETCH_KEYS_MAX {
            windows.hits.retain(|_, hits| {
                while hits.front().is_some_and(|at| at.saturating_add(FETCH_WINDOW_SECS) <= now) {
                    hits.pop_front();
                }
                !hits.is_empty()
            });
            if windows.hits.len() >= FETCH_KEYS_MAX {
                return Err(FETCH_WINDOW_SECS);
            }
        }
        for (key, _) in keys {
            windows.hits.entry(key).or_default().push_back(now);
        }
        Ok(())
    }
}

/// `anchor || u8 device id length || device id`.
fn device_key(anchor: &str, device_id: &str) -> Option<Vec<u8>> {
    if anchor.len() != ANCHOR_BYTES || device_id.is_empty() || device_id.len() > DEVICE_ID_MAX {
        return None;
    }
    let mut key = Vec::with_capacity(ANCHOR_BYTES + 1 + device_id.len());
    key.extend_from_slice(anchor.as_bytes());
    key.push(u8::try_from(device_id.len()).ok()?);
    key.extend_from_slice(device_id.as_bytes());
    Some(key)
}

fn one_time_key(device: &[u8], seq: u64) -> Vec<u8> {
    let mut key = device.to_vec();
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn seq_of(key: &[u8], device_len: usize) -> Result<u64, NodeCoreError> {
    let tail = key.get(device_len..).ok_or_else(corrupt)?;
    Ok(u64::from_be_bytes(tail.try_into().map_err(|_| corrupt())?))
}

fn stored_at(value: &[u8]) -> Result<u64, NodeCoreError> {
    let at = value.get(..8).ok_or_else(corrupt)?;
    Ok(u64::from_be_bytes(at.try_into().map_err(|_| corrupt())?))
}

fn with_stamp(now: u64, blob: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(blob.len().saturating_add(8));
    row.extend_from_slice(&now.to_be_bytes());
    row.extend_from_slice(blob);
    row
}

fn expired(at: u64, now: u64) -> bool {
    at.saturating_add(KEY_PACKAGE_MAX_AGE_SECS) < now
}

/// Live rows `(key, stored_at)` and expired keys of one device.
type OneTimeRows = (Vec<(Vec<u8>, u64)>, Vec<Vec<u8>>);

/// Live one-time rows of one device: `(key, stored_at)`, plus the keys of expired ones.
fn one_time_rows<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    device: &[u8],
    now: u64,
) -> Result<OneTimeRows, NodeCoreError> {
    let start = one_time_key(device, 0);
    let end = one_time_key(device, u64::MAX);
    let mut live = Vec::new();
    let mut dead = Vec::new();
    for row in table.range(start.as_slice()..=end.as_slice()).map_err(error)? {
        let (key, value) = row.map_err(error)?;
        let at = stored_at(value.value())?;
        if expired(at, now) {
            dead.push(key.value().to_vec());
        } else {
            live.push((key.value().to_vec(), at));
        }
    }
    Ok((live, dead))
}

fn status_of(one_time: usize, last_resort: bool) -> KeyPackageStatusResponse {
    KeyPackageStatusResponse {
        one_time: u32::try_from(one_time).unwrap_or(u32::MAX),
        last_resort,
        top_up: one_time < TOP_UP_BELOW,
    }
}

fn last_resort_live<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    device: &[u8],
    now: u64,
) -> Result<Option<Vec<u8>>, NodeCoreError> {
    let Some(row) = table.get(device).map_err(error)? else { return Ok(None) };
    let value = row.value();
    if expired(stored_at(value)?, now) {
        return Ok(None);
    }
    Ok(value.get(8..).map(<[u8]>::to_vec))
}

/// Pop timestamps of a device, newest last, as 8-byte big-endian values.
fn decode_pops(bytes: &[u8]) -> Result<Vec<u64>, NodeCoreError> {
    if !bytes.len().is_multiple_of(8) || bytes.len() > POPS_PER_DAY * 8 {
        return Err(corrupt());
    }
    Ok(bytes.as_chunks::<8>().0.iter().map(|chunk| u64::from_be_bytes(*chunk)).collect())
}

impl RouterRedbStore {
    /// Store a device's key packages (authenticated session of that device).
    ///
    /// # Errors
    /// Database failures; bound violations are a [`KeyPackagePublishOutcome::Refused`].
    pub fn key_package_publish(
        &self,
        anchor: &str,
        device_id: &str,
        request: &KeyPackagePublishRequest,
        now: u64,
    ) -> Result<KeyPackagePublishOutcome, NodeCoreError> {
        let Some(device) = device_key(anchor, device_id) else {
            return Ok(KeyPackagePublishOutcome::Refused { code: KeyPackageRefusal::BadDevice });
        };
        if request.one_time.len() > PUBLISH_ONE_TIME_MAX
            || (request.one_time.is_empty() && request.last_resort.is_none())
        {
            return Ok(KeyPackagePublishOutcome::Refused { code: KeyPackageRefusal::BadCount });
        }
        let blobs = request.one_time.iter().chain(request.last_resort.iter());
        if blobs.into_iter().any(|blob| blob.is_empty() || blob.len() > KEY_PACKAGE_MAX_BYTES) {
            return Ok(KeyPackagePublishOutcome::Refused { code: KeyPackageRefusal::BadSize });
        }
        let txn = self.begin_write()?;
        let outcome = {
            let mut one_time = txn.open_table(ONE_TIME).map_err(error)?;
            let mut last_resort = txn.open_table(LAST_RESORT).map_err(error)?;
            let (live, dead) = one_time_rows(&one_time, &device, now)?;
            if live.len().saturating_add(request.one_time.len()) > ONE_TIME_STORED_MAX {
                None
            } else {
                for key in dead {
                    one_time.remove(key.as_slice()).map_err(error)?;
                }
                let mut seq = live
                    .iter()
                    .map(|(key, _)| seq_of(key, device.len()))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .max()
                    .unwrap_or(0);
                for blob in &request.one_time {
                    seq = seq.checked_add(1).ok_or_else(corrupt)?;
                    one_time
                        .insert(
                            one_time_key(&device, seq).as_slice(),
                            with_stamp(now, blob).as_slice(),
                        )
                        .map_err(error)?;
                }
                if let Some(blob) = &request.last_resort {
                    last_resort
                        .insert(device.as_slice(), with_stamp(now, blob).as_slice())
                        .map_err(error)?;
                }
                let has_last_resort = last_resort_live(&last_resort, &device, now)?.is_some();
                Some(status_of(live.len().saturating_add(request.one_time.len()), has_last_resort))
            }
        };
        if let Some(status) = outcome {
            txn.commit()?;
            Ok(KeyPackagePublishOutcome::Stored { status })
        } else {
            txn.abort()?;
            Ok(KeyPackagePublishOutcome::Refused { code: KeyPackageRefusal::Quota })
        }
    }

    /// What `anchor`'s `device_id` has stored.
    ///
    /// # Errors
    /// Database failures.
    pub fn key_package_status(
        &self,
        anchor: &str,
        device_id: &str,
        now: u64,
    ) -> Result<KeyPackageStatusResponse, NodeCoreError> {
        let Some(device) = device_key(anchor, device_id) else {
            return Ok(status_of(0, false));
        };
        let txn = self.db.begin_read().map_err(error)?;
        let one_time = txn.open_table(ONE_TIME).map_err(error)?;
        let last_resort = txn.open_table(LAST_RESORT).map_err(error)?;
        let (live, _) = one_time_rows(&one_time, &device, now)?;
        Ok(status_of(live.len(), last_resort_live(&last_resort, &device, now)?.is_some()))
    }

    /// Hand out one key package per device of `anchor`: the oldest one-time one is popped; when the
    /// device's pop budget (10/h, 100/day) is spent or it has none, its last-resort one is given.
    ///
    /// # Errors
    /// Database failures.
    pub fn key_package_fetch(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<KeyPackageFetchResponse, NodeCoreError> {
        if anchor.len() != ANCHOR_BYTES {
            return Ok(KeyPackageFetchResponse::default());
        }
        let txn = self.begin_write()?;
        let mut answer = Vec::new();
        {
            let mut one_time = txn.open_table(ONE_TIME).map_err(error)?;
            let last_resort = txn.open_table(LAST_RESORT).map_err(error)?;
            let mut pops = txn.open_table(POPS).map_err(error)?;
            let mut devices = device_keys(&one_time, &last_resort, anchor)?;
            devices.truncate(FETCH_DEVICES_MAX);
            for device in devices {
                let device_id = device_id_of(&device)?;
                let (live, dead) = one_time_rows(&one_time, &device, now)?;
                for key in dead {
                    one_time.remove(key.as_slice()).map_err(error)?;
                }
                let history = match pops.get(device.as_slice()).map_err(error)? {
                    Some(row) => decode_pops(row.value())?,
                    None => Vec::new(),
                };
                let day: Vec<u64> =
                    history.into_iter().filter(|at| at.saturating_add(DAY_SECS) > now).collect();
                let hour = day.iter().filter(|at| at.saturating_add(HOUR_SECS) > now).count();
                let budget = hour < POPS_PER_HOUR && day.len() < POPS_PER_DAY;
                let popped = match live.first() {
                    Some((key, _)) if budget => {
                        let blob = one_time
                            .remove(key.as_slice())
                            .map_err(error)?
                            .map(|row| row.value().get(8..).map(<[u8]>::to_vec))
                            .ok_or_else(corrupt)?
                            .ok_or_else(corrupt)?;
                        let mut day = day;
                        day.push(now);
                        let bytes: Vec<u8> = day.iter().flat_map(|at| at.to_be_bytes()).collect();
                        pops.insert(device.as_slice(), bytes.as_slice()).map_err(error)?;
                        Some(blob)
                    }
                    _ => None,
                };
                if let Some(blob) = popped {
                    answer.push(FetchedKeyPackage {
                        device_id,
                        key_package: blob,
                        last_resort: false,
                    });
                } else if let Some(blob) = last_resort_live(&last_resort, &device, now)? {
                    answer.push(FetchedKeyPackage {
                        device_id,
                        key_package: blob,
                        last_resort: true,
                    });
                }
            }
        }
        txn.commit()?;
        Ok(KeyPackageFetchResponse { key_packages: answer })
    }
}

/// Distinct device keys of `anchor` that hold any key package, in key order.
fn device_keys<T: ReadableTable<&'static [u8], &'static [u8]>>(
    one_time: &T,
    last_resort: &T,
    anchor: &str,
) -> Result<Vec<Vec<u8>>, NodeCoreError> {
    let mut start = anchor.as_bytes().to_vec();
    let mut end = start.clone();
    start.push(0);
    end.push(u8::MAX);
    end.extend_from_slice(&[u8::MAX; DEVICE_ID_MAX + 8]);
    let mut devices = std::collections::BTreeSet::new();
    for row in one_time.range(start.as_slice()..=end.as_slice()).map_err(error)? {
        let (key, _) = row.map_err(error)?;
        let key = key.value();
        let device_len = key.len().checked_sub(8).ok_or_else(corrupt)?;
        devices.insert(key.get(..device_len).ok_or_else(corrupt)?.to_vec());
    }
    for row in last_resort.range(start.as_slice()..=end.as_slice()).map_err(error)? {
        let (key, _) = row.map_err(error)?;
        devices.insert(key.value().to_vec());
    }
    Ok(devices.into_iter().collect())
}

fn device_id_of(device: &[u8]) -> Result<String, NodeCoreError> {
    let id = device.get(ANCHOR_BYTES + 1..).ok_or_else(corrupt)?;
    String::from_utf8(id.to_vec()).map_err(|_| corrupt())
}

/// Create the tables so reads on a fresh database find them.
pub(super) fn initialize(txn: &redb::WriteTransaction) -> Result<(), NodeCoreError> {
    for table in [ONE_TIME, LAST_RESORT, POPS] {
        txn.open_table(table).map_err(error)?;
    }
    Ok(())
}
