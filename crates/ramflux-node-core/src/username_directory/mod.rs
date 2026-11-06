// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant independent checkpoint components. OS authentication, protected provisioning and
//! actual transport writers belong to the service integration; no public route is installed.
mod checkpoint;
pub use checkpoint::*;
use ramflux_protocol::username_directory as wire;
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) const META: TableDefinition<&str, &[u8]> =
    TableDefinition::new("username_checkpoint_meta");
pub(crate) const IMAGE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("username_checkpoint_image");
pub(crate) const REDO: TableDefinition<u64, &[u8]> =
    TableDefinition::new("username_checkpoint_redo");
pub(crate) const TX_IDS: TableDefinition<&str, u64> =
    TableDefinition::new("username_checkpoint_tx_ids");

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint refused: {0}")]
    Refused(&'static str),
    #[error("checkpoint storage: {0}")]
    Storage(String),
    #[error(transparent)]
    Codec(#[from] wire::CodecError),
    #[error(transparent)]
    Crypto(#[from] ramflux_crypto::username_directory::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, CheckpointError>;
pub(crate) fn storage(error: impl std::fmt::Display) -> CheckpointError {
    CheckpointError::Storage(error.to_string())
}
pub(crate) fn require(value: bool, rule: &'static str) -> Result<()> {
    if value { Ok(()) } else { Err(CheckpointError::Refused(rule)) }
}
pub(crate) fn fixed(value: &str) -> Result<()> {
    let bytes =
        ramflux_protocol::decode_base64url(value).map_err(|_| CheckpointError::Refused("id"))?;
    require(bytes.len() == 32 && ramflux_protocol::encode_base64url(bytes) == value, "id")
}
/// Exact durable equality fence; no saved READY flag or lease is persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHead {
    pub center_id: String,
    pub generation: u64,
    pub lsn: u64,
    pub digest: String,
    pub clock_floor: u64,
    pub codec_version: u8,
    pub policy: String,
}
impl CheckpointHead {
    pub(crate) fn genesis(center_id: &str, generation: u64, wall: u64) -> Result<Self> {
        let head = Self {
            center_id: center_id.into(),
            generation,
            lsn: 0,
            digest: ramflux_protocol::encode_base64url([0_u8; 32]),
            clock_floor: wall,
            codec_version: 1,
            policy: wire::SCHEMA_POLICY.into(),
        };
        head.validate()?;
        Ok(head)
    }
    fn validate(&self) -> Result<()> {
        require(self.codec_version == 1 && self.policy == wire::SCHEMA_POLICY, "schema")?;
        require(self.clock_floor <= ramflux_protocol::MAX_SAFE_JSON_INTEGER, "clock")?;
        fixed(&self.digest)?;
        let checkpoint = wire::Checkpoint {
            center_id: self.center_id.clone(),
            generation: self.generation,
            lsn: self.lsn,
            previous_digest: self.digest.clone(),
            delta: wire::CheckpointDelta {
                kind: wire::DeltaKind::Clock,
                tx_id: ramflux_protocol::encode_base64url([1_u8; 32]),
                writer_incarnation: ramflux_protocol::encode_base64url([2_u8; 32]),
                clock_floor: self.clock_floor,
                operation: None,
                rows: Vec::new(),
            },
        };
        wire::encode(&checkpoint)?;
        Ok(())
    }
}
/// Trusted clock is owned by the witness, never selected by an append request.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointTime {
    pub wall: u64,
    pub monotonic: u64,
}
pub trait CheckpointClock: Send + Sync {
    fn now(&self) -> CheckpointTime;
}
pub struct SystemCheckpointClock {
    start: Instant,
}
impl Default for SystemCheckpointClock {
    fn default() -> Self {
        Self { start: Instant::now() }
    }
}
impl CheckpointClock for SystemCheckpointClock {
    fn now(&self) -> CheckpointTime {
        CheckpointTime {
            wall: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |v| v.as_secs()),
            monotonic: self.start.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        }
    }
}
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    ramflux_protocol::canonical_json_bytes(value).map_err(storage)
}
pub(crate) fn read_head(db: &redb::Database) -> Result<CheckpointHead> {
    use redb::ReadableDatabase;
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(META).map_err(storage)?;
    let row =
        table.get("head").map_err(storage)?.ok_or(CheckpointError::Refused("uninitialized"))?;
    let head: CheckpointHead = serde_json::from_slice(row.value())?;
    require(canonical(&head)? == row.value(), "head_canonical")?;
    head.validate()?;
    Ok(head)
}
pub(crate) fn put_head(tx: &redb::WriteTransaction, head: &CheckpointHead) -> Result<()> {
    tx.open_table(META)
        .map_err(storage)?
        .insert("head", canonical(head)?.as_slice())
        .map_err(storage)?;
    Ok(())
}
/// Return the bounded typed image key and exact old/new stored cell bytes.
type ImageCell = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
pub(crate) fn cell(row: &wire::Replacement) -> Result<ImageCell> {
    let (table, encoded) = row.order_key()?;
    let mut key = table.as_bytes().to_vec();
    key.push(0);
    // Due storage ordering is numeric time first, then the complete typed key.
    if let wire::Replacement::Due { key: due, .. } = row {
        let at = match due {
            wire::DueKey::Hold { at, .. }
            | wire::DueKey::Operation { at, .. }
            | wire::DueKey::RootWindow { at, .. }
            | wire::DueKey::HomeHoldCredit { at, .. } => *at,
        };
        key.extend_from_slice(&at.to_be_bytes());
    }
    key.extend(encoded);
    macro_rules! arms {($($variant:ident),*)=>{match row {$(wire::Replacement::$variant {key,old,new}=>{
        let pack=|value|canonical(&wire::Replacement::$variant {key:key.clone(),old:None,new:Some(value)});
        (old.clone().map(pack).transpose()?,new.clone().map(pack).transpose()?)
    }),*}};}
    let (old, new) = arms!(Root, Name, Skeleton, Hold, Operation, OpOwner, Due, Counter);
    Ok((key, old, new))
}
pub(crate) fn apply(tx: &redb::WriteTransaction, delta: &wire::CheckpointDelta) -> Result<()> {
    let mut table = tx.open_table(IMAGE).map_err(storage)?;
    for row in &delta.rows {
        let (key, old, _) = cell(row)?;
        let actual = table.get(key.as_slice()).map_err(storage)?.map(|v| v.value().to_vec());
        require(actual == old, "old_image")?;
    }
    for row in &delta.rows {
        let (key, _, new) = cell(row)?;
        if let Some(value) = new {
            table.insert(key.as_slice(), value.as_slice()).map_err(storage)?;
        } else {
            table.remove(key.as_slice()).map_err(storage)?;
        }
    }
    Ok(())
}
/// A bounded indexed page, never a snapshot of the whole authority image.
#[derive(Debug)]
pub struct ImagePage {
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
    pub next: Option<Vec<u8>>,
}
pub(crate) fn page(db: &redb::Database, after: Option<&[u8]>, limit: usize) -> Result<ImagePage> {
    use redb::ReadableDatabase;
    require((1..=128).contains(&limit), "page_limit")?;
    let tx = db.begin_read().map_err(storage)?;
    let table = tx.open_table(IMAGE).map_err(storage)?;
    let range = table.range(after.unwrap_or_default()..).map_err(storage)?;
    let mut rows = Vec::with_capacity(limit);
    for entry in range {
        let (key, value) = entry.map_err(storage)?;
        if after == Some(key.value()) {
            continue;
        }
        if rows.len() == limit {
            break;
        }
        rows.push((key.value().to_vec(), value.value().to_vec()));
    }
    let next = rows.last().map(|(k, _)| k.clone());
    Ok(ImagePage { rows, next })
}
#[cfg(test)]
mod checkpoint_tests;

pub(crate) fn reserve_file(path: &std::path::Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.sync_all()?;
    Ok(())
}
