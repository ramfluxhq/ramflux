// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable monotonic home floor and current-home verdict for the dormant attachment
//! source authority (P25 N5a). Resolve stays read-only, so the floor lives in its own
//! table: every verified `HomeRecord` this router sees advances it, never backwards,
//! and a verdict below the floor is refused even after the cache is gone or the store
//! was reopened.
use super::{
    HEADS, NodeCoreError, ReadableDatabase, RecordEvidence, RouterRedbStore, commit_transition,
    decode, record_hash, storage, write,
};
use crate::{
    HomeMigrationService,
    relay::attachment::{HomeVerdict, RenewalRefusal},
};
use ramflux_protocol::home_migration::{MAX_CHAIN_RECORDS, ResolvePayload, ResolveResult};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

const FLOOR: TableDefinition<&str, &[u8]> = TableDefinition::new("attachment_home_floor_v1");
/// Rows are never evicted: past this many anchors new anchors are refused.
pub const MAX_FLOOR_ANCHORS: usize = 65_536;
/// Cached verdicts: at most this many entries, each kept at most [`CACHE_TTL`] seconds.
pub const MAX_CACHED_VERDICTS: usize = 256;
pub const CACHE_TTL: u64 = 60;

/// Highest verified home evidence observed for one anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFloor {
    pub epoch: u64,
    pub record_hash: String,
    pub observed_at: u64,
}

/// Whether an observation moved the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloorObservation {
    Advanced,
    Unchanged,
}

fn refusal_storage(_: NodeCoreError) -> RenewalRefusal {
    RenewalRefusal::Storage
}

impl RouterRedbStore {
    /// Read the durable floor for `anchor`.
    /// # Errors
    /// `Storage` on a durable read or decode failure.
    pub fn attachment_home_floor(&self, anchor: &str) -> Result<Option<HomeFloor>, RenewalRefusal> {
        let tx = self.migration_db().begin_read().map_err(|e| refusal_storage(storage(e)))?;
        let table = match tx.open_table(FLOOR) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(refusal_storage(storage(e))),
        };
        table
            .get(anchor)
            .map_err(|e| refusal_storage(storage(e)))?
            .map(|v| decode(v.value()))
            .transpose()
            .map_err(refusal_storage)
    }

    /// Advance the floor with verified home evidence in one write transaction.
    /// Older evidence is a no-op; the same epoch with another hash is a fork.
    /// # Errors
    /// `HomeMismatch` on a fork, `HomeTrustUnavailable` when a new anchor would exceed
    /// [`MAX_FLOOR_ANCHORS`], `Storage` on a durable failure. Nothing is written on refusal.
    pub fn observe_attachment_home(
        &self,
        anchor: &str,
        epoch: u64,
        hash: &str,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        self.observe_attachment_home_capped(anchor, epoch, hash, now, MAX_FLOOR_ANCHORS)
    }

    pub(super) fn observe_attachment_home_capped(
        &self,
        anchor: &str,
        epoch: u64,
        hash: &str,
        now: u64,
        max_anchors: usize,
    ) -> Result<FloorObservation, RenewalRefusal> {
        let tx = self.begin_write().map_err(refusal_storage)?;
        let outcome = {
            let table = tx.open_table(FLOOR).map_err(|e| refusal_storage(storage(e)))?;
            let existing: Option<HomeFloor> = table
                .get(anchor)
                .map_err(|e| refusal_storage(storage(e)))?
                .map(|v| decode(v.value()))
                .transpose()
                .map_err(refusal_storage)?;
            match existing {
                Some(row) if epoch < row.epoch => return Ok(FloorObservation::Unchanged),
                Some(row) if epoch == row.epoch && hash == row.record_hash => {
                    return Ok(FloorObservation::Unchanged);
                }
                Some(row) if epoch == row.epoch => return Err(RenewalRefusal::HomeMismatch),
                None if table.len().map_err(|e| refusal_storage(storage(e)))?
                    >= max_anchors as u64 =>
                {
                    return Err(RenewalRefusal::HomeTrustUnavailable);
                }
                _ => FloorObservation::Advanced,
            }
        };
        write(
            &tx,
            FLOOR,
            anchor,
            &HomeFloor { epoch, record_hash: hash.to_owned(), observed_at: now },
        )
        .map_err(refusal_storage)?;
        commit_transition(self, tx).map_err(refusal_storage)?;
        Ok(outcome)
    }

    /// Refuse home evidence that is below the floor, or forks it at the same epoch.
    /// # Errors
    /// `HomeMismatch` for a superseded chain or a fork; `Storage` on a durable failure.
    pub fn check_attachment_home(
        &self,
        anchor: &str,
        epoch: u64,
        hash: &str,
    ) -> Result<(), RenewalRefusal> {
        match self.attachment_home_floor(anchor)? {
            Some(floor)
                if epoch < floor.epoch || (epoch == floor.epoch && hash != floor.record_hash) =>
            {
                Err(RenewalRefusal::HomeMismatch)
            }
            _ => Ok(()),
        }
    }

    /// Fold the router's own current head into the floor (a `latest_migration_home` source).
    /// # Errors
    /// As [`Self::observe_attachment_home`].
    pub fn observe_attachment_head(
        &self,
        anchor: &str,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        let head: Option<RecordEvidence> = {
            let tx = self.migration_db().begin_read().map_err(|e| refusal_storage(storage(e)))?;
            match tx.open_table(HEADS) {
                Ok(table) => table
                    .get(anchor)
                    .map_err(|e| refusal_storage(storage(e)))?
                    .map(|v| decode(v.value()))
                    .transpose()
                    .map_err(refusal_storage)?,
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(refusal_storage(storage(e))),
            }
        };
        let Some(head) = head else { return Ok(FloorObservation::Unchanged) };
        let hash = record_hash(&head.record).map_err(|_| RenewalRefusal::Storage)?;
        self.observe_attachment_home(anchor, head.record.epoch(), &hash, now)
    }
}

/// In-memory verdict cache. It is advisory: the durable floor is the authority.
#[derive(Default)]
pub struct AttachmentHomeVerdicts {
    cache: Mutex<BTreeMap<(String, u64, String), HomeVerdict>>,
}

impl AttachmentHomeVerdicts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of cached verdicts.
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.lock().map_or(0, |c| c.len())
    }

    /// Verdict for `anchor`: a fresh cache hit, otherwise `resolve` (which performs the
    /// `latest_migration_home` lookup), checked against and folded into the floor.
    /// # Errors
    /// `HomeMismatch` when the resolved head is below or forks the floor,
    /// `HomeTrustUnavailable` when the floor is full or the head key is unusable,
    /// `Storage` on a durable failure, or the resolver's refusal.
    pub fn verdict(
        &self,
        store: &RouterRedbStore,
        anchor: &str,
        now: u64,
        resolve: impl FnOnce() -> Result<ResolveResult, RenewalRefusal>,
    ) -> Result<HomeVerdict, RenewalRefusal> {
        if let Some(hit) = self.lookup(anchor, now)? {
            return Ok(hit);
        }
        let result = resolve()?;
        let record = &result.home.record;
        if record.account_anchor() != anchor {
            return Err(RenewalRefusal::HomeMismatch);
        }
        let hash = record_hash(record).map_err(|_| RenewalRefusal::Storage)?;
        store.check_attachment_home(anchor, record.epoch(), &hash)?;
        let (node, key) = record.home();
        let home_node_key = decode_array(key).ok_or(RenewalRefusal::HomeTrustUnavailable)?;
        let home_record_hash = decode_array(&hash).ok_or(RenewalRefusal::Storage)?;
        let verdict = HomeVerdict {
            account_anchor: anchor.to_owned(),
            home_node: node.to_owned(),
            home_node_key,
            home_epoch: record.epoch(),
            home_record_hash,
            checked_at: now,
        };
        if store.observe_attachment_home(anchor, record.epoch(), &hash, now)?
            == FloorObservation::Advanced
        {
            self.evict(anchor)?;
        }
        self.insert(&hash, &verdict, now)?;
        Ok(verdict)
    }

    /// Fold verified evidence into the floor; an advance evicts every cached verdict
    /// for that anchor.
    /// # Errors
    /// As [`RouterRedbStore::observe_attachment_home`].
    pub fn observe(
        &self,
        store: &RouterRedbStore,
        anchor: &str,
        epoch: u64,
        hash: &str,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        let outcome = store.observe_attachment_home(anchor, epoch, hash, now)?;
        if outcome == FloorObservation::Advanced {
            self.evict(anchor)?;
        }
        Ok(outcome)
    }

    fn lookup(&self, anchor: &str, now: u64) -> Result<Option<HomeVerdict>, RenewalRefusal> {
        let mut cache = self.cache.lock().map_err(|_| RenewalRefusal::Storage)?;
        cache.retain(|_, v| now.saturating_sub(v.checked_at) <= CACHE_TTL);
        Ok(cache
            .iter()
            .filter(|((a, _, _), v)| a == anchor && v.checked_at <= now)
            .max_by_key(|((_, epoch, _), _)| *epoch)
            .map(|(_, v)| v.clone()))
    }

    pub(super) fn insert(
        &self,
        hash: &str,
        verdict: &HomeVerdict,
        now: u64,
    ) -> Result<(), RenewalRefusal> {
        let mut cache = self.cache.lock().map_err(|_| RenewalRefusal::Storage)?;
        cache.retain(|_, v| now.saturating_sub(v.checked_at) <= CACHE_TTL);
        while cache.len() >= MAX_CACHED_VERDICTS {
            let Some(oldest) =
                cache.iter().min_by_key(|(_, v)| v.checked_at).map(|(k, _)| k.clone())
            else {
                break;
            };
            cache.remove(&oldest);
        }
        cache.insert(
            (verdict.account_anchor.clone(), verdict.home_epoch, hash.to_owned()),
            verdict.clone(),
        );
        Ok(())
    }

    fn evict(&self, anchor: &str) -> Result<(), RenewalRefusal> {
        self.cache.lock().map_err(|_| RenewalRefusal::Storage)?.retain(|(a, _, _), _| a != anchor);
        Ok(())
    }
}

fn decode_array(encoded: &str) -> Option<[u8; 32]> {
    ramflux_protocol::decode_base64url(encoded).ok()?.try_into().ok()
}

impl HomeMigrationService {
    /// Current-home verdict for `anchor`, resolving through `peer_node` as the hint.
    /// Dormant: no production caller.
    /// # Errors
    /// As [`AttachmentHomeVerdicts::verdict`]; a failed resolve is `HomeTrustUnavailable`.
    pub fn attachment_home_verdict(
        &self,
        verdicts: &AttachmentHomeVerdicts,
        store: &RouterRedbStore,
        anchor: &str,
        peer_node: &str,
        now: u64,
    ) -> Result<HomeVerdict, RenewalRefusal> {
        verdicts.verdict(store, anchor, now, || {
            let payload = ResolvePayload {
                target_anchor: anchor.to_owned(),
                after_home_hash: None,
                limit: MAX_CHAIN_RECORDS as u64,
                old_node_hint: Some(peer_node.to_owned()),
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            self.latest_migration_home_at(store, now, deadline, &payload, "attachment-verdict")
                .map_err(|e| match e {
                    NodeCoreError::HomeMigration(_) => RenewalRefusal::HomeTrustUnavailable,
                    _ => RenewalRefusal::Storage,
                })
        })
    }
}
