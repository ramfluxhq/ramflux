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
use std::collections::BTreeMap;

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

/// One floor write: the evidence, the clock, and the two policy knobs.
#[derive(Clone, Copy)]
pub(super) struct FloorWrite<'a> {
    pub anchor: &'a str,
    pub epoch: u64,
    pub hash: &'a str,
    pub now: u64,
    /// Refuse evidence below the floor instead of ignoring it.
    pub strict: bool,
    pub max_anchors: usize,
}
impl<'a> FloorWrite<'a> {
    pub(super) fn new(anchor: &'a str, epoch: u64, hash: &'a str, now: u64, strict: bool) -> Self {
        Self { anchor, epoch, hash, now, strict, max_anchors: MAX_FLOOR_ANCHORS }
    }
}

/// Verdict cache and its generation, shared by every observer of one store. The
/// generation moves on every floor advance made through the store, under the same lock
/// that guards publication, so a verdict is never published across an advance.
#[derive(Default)]
pub(crate) struct VerdictCache {
    generation: u64,
    entries: BTreeMap<(String, u64, String), HomeVerdict>,
}

/// Test seam: called at named points with no lock held.
#[cfg(test)]
pub(crate) type VerdictHook = std::sync::Arc<dyn Fn(&RouterRedbStore, &'static str) + Send + Sync>;

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

    /// Fold verified home evidence into the floor. Older evidence is a no-op.
    /// # Errors
    /// `HomeMismatch` on a fork at the floor epoch, `HomeTrustUnavailable` when a new
    /// anchor would exceed [`MAX_FLOOR_ANCHORS`], `Storage` on a durable failure.
    pub fn observe_attachment_home(
        &self,
        anchor: &str,
        epoch: u64,
        hash: &str,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        self.floor_commit(&FloorWrite::new(anchor, epoch, hash, now, false)).map(|(o, _)| o)
    }

    /// Check and fold in one write transaction: evidence below the floor, or forking
    /// it, is refused instead of being a no-op.
    /// # Errors
    /// As [`Self::observe_attachment_home`], plus `HomeMismatch` below the floor.
    pub fn admit_attachment_home(
        &self,
        anchor: &str,
        epoch: u64,
        hash: &str,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        self.floor_commit(&FloorWrite::new(anchor, epoch, hash, now, true)).map(|(o, _)| o)
    }

    pub(super) fn floor_commit(
        &self,
        write_request: &FloorWrite<'_>,
    ) -> Result<(FloorObservation, u64), RenewalRefusal> {
        let FloorWrite { anchor, epoch, hash, now, strict, max_anchors } = *write_request;
        if !strict {
            // Fast path for the common no-op, without a write transaction.
            if let Some(row) = self.attachment_home_floor(anchor)?
                && (epoch < row.epoch || (epoch == row.epoch && hash == row.record_hash))
            {
                return Ok((FloorObservation::Unchanged, self.floor_generation()?));
            }
        }
        let mut cache = self.attachment_verdicts.lock().map_err(|_| RenewalRefusal::Storage)?;
        let tx = self.begin_write().map_err(refusal_storage)?;
        {
            let table = tx.open_table(FLOOR).map_err(|e| refusal_storage(storage(e)))?;
            let existing: Option<HomeFloor> = table
                .get(anchor)
                .map_err(|e| refusal_storage(storage(e)))?
                .map(|v| decode(v.value()))
                .transpose()
                .map_err(refusal_storage)?;
            match existing {
                Some(row) if epoch < row.epoch => {
                    return if strict {
                        Err(RenewalRefusal::HomeMismatch)
                    } else {
                        Ok((FloorObservation::Unchanged, cache.generation))
                    };
                }
                Some(row) if epoch == row.epoch => {
                    return if hash == row.record_hash {
                        Ok((FloorObservation::Unchanged, cache.generation))
                    } else {
                        Err(RenewalRefusal::HomeMismatch)
                    };
                }
                None if table.len().map_err(|e| refusal_storage(storage(e)))?
                    >= max_anchors as u64 =>
                {
                    return Err(RenewalRefusal::HomeTrustUnavailable);
                }
                _ => {}
            }
        }
        write(
            &tx,
            FLOOR,
            anchor,
            &HomeFloor { epoch, record_hash: hash.to_owned(), observed_at: now },
        )
        .map_err(refusal_storage)?;
        commit_transition(self, tx).map_err(refusal_storage)?;
        cache.generation += 1;
        cache.entries.retain(|(a, _, _), _| a != anchor);
        Ok((FloorObservation::Advanced, cache.generation))
    }

    fn floor_generation(&self) -> Result<u64, RenewalRefusal> {
        Ok(self.attachment_verdicts.lock().map_err(|_| RenewalRefusal::Storage)?.generation)
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

    /// Fold the router's own current head into the floor.
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
        self.observe_attachment_evidence(&head, now)
    }

    /// Fold one verified `RecordEvidence` into the floor.
    /// # Errors
    /// As [`Self::observe_attachment_home`].
    pub fn observe_attachment_evidence(
        &self,
        evidence: &RecordEvidence,
        now: u64,
    ) -> Result<FloorObservation, RenewalRefusal> {
        let hash = record_hash(&evidence.record).map_err(|_| RenewalRefusal::Storage)?;
        self.observe_attachment_home(
            evidence.record.account_anchor(),
            evidence.record.epoch(),
            &hash,
            now,
        )
    }

    /// Resolver hook: every verified `latest_migration_home` result lands in the floor.
    /// A fork or a full floor is the attachment verdict's concern, not a migration
    /// failure; only a durable failure propagates.
    pub(crate) fn observe_attachment_resolved(
        &self,
        result: &ResolveResult,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        match self.observe_attachment_evidence(&result.home, now) {
            Err(RenewalRefusal::Storage) => Err(storage("attachment home floor write failed")),
            _ => Ok(()),
        }
    }

    /// Number of cached verdicts.
    #[must_use]
    pub fn attachment_cached_verdicts(&self) -> usize {
        self.attachment_verdicts.lock().map_or(0, |c| c.entries.len())
    }

    #[cfg(test)]
    fn verdict_hook(&self, point: &'static str) {
        let hook = self.attachment_verdict_hook.lock().ok().and_then(|h| h.clone());
        if let Some(hook) = hook {
            hook(self, point);
        }
    }

    /// Verdict for `anchor`. A cache hit is revalidated against the durable floor; a
    /// miss runs `resolve` (the `latest_migration_home` lookup), then check and floor
    /// advance happen in one transaction, and the verdict is published only if no other
    /// advance happened since.
    /// # Errors
    /// `HomeMismatch` when the head is below or forks the floor or names another anchor,
    /// `HomeTrustUnavailable` when the floor is full, the key is unusable or publication
    /// keeps racing advances, `Storage` on a durable failure, or the resolver's refusal.
    pub fn attachment_home_verdict(
        &self,
        anchor: &str,
        now: u64,
        resolve: impl FnOnce() -> Result<ResolveResult, RenewalRefusal>,
    ) -> Result<HomeVerdict, RenewalRefusal> {
        if let Some(hit) = self.cache_lookup(anchor, now)? {
            let hash = ramflux_protocol::encode_base64url(hit.home_record_hash);
            match self.check_attachment_home(anchor, hit.home_epoch, &hash) {
                Ok(()) => return Ok(hit),
                Err(RenewalRefusal::HomeMismatch) => self.cache_evict(anchor)?,
                Err(other) => return Err(other),
            }
        }
        let result = resolve()?;
        let record = &result.home.record;
        if record.account_anchor() != anchor {
            return Err(RenewalRefusal::HomeMismatch);
        }
        let hash = record_hash(record).map_err(|_| RenewalRefusal::Storage)?;
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
        for _ in 0..3 {
            #[cfg(test)]
            self.verdict_hook("before_admit");
            let (_, generation) =
                self.floor_commit(&FloorWrite::new(anchor, record.epoch(), &hash, now, true))?;
            #[cfg(test)]
            self.verdict_hook("before_publish");
            let mut cache = self.attachment_verdicts.lock().map_err(|_| RenewalRefusal::Storage)?;
            if cache.generation != generation {
                continue;
            }
            cache.entries.retain(|_, v| now.saturating_sub(v.checked_at) <= CACHE_TTL);
            while cache.entries.len() >= MAX_CACHED_VERDICTS {
                let Some(oldest) =
                    cache.entries.iter().min_by_key(|(_, v)| v.checked_at).map(|(k, _)| k.clone())
                else {
                    break;
                };
                cache.entries.remove(&oldest);
            }
            cache.entries.insert((anchor.to_owned(), verdict.home_epoch, hash), verdict.clone());
            return Ok(verdict);
        }
        Err(RenewalRefusal::HomeTrustUnavailable)
    }

    fn cache_lookup(&self, anchor: &str, now: u64) -> Result<Option<HomeVerdict>, RenewalRefusal> {
        let mut cache = self.attachment_verdicts.lock().map_err(|_| RenewalRefusal::Storage)?;
        cache.entries.retain(|_, v| now.saturating_sub(v.checked_at) <= CACHE_TTL);
        Ok(cache
            .entries
            .iter()
            .filter(|((a, _, _), v)| a == anchor && v.checked_at <= now)
            .max_by_key(|((_, epoch, _), _)| *epoch)
            .map(|(_, v)| v.clone()))
    }

    fn cache_evict(&self, anchor: &str) -> Result<(), RenewalRefusal> {
        self.attachment_verdicts
            .lock()
            .map_err(|_| RenewalRefusal::Storage)?
            .entries
            .retain(|(a, _, _), _| a != anchor);
        Ok(())
    }

    /// Test seam: insert directly.
    #[cfg(test)]
    pub(super) fn cache_insert_for_test(&self, hash: &str, verdict: &HomeVerdict) {
        if let Ok(mut c) = self.attachment_verdicts.lock() {
            c.entries.insert(
                (verdict.account_anchor.clone(), verdict.home_epoch, hash.to_owned()),
                verdict.clone(),
            );
        }
    }
}

/// Floor write inside the transaction that saves a home head: every persisted head is
/// verified evidence. A fork, older evidence or a full floor leaves the floor alone.
pub(super) fn record_head_in_tx(
    tx: &redb::WriteTransaction,
    evidence: &RecordEvidence,
) -> Result<(), NodeCoreError> {
    let anchor = evidence.record.account_anchor();
    let epoch = evidence.record.epoch();
    let hash = record_hash(&evidence.record).map_err(storage)?;
    let now = tx
        .open_table(super::CLOCK)
        .map_err(storage)?
        .get("floor")
        .map_err(storage)?
        .map_or(0, |v| v.value());
    {
        let table = tx.open_table(FLOOR).map_err(storage)?;
        let existing: Option<HomeFloor> =
            table.get(anchor).map_err(storage)?.map(|v| decode(v.value())).transpose()?;
        match existing {
            Some(row) if epoch <= row.epoch => return Ok(()),
            None if table.len().map_err(storage)? >= MAX_FLOOR_ANCHORS as u64 => return Ok(()),
            _ => {}
        }
    }
    write(tx, FLOOR, anchor, &HomeFloor { epoch, record_hash: hash, observed_at: now })
}

fn decode_array(encoded: &str) -> Option<[u8; 32]> {
    ramflux_protocol::decode_base64url(encoded).ok()?.try_into().ok()
}

impl HomeMigrationService {
    /// Current-home verdict for `anchor`, resolving through `peer_node` as the hint.
    /// Dormant: no production caller.
    /// # Errors
    /// As [`RouterRedbStore::attachment_home_verdict`]; a failed resolve is
    /// `HomeTrustUnavailable`.
    pub fn attachment_home_verdict(
        &self,
        store: &RouterRedbStore,
        anchor: &str,
        peer_node: &str,
        now: u64,
    ) -> Result<HomeVerdict, RenewalRefusal> {
        store.attachment_home_verdict(anchor, now, || {
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
