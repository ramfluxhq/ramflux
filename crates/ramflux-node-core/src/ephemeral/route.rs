// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile ephemeral replay set (D3). Lives on `RouterCore` outside snapshot/save.

use crate::lock_unpoisoned;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};

/// Inclusive bound: 65,536 live authenticated digests (32 B digest + 8 B D each).
pub const EPHEMERAL_REPLAY_BOUND: usize = 65_536;

/// Bytes of one stored `(digest, D)` tuple. The set stores this once per live marker.
pub const EPHEMERAL_REPLAY_ENTRY_BYTES: usize = 32 + 8;

/// Inclusive retained-tuple budget at [`EPHEMERAL_REPLAY_BOUND`] (fixed costs included).
pub const EPHEMERAL_REPLAY_BUDGET_BYTES: usize =
    EPHEMERAL_REPLAY_BOUND * EPHEMERAL_REPLAY_ENTRY_BYTES;

static SATURATION_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Outcome of inserting one authenticated ephemeral digest until exclusive deadline `D`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum EphemeralReplayAdmit {
    /// Digest was not live; it is now recorded until `D`.
    Fresh,
    /// The same digest is already live (duplicate before `D`).
    Replayed,
    /// The set holds 65,536 live markers; this new digest is refused and no live marker is evicted.
    RateLimited,
    /// Incoming `D` is not live (`now_ms >= D * 1000`); the digest is not recorded.
    /// A stored live marker for the same digest is left in place.
    Expired,
}

/// Domain-separated marker of authenticated source root/device, envelope id and payload hash.
#[must_use]
pub fn ephemeral_replay_digest(
    source_root: &str,
    source_device: &str,
    envelope_id: &str,
    payload_hash: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("ramflux.ephemeral.replay.v1");
    for part in [source_root, source_device, envelope_id, payload_hash] {
        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&len.to_be_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Exclusive live check: a marker survives only while `now_ms < D * 1000`.
fn marker_is_live(now_ms: u64, deadline_unix: u64) -> bool {
    deadline_unix.checked_mul(1_000).is_some_and(|deadline_ms| now_ms < deadline_ms)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EphemeralReplaySet {
    /// Sole `(digest, D)` store: 65,536 × 40 B = 2,621,440 B tuple payload at the bound.
    by_digest: HashMap<[u8; 32], u64>,
    /// Compact expiry index keyed by stored `D` (no second digest copy).
    by_deadline: BTreeSet<u64>,
}

impl EphemeralReplaySet {
    fn expire_due(&mut self, now_ms: u64) {
        let mut dropped_any = false;
        while let Some(&deadline_unix) = self.by_deadline.first() {
            if marker_is_live(now_ms, deadline_unix) {
                break;
            }
            self.by_deadline.pop_first();
            dropped_any = true;
        }
        if dropped_any {
            self.by_digest.retain(|_, stored| marker_is_live(now_ms, *stored));
        }
    }

    fn admit(&mut self, digest: [u8; 32], deadline_unix: u64, now_ms: u64) -> EphemeralReplayAdmit {
        self.expire_due(now_ms);
        if !marker_is_live(now_ms, deadline_unix) {
            return EphemeralReplayAdmit::Expired;
        }
        if self.by_digest.contains_key(&digest) {
            return EphemeralReplayAdmit::Replayed;
        }
        if self.by_digest.len() >= EPHEMERAL_REPLAY_BOUND {
            SATURATION_TOTAL.fetch_add(1, Ordering::Relaxed);
            tracing::debug!("ephemeral replay set full; live marker not evicted");
            return EphemeralReplayAdmit::RateLimited;
        }
        self.by_digest.insert(digest, deadline_unix);
        self.by_deadline.insert(deadline_unix);
        EphemeralReplayAdmit::Fresh
    }

    #[cfg(test)]
    fn contains_live(&self, digest: &[u8; 32], now_ms: u64) -> bool {
        self.by_digest
            .get(digest)
            .is_some_and(|deadline_unix| marker_is_live(now_ms, *deadline_unix))
    }
}

impl crate::RouterCore {
    /// Record or refuse an authenticated ephemeral digest until exclusive deadline `D`.
    pub fn admit_ephemeral_replay(
        &self,
        digest: [u8; 32],
        deadline_unix: u64,
        now_ms: u64,
    ) -> EphemeralReplayAdmit {
        lock_unpoisoned(&self.ephemeral_replay).admit(digest, deadline_unix, now_ms)
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_replay_len(&self) -> usize {
        lock_unpoisoned(&self.ephemeral_replay).by_digest.len()
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_replay_contains_live(&self, digest: &[u8; 32], now_ms: u64) -> bool {
        lock_unpoisoned(&self.ephemeral_replay).contains_live(digest, now_ms)
    }
}

#[cfg(test)]
pub(crate) fn saturation_total() -> u64 {
    SATURATION_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{
        EPHEMERAL_REPLAY_BOUND, EPHEMERAL_REPLAY_BUDGET_BYTES, EPHEMERAL_REPLAY_ENTRY_BYTES,
        EphemeralReplayAdmit, ephemeral_replay_digest, saturation_total,
    };
    use crate::{RouterCore, RouterRedbStore};
    use redb::{ReadableDatabase, ReadableTable, TableHandle};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const DEADLINE_UNIX: u64 = 2_000;
    const NOW_LIVE_MS: u64 = 1_000_000;
    const NOW_AT_D_MS: u64 = 2_000_000;
    const NOW_BEFORE_D_MS: u64 = 1_999_999;

    fn temp_path(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ramflux-s6c-p07-{name}-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn digest(n: u32) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out[28..].copy_from_slice(&n.to_be_bytes());
        out
    }

    fn restarted(router: &RouterCore) -> RouterCore {
        RouterCore::from_snapshot(router.snapshot())
    }

    fn row_digest_is_domain_separated() {
        let a = ephemeral_replay_digest("root", "dev", "env", "hash");
        let b = ephemeral_replay_digest("root", "dev", "env", "hash");
        let c = ephemeral_replay_digest("root", "dev", "env2", "hash");
        let d = ephemeral_replay_digest("rootX", "dev", "env", "hash");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, [0_u8; 32]);
    }

    fn fill(router: &RouterCore, count: usize, now_ms: u64) -> TestResult {
        for n in 0..count {
            let n = u32::try_from(n)?;
            assert_eq!(
                router.admit_ephemeral_replay(digest(n), DEADLINE_UNIX, now_ms),
                EphemeralReplayAdmit::Fresh,
                "digest {n} should be fresh"
            );
        }
        Ok(())
    }

    fn row_bound_accepted() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(router.ephemeral_replay_contains_live(&digest(0), NOW_LIVE_MS));
        assert!(router.ephemeral_replay_contains_live(
            &digest(u32::try_from(EPHEMERAL_REPLAY_BOUND - 1)?),
            NOW_LIVE_MS
        ));
        Ok(())
    }

    fn row_next_refused_without_eviction() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        let before = saturation_total();
        let overflow = u32::try_from(EPHEMERAL_REPLAY_BOUND)?;
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::RateLimited
        );
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(!router.ephemeral_replay_contains_live(&digest(overflow), NOW_LIVE_MS));
        assert!(router.ephemeral_replay_contains_live(&digest(0), NOW_LIVE_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(0), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), EPHEMERAL_REPLAY_BOUND);
        assert!(saturation_total() > before);
        Ok(())
    }

    fn row_duplicate_replayed_from_valid() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(1), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(
            router.admit_ephemeral_replay(digest(1), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
    }

    fn row_live_at_exclusive_lower_ms() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(2), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert!(router.ephemeral_replay_contains_live(&digest(2), NOW_BEFORE_D_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(2), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Replayed
        );
    }

    fn row_expired_incoming_preserves_live_marker() {
        let router = RouterCore::new();
        let x = digest(11);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1005, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1000, NOW_LIVE_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert!(router.ephemeral_replay_contains_live(&x, NOW_LIVE_MS));
        assert_eq!(
            router.admit_ephemeral_replay(x, 1005, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
    }

    fn row_stored_expired_cleanup_still_works() {
        let router = RouterCore::new();
        let x = digest(12);
        assert_eq!(router.admit_ephemeral_replay(x, 1000, 999_000), EphemeralReplayAdmit::Fresh);
        assert_eq!(router.ephemeral_replay_len(), 1);
        assert_eq!(
            router.admit_ephemeral_replay(x, 1000, 1_000_000),
            EphemeralReplayAdmit::Expired
        );
        assert!(!router.ephemeral_replay_contains_live(&x, 1_000_000));
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_expired_at_d_drops_marker() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(3), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert!(router.ephemeral_replay_contains_live(&digest(3), NOW_BEFORE_D_MS));
        assert_eq!(
            router.admit_ephemeral_replay(digest(3), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert!(!router.ephemeral_replay_contains_live(&digest(3), NOW_AT_D_MS));
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_deadline_mul_overflow_expired() {
        let router = RouterCore::new();
        let overflowing = (u64::MAX / 1_000) + 1;
        assert_eq!(
            router.admit_ephemeral_replay(digest(4), overflowing, NOW_LIVE_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
    }

    fn row_retained_bytes_fit_budget() -> TestResult {
        assert_eq!(EPHEMERAL_REPLAY_ENTRY_BYTES, 32 + 8);
        assert_eq!(
            EPHEMERAL_REPLAY_BOUND * EPHEMERAL_REPLAY_ENTRY_BYTES,
            EPHEMERAL_REPLAY_BUDGET_BYTES
        );
        assert_eq!(EPHEMERAL_REPLAY_BUDGET_BYTES, 2_621_440);
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        let retained = router.ephemeral_replay_len() * EPHEMERAL_REPLAY_ENTRY_BYTES;
        assert_eq!(retained, EPHEMERAL_REPLAY_BUDGET_BYTES);
        assert!(retained <= EPHEMERAL_REPLAY_BUDGET_BYTES);
        Ok(())
    }

    fn row_expiry_frees_slot() -> TestResult {
        let router = RouterCore::new();
        fill(&router, EPHEMERAL_REPLAY_BOUND, NOW_LIVE_MS)?;
        let overflow = u32::try_from(EPHEMERAL_REPLAY_BOUND)?;
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
        assert_eq!(
            router.admit_ephemeral_replay(digest(overflow), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(router.ephemeral_replay_len(), 1);
        Ok(())
    }

    fn scan_tables_for_replay_set(path: &Path) -> TestResult {
        let db = redb::Database::open(path)?;
        let tx = db.begin_read()?;
        for table in tx.list_tables()? {
            let name = table.name().to_owned();
            assert!(
                !name.contains("ephemeral_replay") && !name.contains("ephemeral/route"),
                "replay table {name}"
            );
            let definition = redb::TableDefinition::<&str, &[u8]>::new(name.as_str());
            let Ok(opened) = tx.open_table(definition) else {
                continue;
            };
            for entry in opened.iter()? {
                let (key, value) = entry?;
                let key = key.value();
                let value = String::from_utf8_lossy(value.value());
                assert!(!key.contains("ephemeral_replay"), "key {key}");
                assert!(!value.contains("ephemeral_replay"), "value in {name}");
            }
        }
        Ok(())
    }

    fn row_restart_empties_then_duplicate_before_d() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(7), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        let restored = restarted(&router);
        assert_eq!(restored.ephemeral_replay_len(), 0);
        assert!(!restored.ephemeral_replay_contains_live(&digest(7), NOW_LIVE_MS));
        assert_eq!(
            restored.admit_ephemeral_replay(digest(7), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        assert_eq!(restored.ephemeral_replay_len(), 1);
    }

    fn row_repeated_restarts_duplicate_only_before_d() {
        let mut router = RouterCore::new();
        for _ in 0..3 {
            assert_eq!(
                router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_LIVE_MS),
                EphemeralReplayAdmit::Fresh
            );
            router = restarted(&router);
            assert_eq!(router.ephemeral_replay_len(), 0);
        }
        assert_eq!(
            router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_BEFORE_D_MS),
            EphemeralReplayAdmit::Fresh
        );
        router = restarted(&router);
        assert_eq!(
            router.admit_ephemeral_replay(digest(8), DEADLINE_UNIX, NOW_AT_D_MS),
            EphemeralReplayAdmit::Expired
        );
        assert_eq!(router.ephemeral_replay_len(), 0);
        assert!(!router.ephemeral_replay_contains_live(&digest(8), NOW_AT_D_MS));
    }

    fn row_clone_keeps_in_process_markers() {
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(9), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        let cloned = router.clone();
        assert_eq!(cloned.ephemeral_replay_len(), 1);
        assert_eq!(
            cloned.admit_ephemeral_replay(digest(9), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Replayed
        );
    }

    fn row_save_reopen_has_empty_set() -> TestResult {
        let path = temp_path("reopen");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        assert_eq!(
            router.admit_ephemeral_replay(digest(10), DEADLINE_UNIX, NOW_LIVE_MS),
            EphemeralReplayAdmit::Fresh
        );
        store.save_router(&router)?;
        drop(router);
        drop(store);
        scan_tables_for_replay_set(&path)?;
        let store = RouterRedbStore::open(&path)?;
        let restored = store.load_router()?;
        match restored {
            None => {}
            Some(restored) => {
                assert_eq!(restored.ephemeral_replay_len(), 0);
                assert!(!restored.ephemeral_replay_contains_live(&digest(10), NOW_LIVE_MS));
            }
        }
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn ephemeral_replay_saturation() -> TestResult {
        row_digest_is_domain_separated();
        row_bound_accepted()?;
        row_next_refused_without_eviction()?;
        row_duplicate_replayed_from_valid();
        row_expiry_frees_slot()?;
        row_retained_bytes_fit_budget()?;
        Ok(())
    }

    #[test]
    fn ephemeral_restart_window() -> TestResult {
        row_live_at_exclusive_lower_ms();
        row_expired_at_d_drops_marker();
        row_expired_incoming_preserves_live_marker();
        row_stored_expired_cleanup_still_works();
        row_deadline_mul_overflow_expired();
        row_restart_empties_then_duplicate_before_d();
        row_repeated_restarts_duplicate_only_before_d();
        row_clone_keeps_in_process_markers();
        row_save_reopen_has_empty_set()?;
        Ok(())
    }
}
