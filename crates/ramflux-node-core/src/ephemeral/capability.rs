// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-memory ephemeral capability map and C1 route gate.

use crate::{SessionLifecycle, lock_unpoisoned};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Arc, Mutex};

/// Inclusive bound for the capability map and for `established_in_boot`.
pub const EPHEMERAL_CAPABILITY_BOUND: usize = 262_144;

static MAP_FULL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// C1 decision for target `T` before any ephemeral forward.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub enum EphemeralRouteGate {
    /// Map entry matches the live S6a descriptor route.
    Online { gateway_id: String, session_id: String },
    /// No S6a descriptor is recorded for `T`.
    Offline,
    /// Capability is absent or does not match the live descriptor route.
    RecipientUnsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityRecord {
    gateway_id: String,
    session_id: String,
    generation: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EphemeralCapabilityState {
    map: HashMap<String, CapabilityRecord>,
    established_in_boot: HashSet<String>,
    next_generation: u64,
}

impl EphemeralCapabilityState {
    fn clear_on_establishment(&mut self, target: &str) {
        self.map.remove(target);
        if self.established_in_boot.contains(target)
            || self.established_in_boot.len() < EPHEMERAL_CAPABILITY_BOUND
        {
            self.established_in_boot.insert(target.to_owned());
        }
    }

    fn stamp(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }

    fn bind(&mut self, target: &str, gateway_id: &str, session_id: &str) -> bool {
        let record = CapabilityRecord {
            gateway_id: gateway_id.to_owned(),
            session_id: session_id.to_owned(),
            generation: self.stamp(),
        };
        if let Some(entry) = self.map.get_mut(target) {
            *entry = record;
            return true;
        }
        if self.map.len() >= EPHEMERAL_CAPABILITY_BOUND {
            MAP_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.map.insert(target.to_owned(), record);
        true
    }
}

#[cfg(test)]
type AfterSessionHook = Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
static AFTER_SESSION: Mutex<Option<(String, AfterSessionHook)>> = Mutex::new(None);

#[cfg(test)]
pub(crate) fn set_route_gate_after_session(target: Option<(&str, AfterSessionHook)>) {
    *lock_unpoisoned(&AFTER_SESSION) = target.map(|(name, hook)| (name.to_owned(), hook));
}

#[cfg(test)]
fn run_after_session_hook(target: &str) {
    let hook = lock_unpoisoned(&AFTER_SESSION)
        .as_ref()
        .and_then(|(name, hook)| (name == target).then(|| Arc::clone(hook)));
    if let Some(hook) = hook {
        hook();
    }
}

impl crate::RouterCore {
    /// W1: every (re)establishment clears `map[T]` and records `T` in this boot.
    pub fn clear_ephemeral_capability(&self, target: &str) {
        lock_unpoisoned(&self.ephemeral_capability).clear_on_establishment(target);
    }

    /// W2: record capability from this registration's own `ephemeral` advertisement.
    pub fn bind_ephemeral_capability(&self, target: &str, gateway_id: &str, session_id: &str) {
        let recorded =
            lock_unpoisoned(&self.ephemeral_capability).bind(target, gateway_id, session_id);
        if !recorded {
            tracing::debug!(
                target_delivery_id = target,
                "ephemeral capability map full; flag not recorded"
            );
        }
    }

    /// C1: capability-gated route for `T`. Lazily drops a stale map entry.
    pub fn route_gate(&self, target: &str) -> EphemeralRouteGate {
        let observed = lock_unpoisoned(&self.ephemeral_capability).map.get(target).cloned();
        let descriptor = self.session(target);
        #[cfg(test)]
        run_after_session_hook(target);
        let mut state = lock_unpoisoned(&self.ephemeral_capability);
        let current = state.map.get(target).cloned();
        if let Some(descriptor) = descriptor.as_ref()
            && descriptor.lifecycle == SessionLifecycle::Live
            && let Some(record) = current.as_ref()
            && record.gateway_id == descriptor.gateway_id
            && record.session_id == descriptor.session_id
        {
            return EphemeralRouteGate::Online {
                gateway_id: record.gateway_id.clone(),
                session_id: record.session_id.clone(),
            };
        }
        if current == observed {
            state.map.remove(target);
        }
        if descriptor.is_none() {
            EphemeralRouteGate::Offline
        } else {
            EphemeralRouteGate::RecipientUnsupported
        }
    }

    /// Inspection: in-memory capability occupancy.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn ephemeral_map_len(&self) -> usize {
        lock_unpoisoned(&self.ephemeral_capability).map.len()
    }

    /// Inspection: whether `target` has a capability map entry.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn ephemeral_map_contains(&self, target: &str) -> bool {
        lock_unpoisoned(&self.ephemeral_capability).map.contains_key(target)
    }

    /// Inspection: occupancy of `established_in_boot`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn established_in_boot_len(&self) -> usize {
        lock_unpoisoned(&self.ephemeral_capability).established_in_boot.len()
    }

    /// Inspection: whether `target` was established in this boot.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn established_in_boot_contains(&self, target: &str) -> bool {
        lock_unpoisoned(&self.ephemeral_capability).established_in_boot.contains(target)
    }
}

#[cfg(test)]
pub(crate) fn map_full_total() -> u64 {
    MAP_FULL_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "hang guards must panic")]
mod tests {
    use super::{
        EPHEMERAL_CAPABILITY_BOUND, EphemeralRouteGate, map_full_total,
        set_route_gate_after_session,
    };
    use crate::{NodeCoreError, RouterCore, RouterRedbStore, SessionDescriptor, SessionLifecycle};
    use redb::{ReadableDatabase, ReadableTable, TableHandle};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn temp_path(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ramflux-s6c-p04-{name}-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn descriptor(target: &str, gateway: &str, session: &str, seq: u64) -> SessionDescriptor {
        SessionDescriptor {
            target_delivery_id: target.to_owned(),
            device_id: "device".to_owned(),
            gateway_id: gateway.to_owned(),
            session_id: session.to_owned(),
            device_epoch: 1,
            session_seq: seq,
            last_cursor: None,
            push_alias_hash: None,
            lifecycle: SessionLifecycle::Live,
        }
    }

    fn bind_live(router: &RouterCore, session: &SessionDescriptor) -> Result<(), NodeCoreError> {
        router.clear_ephemeral_capability(&session.target_delivery_id);
        router.upsert_session(session.clone())?;
        router.mark_live(&session.target_delivery_id)?;
        router.bind_ephemeral_capability(
            &session.target_delivery_id,
            &session.gateway_id,
            &session.session_id,
        );
        Ok(())
    }

    fn capable(router: &RouterCore, target: &str) -> Result<SessionDescriptor, NodeCoreError> {
        let session = descriptor(target, "gateway", "session", 1);
        bind_live(router, &session)?;
        assert_eq!(
            router.route_gate(target),
            EphemeralRouteGate::Online {
                gateway_id: "gateway".into(),
                session_id: "session".into(),
            }
        );
        Ok(session)
    }

    fn assert_no_forward(gate: &EphemeralRouteGate, forwards: &mut u32) {
        if matches!(gate, EphemeralRouteGate::Online { .. }) {
            *forwards = forwards.saturating_add(1);
        }
        assert_eq!(*forwards, 0, "zero forwards");
    }

    fn row_gateway_mismatch_retains_until_c1() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-gw-only")?;
        let mut changed = session.clone();
        changed.gateway_id = "gateway-b".into();
        changed.session_seq = 2;
        router.upsert_session(changed)?;
        router.mark_live(&session.target_delivery_id)?;
        assert!(router.ephemeral_map_contains(&session.target_delivery_id));
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        assert!(!router.ephemeral_map_contains(&session.target_delivery_id));
        Ok(())
    }

    fn row_session_mismatch_retains_until_c1() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-sid-only")?;
        let mut changed = session.clone();
        changed.session_id = "session-b".into();
        changed.session_seq = 2;
        router.upsert_session(changed)?;
        router.mark_live(&session.target_delivery_id)?;
        assert!(router.ephemeral_map_contains(&session.target_delivery_id));
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        assert!(!router.ephemeral_map_contains(&session.target_delivery_id));
        Ok(())
    }

    fn row_stale_lookup_preserves_fresh_bind() -> TestResult {
        let target = format!("target-m1-{}", std::process::id());
        let router = Arc::new(RouterCore::new());
        let initial = descriptor(&target, "gateway", "session", 1);
        bind_live(&router, &initial)?;
        let replacement = descriptor(&target, "gateway", "session-2", 2);
        let entered = Arc::new(Barrier::new(2));
        let released = Arc::new(Barrier::new(2));
        set_route_gate_after_session(Some((
            &target,
            Arc::new({
                let entered = Arc::clone(&entered);
                let released = Arc::clone(&released);
                move || {
                    entered.wait();
                    released.wait();
                }
            }),
        )));
        let clear = ClearHook;
        let (lookup_tx, lookup_rx) = mpsc::channel();
        let lookup_router = Arc::clone(&router);
        let lookup_target = target.clone();
        std::thread::spawn(move || {
            let gate = lookup_router.route_gate(&lookup_target);
            let _ = lookup_tx.send(gate);
        });
        let (work_tx, work_rx) = mpsc::channel();
        let work_router = Arc::clone(&router);
        std::thread::spawn(move || {
            entered.wait();
            work_router.clear_ephemeral_capability(&replacement.target_delivery_id);
            let result = bind_live(&work_router, &replacement);
            released.wait();
            let _ = work_tx.send(result);
        });
        let gate = lookup_rx.recv_timeout(Duration::from_secs(10)).expect("hang guard 10 s");
        work_rx.recv_timeout(Duration::from_secs(10)).expect("hang guard 10 s")?;
        drop(clear);
        assert!(router.ephemeral_map_contains(&target));
        assert_eq!(
            router.route_gate(&target),
            EphemeralRouteGate::Online {
                gateway_id: "gateway".into(),
                session_id: "session-2".into(),
            }
        );
        assert_ne!(
            gate,
            EphemeralRouteGate::Online {
                gateway_id: "gateway".into(),
                session_id: "session-2".into(),
            }
        );
        Ok(())
    }

    fn row_fresh_same_gs_capable_bind_survives_stale_lookup() -> TestResult {
        let target = format!("target-same-gs-{}", std::process::id());
        let router = Arc::new(RouterCore::new());
        let initial = descriptor(&target, "gateway", "session", 1);
        bind_live(&router, &initial)?;
        router.mark_draining(&target)?;
        let resume = descriptor(&target, "gateway", "session", 2);
        let entered = Arc::new(Barrier::new(2));
        let released = Arc::new(Barrier::new(2));
        set_route_gate_after_session(Some((
            &target,
            Arc::new({
                let entered = Arc::clone(&entered);
                let released = Arc::clone(&released);
                move || {
                    entered.wait();
                    released.wait();
                }
            }),
        )));
        let clear = ClearHook;
        let (lookup_tx, lookup_rx) = mpsc::channel();
        let lookup_router = Arc::clone(&router);
        let lookup_target = target.clone();
        std::thread::spawn(move || {
            let gate = lookup_router.route_gate(&lookup_target);
            let _ = lookup_tx.send(gate);
        });
        let (work_tx, work_rx) = mpsc::channel();
        let work_router = Arc::clone(&router);
        std::thread::spawn(move || {
            entered.wait();
            let result = bind_live(&work_router, &resume);
            released.wait();
            let _ = work_tx.send(result);
        });
        let _gate = lookup_rx.recv_timeout(Duration::from_secs(10)).expect("hang guard 10 s");
        work_rx.recv_timeout(Duration::from_secs(10)).expect("hang guard 10 s")?;
        drop(clear);
        assert!(
            router.ephemeral_map_contains(&target),
            "fresh same-(G,S) capable bind removed by stale lookup"
        );
        assert_eq!(
            router.route_gate(&target),
            EphemeralRouteGate::Online {
                gateway_id: "gateway".into(),
                session_id: "session".into(),
            }
        );
        Ok(())
    }

    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            set_route_gate_after_session(None);
        }
    }

    fn row_draining_refuses_and_lazily_removes() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-drain")?;
        router.mark_draining(&session.target_delivery_id)?;
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        assert!(!router.ephemeral_map_contains(&session.target_delivery_id));
        Ok(())
    }

    fn row_removal_offline() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-remove")?;
        let _removed = router
            .target_shard(&session.target_delivery_id)
            .registry
            .remove_target(&session.target_delivery_id);
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::Offline);
        assert_no_forward(&gate, &mut forwards);
        assert!(!router.ephemeral_map_contains(&session.target_delivery_id));
        Ok(())
    }

    fn row_map_full_flag_not_recorded_durable_unaffected() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-kept")?;
        assert_eq!(router.ephemeral_map_len(), 1);
        assert!(router.ephemeral_map_contains("target-kept"));
        for index in 0..EPHEMERAL_CAPABILITY_BOUND {
            if router.ephemeral_map_len() >= EPHEMERAL_CAPABILITY_BOUND {
                break;
            }
            let filler = format!("f{index}");
            router.clear_ephemeral_capability(&filler);
            router.bind_ephemeral_capability(&filler, "g", "s");
        }
        assert_eq!(router.ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
        assert_eq!(router.established_in_boot_len(), EPHEMERAL_CAPABILITY_BOUND);
        let before_full = map_full_total();
        let overflow = descriptor("target-overflow", "gateway", "session-overflow", 1);
        router.clear_ephemeral_capability(&overflow.target_delivery_id);
        router.upsert_session(overflow.clone())?;
        router.mark_live(&overflow.target_delivery_id)?;
        router.bind_ephemeral_capability(
            &overflow.target_delivery_id,
            &overflow.gateway_id,
            &overflow.session_id,
        );
        assert!(map_full_total() > before_full);
        assert_eq!(router.ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
        assert!(!router.ephemeral_map_contains("target-overflow"));
        assert!(!router.established_in_boot_contains("target-overflow"));
        let recorded = router.session("target-overflow").ok_or("durable session")?;
        assert_eq!(recorded.lifecycle, SessionLifecycle::Live);
        assert_eq!(recorded.session_id, overflow.session_id);
        let mut forwards = 0;
        let gate = router.route_gate("target-overflow");
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        assert_eq!(
            router.route_gate(&session.target_delivery_id),
            EphemeralRouteGate::Online {
                gateway_id: session.gateway_id,
                session_id: session.session_id,
            }
        );
        Ok(())
    }

    fn scan_tables_for_capability_state(path: &Path) -> TestResult {
        let db = redb::Database::open(path)?;
        let tx = db.begin_read()?;
        for table in tx.list_tables()? {
            let name = table.name().to_owned();
            assert!(
                !name.contains("ephemeral") && !name.contains("established_in_boot"),
                "capability table {name}"
            );
            let definition = redb::TableDefinition::<&str, &[u8]>::new(name.as_str());
            let Ok(opened) = tx.open_table(definition) else {
                continue;
            };
            for entry in opened.iter()? {
                let (key, value) = entry?;
                let key = key.value();
                let value = String::from_utf8_lossy(value.value());
                assert!(!key.contains("established_in_boot"), "key {key}");
                assert!(!value.contains("established_in_boot"), "value in {name}");
                assert!(!key.contains("ephemeral_capability"), "key {key}");
                assert!(!value.contains("ephemeral_capability"), "value in {name}");
            }
        }
        Ok(())
    }

    fn row_map_and_set_absent_after_reopen() -> TestResult {
        let path = temp_path("reopen");
        let store = RouterRedbStore::open(&path)?;
        let router = RouterCore::new();
        let session = capable(&router, "target-persist")?;
        store.record_session_entry(&session)?;
        store.save_router(&router)?;
        drop(router);
        drop(store);
        scan_tables_for_capability_state(&path)?;
        let store = RouterRedbStore::open(&path)?;
        let restored = store.load_router()?.ok_or("restored router")?;
        assert_eq!(restored.ephemeral_map_len(), 0);
        assert_eq!(restored.established_in_boot_len(), 0);
        assert!(!restored.ephemeral_map_contains(&session.target_delivery_id));
        assert!(!restored.established_in_boot_contains(&session.target_delivery_id));
        let live = restored.session(&session.target_delivery_id).ok_or("restored session")?;
        assert_eq!(live.lifecycle, SessionLifecycle::Live);
        let mut forwards = 0;
        let gate = restored.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        drop(restored);
        drop(store);
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn ephemeral_capability_route_binding() -> TestResult {
        row_fresh_same_gs_capable_bind_survives_stale_lookup()?;
        row_stale_lookup_preserves_fresh_bind()?;
        row_gateway_mismatch_retains_until_c1()?;
        row_session_mismatch_retains_until_c1()?;
        row_draining_refuses_and_lazily_removes()?;
        row_removal_offline()?;
        row_map_full_flag_not_recorded_durable_unaffected()?;
        row_map_and_set_absent_after_reopen()?;
        Ok(())
    }
}
