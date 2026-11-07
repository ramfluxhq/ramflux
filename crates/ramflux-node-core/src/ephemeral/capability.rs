// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! In-memory ephemeral capability map and C1 route gate.

use crate::{SessionLifecycle, lock_unpoisoned};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

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

#[derive(Clone, Debug, Default)]
pub(crate) struct EphemeralCapabilityState {
    map: HashMap<String, (String, String)>,
    established_in_boot: HashSet<String>,
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

    fn bind(&mut self, target: &str, gateway_id: &str, session_id: &str) {
        if let Some(entry) = self.map.get_mut(target) {
            *entry = (gateway_id.to_owned(), session_id.to_owned());
            return;
        }
        if self.map.len() >= EPHEMERAL_CAPABILITY_BOUND {
            MAP_FULL_TOTAL.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target_delivery_id = target,
                "ephemeral capability map full; flag not recorded"
            );
            return;
        }
        self.map.insert(target.to_owned(), (gateway_id.to_owned(), session_id.to_owned()));
    }
}

impl crate::RouterCore {
    /// W1: every (re)establishment clears `map[T]` and records `T` in this boot.
    pub fn clear_ephemeral_capability(&self, target: &str) {
        lock_unpoisoned(&self.ephemeral_capability).clear_on_establishment(target);
    }

    /// W2: record capability from this registration's own `ephemeral` advertisement.
    pub fn bind_ephemeral_capability(&self, target: &str, gateway_id: &str, session_id: &str) {
        lock_unpoisoned(&self.ephemeral_capability).bind(target, gateway_id, session_id);
    }

    /// C1: capability-gated route for `T`. Lazily drops a stale map entry.
    pub fn route_gate(&self, target: &str) -> EphemeralRouteGate {
        let descriptor = self.session(target);
        let mut state = lock_unpoisoned(&self.ephemeral_capability);
        let Some(descriptor) = descriptor else {
            state.map.remove(target);
            return EphemeralRouteGate::Offline;
        };
        if let Some((gateway_id, session_id)) = state.map.get(target).cloned()
            && descriptor.lifecycle == SessionLifecycle::Live
            && gateway_id == descriptor.gateway_id
            && session_id == descriptor.session_id
        {
            EphemeralRouteGate::Online { gateway_id, session_id }
        } else {
            state.map.remove(target);
            EphemeralRouteGate::RecipientUnsupported
        }
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_map_len(&self) -> usize {
        lock_unpoisoned(&self.ephemeral_capability).map.len()
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_map_contains(&self, target: &str) -> bool {
        lock_unpoisoned(&self.ephemeral_capability).map.contains_key(target)
    }

    #[cfg(test)]
    pub(crate) fn established_in_boot_len(&self) -> usize {
        lock_unpoisoned(&self.ephemeral_capability).established_in_boot.len()
    }

    #[cfg(test)]
    pub(crate) fn established_in_boot_contains(&self, target: &str) -> bool {
        lock_unpoisoned(&self.ephemeral_capability).established_in_boot.contains(target)
    }
}

#[cfg(test)]
pub(crate) fn map_full_total() -> u64 {
    MAP_FULL_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{EPHEMERAL_CAPABILITY_BOUND, EphemeralRouteGate, map_full_total};
    use crate::{
        NodeCoreError, RouterCore, RouterRedbStore, SessionDescriptor, SessionLifecycle,
        SessionPushSessionRequest,
    };
    use redb::{ReadableDatabase, ReadableTable, TableHandle};
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

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

    fn establish_legacy(
        router: &RouterCore,
        session: &SessionDescriptor,
    ) -> Result<(), NodeCoreError> {
        router.clear_ephemeral_capability(&session.target_delivery_id);
        router.upsert_session(session.clone())?;
        router.mark_live(&session.target_delivery_id)?;
        Ok(())
    }

    fn establish_capable(
        router: &RouterCore,
        session: &SessionDescriptor,
        ephemeral: bool,
    ) -> Result<(), NodeCoreError> {
        establish_legacy(router, session)?;
        if ephemeral {
            router.bind_ephemeral_capability(
                &session.target_delivery_id,
                &session.gateway_id,
                &session.session_id,
            );
        }
        Ok(())
    }

    fn capable(router: &RouterCore, target: &str) -> Result<SessionDescriptor, NodeCoreError> {
        let session = descriptor(target, "gateway", "session", 1);
        establish_capable(router, &session, true)?;
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

    fn row_resume_without_capability() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-btf")?;
        let mut forwards = 0;
        establish_legacy(
            &router,
            &descriptor(&session.target_delivery_id, &session.gateway_id, &session.session_id, 2),
        )?;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        assert!(!router.ephemeral_map_contains(&session.target_delivery_id));
        Ok(())
    }

    fn row_resume_with_capability_after_legacy() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-reverse")?;
        establish_legacy(
            &router,
            &descriptor(&session.target_delivery_id, &session.gateway_id, &session.session_id, 2),
        )?;
        assert_eq!(
            router.route_gate(&session.target_delivery_id),
            EphemeralRouteGate::RecipientUnsupported
        );
        establish_capable(
            &router,
            &descriptor(&session.target_delivery_id, &session.gateway_id, &session.session_id, 3),
            true,
        )?;
        assert_eq!(
            router.route_gate(&session.target_delivery_id),
            EphemeralRouteGate::Online {
                gateway_id: session.gateway_id,
                session_id: session.session_id,
            }
        );
        Ok(())
    }

    fn row_capable_ephemeral_false_clears() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-false")?;
        let body = json!({
            "target_delivery_id": session.target_delivery_id,
            "device_id": session.device_id,
            "gateway_id": session.gateway_id,
            "session_id": session.session_id,
            "device_epoch": 1,
            "session_seq": 2,
            "last_cursor": null,
            "push_alias_hash": null,
            "lifecycle": "Live",
            "session_push": true
        });
        let request: SessionPushSessionRequest = serde_json::from_value(body)?;
        assert!(!request.ephemeral);
        establish_capable(&router, &request.session, request.ephemeral)?;
        let mut forwards = 0;
        let gate = router.route_gate("target-false");
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        Ok(())
    }

    fn row_legacy_other_gateway_clears() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-other-gw")?;
        establish_legacy(
            &router,
            &descriptor(&session.target_delivery_id, "gateway-b", "session-b", 2),
        )?;
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        let recorded = router.session(&session.target_delivery_id).ok_or("descriptor")?;
        assert_eq!(recorded.gateway_id, "gateway-b");
        assert_eq!(recorded.session_id, "session-b");
        Ok(())
    }

    fn row_new_capable_session_without_ephemeral_same_gateway() -> TestResult {
        let router = RouterCore::new();
        let session = capable(&router, "target-new-session")?;
        establish_capable(
            &router,
            &descriptor(&session.target_delivery_id, &session.gateway_id, "session-2", 2),
            false,
        )?;
        let mut forwards = 0;
        let gate = router.route_gate(&session.target_delivery_id);
        assert_eq!(gate, EphemeralRouteGate::RecipientUnsupported);
        assert_no_forward(&gate, &mut forwards);
        Ok(())
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
        for index in 0..EPHEMERAL_CAPABILITY_BOUND.saturating_sub(1) {
            let filler = format!("f{index}");
            router.clear_ephemeral_capability(&filler);
            router.bind_ephemeral_capability(&filler, "g", "s");
        }
        assert_eq!(router.ephemeral_map_len(), EPHEMERAL_CAPABILITY_BOUND);
        assert_eq!(router.established_in_boot_len(), EPHEMERAL_CAPABILITY_BOUND);
        let before_full = map_full_total();
        let overflow = descriptor("target-overflow", "gateway", "session-overflow", 1);
        establish_capable(&router, &overflow, true)?;
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
        row_resume_without_capability()?;
        row_resume_with_capability_after_legacy()?;
        row_capable_ephemeral_false_clears()?;
        row_legacy_other_gateway_clears()?;
        row_new_capable_session_without_ephemeral_same_gateway()?;
        row_draining_refuses_and_lazily_removes()?;
        row_removal_offline()?;
        row_map_full_flag_not_recorded_durable_unaffected()?;
        row_map_and_set_absent_after_reopen()?;
        Ok(())
    }
}
