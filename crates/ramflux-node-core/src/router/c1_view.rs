// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Narrow read-only view of [`RouterCore`] for ephemeral C1 routing.
//!
//! `core` is private so ephemeral modules cannot reach `target_shard`,
//! inbox publication, or other durable sinks.

use super::{RouterCore, lock_unpoisoned};
use crate::{
    EnvelopeAuthorityReason, EphemeralReassertionError, EphemeralRegistrationItem,
    EphemeralReplayAdmit, EphemeralRouteGate, EphemeralRouteResult, NodeCoreError,
    SessionDescriptor,
};
use ramflux_protocol::Envelope;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

/// Inbox and home-node forward occupancy observed around one C1 decision.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EphemeralDispatchObservation {
    pub pending_inbox: usize,
    pub forwarding_reservations: usize,
}

/// Accessors ephemeral modules are allowed to call. Durable persistence
/// methods on [`RouterCore`] are not visible through this type.
pub struct EphemeralRouterView<'a> {
    core: &'a RouterCore,
}

impl RouterCore {
    /// Borrow this router as the narrow ephemeral view.
    #[must_use]
    pub fn ephemeral_view(&self) -> EphemeralRouterView<'_> {
        EphemeralRouterView { core: self }
    }

    /// W1: every (re)establishment clears `map[T]` and records `T` in this boot.
    pub fn clear_ephemeral_capability(&self, target: &str) {
        self.ephemeral_view().clear_ephemeral_capability(target);
    }

    /// W2: record capability from this registration's own `ephemeral` advertisement.
    pub fn bind_ephemeral_capability(&self, target: &str, gateway_id: &str, session_id: &str) {
        self.ephemeral_view().bind_ephemeral_capability(target, gateway_id, session_id);
    }

    /// Process-local boot identifier advertised on the capabilities reply.
    #[must_use]
    pub fn router_boot_id(&self) -> &str {
        &self.router_boot_id
    }

    /// Restore map entries after a restart. Retries are idempotent.
    ///
    /// # Errors
    /// Returns [`EphemeralReassertionError::BootMismatch`] when `boot_id` does not
    /// match this process, or [`EphemeralReassertionError::TooManyItems`] when
    /// `items.len()` exceeds the re-assertion item bound.
    pub fn reassert_ephemeral_registrations(
        &self,
        boot_id: &str,
        items: &[EphemeralRegistrationItem],
    ) -> Result<usize, EphemeralReassertionError> {
        self.ephemeral_view().reassert_ephemeral_registrations(boot_id, items)
    }

    /// C1: capability-gated route for `T`. Lazily drops a stale map entry.
    #[must_use]
    pub fn route_gate(&self, target: &str) -> EphemeralRouteGate {
        self.ephemeral_view().route_gate(target)
    }

    /// Read-only ephemeral route: recompute D, verify source without E1, then C1.
    #[must_use]
    pub fn route_ephemeral(
        &self,
        envelope: &Envelope,
        supplied_expires_at_ms: u64,
        now_ms: u64,
    ) -> EphemeralRouteResult {
        self.ephemeral_view().route_ephemeral(envelope, supplied_expires_at_ms, now_ms)
    }

    /// Record or refuse an authenticated ephemeral digest until exclusive deadline `D`.
    pub fn admit_ephemeral_replay(
        &self,
        digest: [u8; 32],
        deadline_unix: u64,
        now_ms: u64,
    ) -> EphemeralReplayAdmit {
        self.ephemeral_view().admit_ephemeral_replay(digest, deadline_unix, now_ms)
    }
}

impl<'a> EphemeralRouterView<'a> {
    pub(crate) fn session(&self, target: &str) -> Option<SessionDescriptor> {
        self.core.session(target)
    }

    pub(crate) fn boot_id(&self) -> &str {
        &self.core.router_boot_id
    }

    pub(crate) fn capability_state(&self) -> &'a Mutex<crate::ephemeral::EphemeralCapabilityState> {
        &self.core.ephemeral_capability
    }

    pub(crate) fn replay_state(&self) -> &'a Mutex<crate::ephemeral::EphemeralReplaySet> {
        &self.core.ephemeral_replay
    }

    pub(crate) fn target_not_local(&self, target: &str, now_unix_seconds: i64) -> bool {
        self.core.effective_home_node_migration_for_target(target, now_unix_seconds).is_some()
    }

    pub(crate) fn record_route_call(&self) {
        self.core.ephemeral_route_calls.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn authenticate_ephemeral_source(
        &self,
        envelope: &Envelope,
    ) -> Result<(), EphemeralRouteResult> {
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or(EphemeralRouteResult::RootMismatch)?;
        let lookup = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
            .map_err(|_| EphemeralRouteResult::RootMismatch)?;
        let control = lock_unpoisoned(&self.core.control);
        let Some(authority) = control
            .mvp1_identities
            .resolve_device_selector(&lookup)
            .and_then(|identity| control.mvp1_identities.device_auth_key(&identity))
        else {
            return Err(EphemeralRouteResult::RootMismatch);
        };
        match authority.verify_envelope_source(envelope) {
            Ok(_) => Ok(()),
            Err(NodeCoreError::SourceAuthorityRefused {
                reason_code: EnvelopeAuthorityReason::Revoked,
            }) => Err(EphemeralRouteResult::RevokedSource),
            Err(_) => Err(EphemeralRouteResult::RootMismatch),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl RouterCore {
    /// Inspection: in-memory capability occupancy.
    #[must_use]
    pub fn ephemeral_map_len(&self) -> usize {
        self.ephemeral_view().ephemeral_map_len()
    }

    /// Inspection: whether `target` has a capability map entry.
    #[must_use]
    pub fn ephemeral_map_contains(&self, target: &str) -> bool {
        self.ephemeral_view().ephemeral_map_contains(target)
    }

    /// Inspection: occupancy of `established_in_boot`.
    #[must_use]
    pub fn established_in_boot_len(&self) -> usize {
        self.ephemeral_view().established_in_boot_len()
    }

    /// Inspection: whether `target` was established in this boot.
    #[must_use]
    pub fn established_in_boot_contains(&self, target: &str) -> bool {
        self.ephemeral_view().established_in_boot_contains(target)
    }

    /// Durable identities, replay guard and foreign-device heads as observed bytes.
    ///
    /// # Errors
    /// Returns an error when a snapshot field cannot be encoded.
    pub fn ephemeral_durable_snapshot(
        &self,
    ) -> Result<crate::EphemeralDurableSnapshot, NodeCoreError> {
        let snap = self.snapshot();
        Ok(crate::EphemeralDurableSnapshot {
            identities: serde_json::to_vec(&snap.mvp1_identities)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            replay: serde_json::to_vec(&snap.replay_guard_state)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            foreign_device_heads: serde_json::to_vec(&snap.foreign_device_heads)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            sessions: serde_json::to_vec(&snap.registry)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            home_node_migrations: serde_json::to_vec(&snap.home_node_migrations)
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
            local_home_node_id: serde_json::to_vec(&self.local_home_node_id())
                .map_err(|error| NodeCoreError::SnapshotSerialization(error.to_string()))?,
        })
    }

    /// Test-only: record an effective home-node migration for `identity_commitment`.
    pub fn test_put_home_node_migration(
        &self,
        identity_commitment: String,
        record: crate::HomeNodeMigrationRecord,
    ) {
        let mut control = lock_unpoisoned(&self.control);
        control.home_node_migrations.insert(identity_commitment, record);
        self.refresh_migration_read_snapshot_from_control(&control);
    }

    /// Calls into `route_ephemeral` on this process-local router.
    #[must_use]
    pub fn route_ephemeral_call_count(&self) -> u64 {
        self.ephemeral_route_calls.load(Ordering::SeqCst)
    }

    /// Inbox occupancy and home-node forward reservations for `target`.
    #[must_use]
    pub fn ephemeral_dispatch_observation(&self, target: &str) -> EphemeralDispatchObservation {
        EphemeralDispatchObservation {
            pending_inbox: self.pending_entries_for_target(target).len(),
            forwarding_reservations: self
                .forwarding_reservations
                .shards
                .iter()
                .map(|shard| lock_unpoisoned(shard).len())
                .sum(),
        }
    }

    /// Test-only: mark the envelope's registered source device revoked.
    pub fn test_revoke_envelope_source(&self, envelope: &Envelope) {
        let Some(root) =
            envelope.ext.ext.get("source_root_commitment").and_then(serde_json::Value::as_str)
        else {
            return;
        };
        let Ok(lookup) = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
        else {
            return;
        };
        let mut control = lock_unpoisoned(&self.control);
        if let Some(identity) = control.mvp1_identities.resolve_device_selector(&lookup) {
            control.mvp1_identities.revoked_devices.insert(identity.storage_key().to_owned());
        }
    }
}

#[cfg(test)]
impl RouterCore {
    pub(crate) fn ephemeral_replay_len(&self) -> usize {
        self.ephemeral_view().ephemeral_replay_len()
    }

    pub(crate) fn ephemeral_replay_contains_live(&self, digest: &[u8; 32], now_ms: u64) -> bool {
        self.ephemeral_view().ephemeral_replay_contains_live(digest, now_ms)
    }
}
