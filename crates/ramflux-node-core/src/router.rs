// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    AbuseReportRecord, AccountLifecycleRecord, CursorAckState, DeliveryDecision,
    IdentityLifecycleTombstone, InboxEntry, ItestMvp1DeviceAuthKeyResponse,
    ItestMvp1DeviceManifestResponse, ItestMvp1IdentityRegistrationResponse,
    ItestMvp1IdentityRegistry, ItestMvp1InboxResponse, ItestMvp1PrekeyResponse,
    ItestMvp1PublishPrekeyRequest, ItestMvp1RegisterIdentityRequest, ItestMvp1RevokeDeviceResponse,
    ItestMvp6FriendRequestBudgetRequest, ItestMvp6FriendRequestBudgetResponse,
    ItestMvp10OwnDeviceFanoutDelivery, ItestMvp10OwnDeviceFanoutRequest,
    ItestMvp10OwnDeviceFanoutResponse, ItestRegistrationPolicy, NodeCoreError,
    NodeReplayGuardState, OfflineQueuedDelivery, OnlineDelivery, OpaqueDeviceInbox,
    RouterSubmitOutcome, SessionDescriptor, SessionRegistry, envelope_replay_tuple_key,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ROUTER_TARGET_SHARD_COUNT: usize = 64;
const ROUTER_REPLAY_GUARD_SHARD_COUNT: usize = 64;

#[must_use]
pub fn mvp10_fanout_envelope_id(base_envelope_id: &str, device_id: &str) -> String {
    format!("{}:{}{}:{}", base_envelope_id.len(), base_envelope_id, device_id.len(), device_id)
}

#[derive(Debug)]
pub struct RouterCore {
    pub(crate) target_shards: Vec<Mutex<RouterTargetShard>>,
    envelope_target_index: Mutex<BTreeMap<String, String>>,
    pub(crate) control: Mutex<RouterControlState>,
    pub(crate) replay_guard_shards: Vec<Mutex<NodeReplayGuardState>>,
}

#[derive(Clone, Debug)]
pub struct ReplayAcceptedEnvelope {
    envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug)]
pub struct ReplayAcceptedFanoutDelivery {
    pub device_id: String,
    pub target_delivery_id: String,
    envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug)]
pub struct ReplayAcceptedFanoutPlan {
    pub principal_id: String,
    pub source_device_id: String,
    pub deliveries: Vec<ReplayAcceptedFanoutDelivery>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RouterTargetShard {
    pub(crate) registry: SessionRegistry,
    pub(crate) inbox: OpaqueDeviceInbox,
    pub(crate) deactivated_delivery_targets: BTreeSet<String>,
    pub(crate) deleted_delivery_targets: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RouterControlState {
    pub(crate) mvp1_identities: ItestMvp1IdentityRegistry,
    pub(crate) lifecycle_by_principal: BTreeMap<String, AccountLifecycleRecord>,
    pub(crate) lifecycle_tombstones: BTreeMap<String, IdentityLifecycleTombstone>,
    pub(crate) abuse_reports: BTreeMap<String, AbuseReportRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RouterCoreSnapshot {
    pub(crate) registry: SessionRegistry,
    pub(crate) inbox: OpaqueDeviceInbox,
    pub(crate) mvp1_identities: ItestMvp1IdentityRegistry,
    pub(crate) lifecycle_by_principal: BTreeMap<String, AccountLifecycleRecord>,
    pub(crate) lifecycle_tombstones: BTreeMap<String, IdentityLifecycleTombstone>,
    pub(crate) deactivated_delivery_targets: BTreeSet<String>,
    pub(crate) deleted_delivery_targets: BTreeSet<String>,
    pub(crate) abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub(crate) replay_guard_state: NodeReplayGuardState,
}

impl RouterCore {
    #[must_use]
    pub fn new() -> Self {
        Self::from_snapshot(RouterCoreSnapshot::default())
    }

    #[must_use]
    pub fn registry_snapshot(&self) -> SessionRegistry {
        self.snapshot().registry
    }

    #[must_use]
    pub fn inbox_snapshot(&self) -> OpaqueDeviceInbox {
        self.snapshot().inbox
    }

    #[must_use]
    pub fn mvp1_identities_snapshot(&self) -> ItestMvp1IdentityRegistry {
        lock_unpoisoned(&self.control).mvp1_identities.clone()
    }

    #[must_use]
    pub fn cursor_state(&self, target_delivery_id: &str) -> Option<CursorAckState> {
        self.target_shard(target_delivery_id).inbox.cursor_state(target_delivery_id).cloned()
    }

    #[must_use]
    pub fn session(&self, target_delivery_id: &str) -> Option<SessionDescriptor> {
        self.target_shard(target_delivery_id).registry.session(target_delivery_id).cloned()
    }

    #[must_use]
    pub fn pending_entries_for_target(&self, target_delivery_id: &str) -> Vec<InboxEntry> {
        self.target_shard(target_delivery_id).inbox.pull_after(target_delivery_id, 0, usize::MAX)
    }

    /// # Errors
    /// Returns an error when the identity proof is invalid or the session cannot be bound.
    pub fn mvp1_register_identity(
        &self,
        request: &ItestMvp1RegisterIdentityRequest,
    ) -> Result<ItestMvp1IdentityRegistrationResponse, NodeCoreError> {
        let (mut session, registration_trust_tier) = {
            let mut control = lock_unpoisoned(&self.control);
            control.mvp1_identities.register_identity(request)?
        };
        if let Some(existing) = self
            .target_shard(&session.target_delivery_id)
            .registry
            .session(&session.target_delivery_id)
            && existing.session_id == session.session_id
        {
            session.session_seq = existing.session_seq;
            session.last_cursor.clone_from(&existing.last_cursor);
        }
        self.upsert_session(session)?;
        Ok(ItestMvp1IdentityRegistrationResponse {
            principal_id: request.proof.principal_id.clone(),
            device_id: request.proof.device_id.clone(),
            device_epoch: request.proof.device_epoch,
            target_delivery_id: request.target_delivery_id.clone(),
            session_bound: true,
            registration_trust_tier,
        })
    }

    pub fn mvp6_set_registration_policy(&self, policy: ItestRegistrationPolicy) {
        lock_unpoisoned(&self.control).mvp1_identities.set_registration_policy(policy);
    }

    #[must_use]
    pub fn mvp6_registration_policy(&self) -> ItestRegistrationPolicy {
        lock_unpoisoned(&self.control).mvp1_identities.registration_policy().clone()
    }

    /// # Errors
    /// Returns an error when the request exceeds the tier-specific budget.
    pub fn mvp6_record_friend_request(
        &self,
        request: &ItestMvp6FriendRequestBudgetRequest,
    ) -> Result<ItestMvp6FriendRequestBudgetResponse, NodeCoreError> {
        lock_unpoisoned(&self.control).mvp1_identities.record_friend_request(request)
    }

    /// # Errors
    /// Returns an error when the revocation is not authorized by the principal root key.
    pub fn mvp1_revoke_device(
        &self,
        request: &crate::ItestMvp1RevokeDeviceRequest,
    ) -> Result<ItestMvp1RevokeDeviceResponse, NodeCoreError> {
        let revoked = lock_unpoisoned(&self.control).mvp1_identities.revoke_device(request)?;
        Ok(ItestMvp1RevokeDeviceResponse { device_id: request.device_id.clone(), revoked })
    }

    /// # Errors
    /// Returns an error when the prekey bundle is invalid or the device cannot publish.
    pub fn mvp1_publish_prekey(
        &self,
        request: ItestMvp1PublishPrekeyRequest,
    ) -> Result<ItestMvp1PrekeyResponse, NodeCoreError> {
        let device_id = request.device_id.clone();
        let mut control = lock_unpoisoned(&self.control);
        control.mvp1_identities.publish_prekey(request)?;
        Ok(ItestMvp1PrekeyResponse {
            device_id: device_id.clone(),
            bundle: control.mvp1_identities.prekey_bundle(&device_id).cloned(),
            principal_commitment: control
                .mvp1_identities
                .principal_commitment_for_device(&device_id)
                .unwrap_or_default()
                .to_owned(),
            target_delivery_id: control
                .mvp1_identities
                .target_delivery_id_for_device(&device_id)
                .map(str::to_owned),
        })
    }

    #[must_use]
    pub fn mvp1_prekey(&self, device_id: &str) -> ItestMvp1PrekeyResponse {
        let control = lock_unpoisoned(&self.control);
        ItestMvp1PrekeyResponse {
            device_id: device_id.to_owned(),
            bundle: control.mvp1_identities.prekey_bundle(device_id).cloned(),
            principal_commitment: control
                .mvp1_identities
                .principal_commitment_for_device(device_id)
                .unwrap_or_default()
                .to_owned(),
            target_delivery_id: control
                .mvp1_identities
                .target_delivery_id_for_device(device_id)
                .map(str::to_owned),
        }
    }

    #[must_use]
    pub fn mvp1_device_manifest(
        &self,
        principal_commitment: &str,
    ) -> Option<ItestMvp1DeviceManifestResponse> {
        lock_unpoisoned(&self.control).mvp1_identities.device_manifest(principal_commitment)
    }

    #[must_use]
    pub fn mvp1_device_auth_key(&self, device_id: &str) -> Option<ItestMvp1DeviceAuthKeyResponse> {
        lock_unpoisoned(&self.control).mvp1_identities.device_auth_key(device_id)
    }

    #[must_use]
    pub fn mvp1_inbox(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
    ) -> ItestMvp1InboxResponse {
        ItestMvp1InboxResponse {
            target_delivery_id: target_delivery_id.to_owned(),
            entries: self.resume(target_delivery_id, after_inbox_seq, limit),
        }
    }

    /// # Errors
    /// Returns an error when the source device is not registered under the principal.
    pub fn mvp10_own_device_fanout(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
    ) -> Result<ItestMvp10OwnDeviceFanoutResponse, NodeCoreError> {
        let plan = self.accept_own_device_fanout_replay(request)?;
        let delivered = plan
            .deliveries
            .into_iter()
            .map(|delivery| self.submit_replay_accepted_fanout_delivery(delivery).0)
            .collect();
        Ok(ItestMvp10OwnDeviceFanoutResponse {
            principal_id: plan.principal_id,
            source_device_id: plan.source_device_id,
            delivered,
        })
    }

    /// # Errors
    /// Returns an error when the envelope replay tuple has already been accepted.
    pub fn accept_envelope_replay(
        &self,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<ReplayAcceptedEnvelope, NodeCoreError> {
        self.check_envelope_replay_once(&envelope, now_unix_seconds)?;
        Ok(ReplayAcceptedEnvelope { envelope })
    }

    #[must_use]
    pub fn submit_replay_accepted_envelope(
        &self,
        accepted: ReplayAcceptedEnvelope,
    ) -> RouterSubmitOutcome {
        self.submit_envelope_after_replay_check(accepted.envelope)
    }

    /// # Errors
    /// Returns an error when the source device is not registered under the principal
    /// or the fan-out envelope replay tuple has already been accepted.
    pub fn accept_own_device_fanout_replay(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
    ) -> Result<ReplayAcceptedFanoutPlan, NodeCoreError> {
        let targets = self.mvp10_own_device_targets(&request)?;
        self.check_envelope_replay_once(&request.envelope, request.envelope.created_at)?;
        let deliveries = targets
            .into_iter()
            .map(|(device_id, target_delivery_id)| {
                let mut envelope = request.envelope.clone();
                envelope.target_delivery_id.clone_from(&target_delivery_id);
                envelope.envelope_id =
                    mvp10_fanout_envelope_id(&request.envelope.envelope_id, &device_id);
                ReplayAcceptedFanoutDelivery { device_id, target_delivery_id, envelope }
            })
            .collect();
        Ok(ReplayAcceptedFanoutPlan {
            principal_id: request.principal_id,
            source_device_id: request.source_device_id,
            deliveries,
        })
    }

    #[must_use]
    pub fn submit_replay_accepted_fanout_delivery(
        &self,
        delivery: ReplayAcceptedFanoutDelivery,
    ) -> (ItestMvp10OwnDeviceFanoutDelivery, Option<InboxEntry>) {
        let outcome = self.submit_envelope_after_replay_check(delivery.envelope);
        let (outcome, inbox_seq, entry) = match outcome {
            RouterSubmitOutcome::Online(delivery) => (
                "online".to_owned(),
                Some(delivery.inbox_seq),
                Some(InboxEntry {
                    inbox_seq: delivery.inbox_seq,
                    target_delivery_id: delivery.target_delivery_id,
                    envelope: delivery.envelope,
                }),
            ),
            RouterSubmitOutcome::OfflineQueued(delivery) => {
                ("offline_queued".to_owned(), Some(delivery.entry.inbox_seq), Some(delivery.entry))
            }
            RouterSubmitOutcome::RejectedDeactivated { .. } => {
                ("rejected_deactivated".to_owned(), None, None)
            }
            RouterSubmitOutcome::RejectedDeleted { .. } => {
                ("rejected_deleted".to_owned(), None, None)
            }
            RouterSubmitOutcome::RejectedSecurity { .. } => {
                ("rejected_security".to_owned(), None, None)
            }
        };
        (
            ItestMvp10OwnDeviceFanoutDelivery {
                device_id: delivery.device_id,
                target_delivery_id: delivery.target_delivery_id,
                outcome,
                inbox_seq,
            },
            entry,
        )
    }

    fn mvp10_own_device_targets(
        &self,
        request: &ItestMvp10OwnDeviceFanoutRequest,
    ) -> Result<Vec<(String, String)>, NodeCoreError> {
        let control = lock_unpoisoned(&self.control);
        if control
            .mvp1_identities
            .devices
            .get(&request.source_device_id)
            .is_none_or(|device| device.principal_id != request.principal_id)
        {
            return Err(NodeCoreError::ItestHttp(format!(
                "source device is not registered for principal: {}",
                request.source_device_id
            )));
        }
        Ok(control
            .mvp1_identities
            .active_own_device_targets(&request.principal_id, &request.source_device_id))
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn upsert_session(&self, descriptor: SessionDescriptor) -> Result<(), NodeCoreError> {
        self.target_shard(&descriptor.target_delivery_id).registry.upsert_session(descriptor)
    }

    /// # Errors
    /// Returns an error when the target session does not exist.
    pub fn mark_live(&self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.target_shard(target_delivery_id).registry.mark_live(target_delivery_id)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_draining(&self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.target_shard(target_delivery_id).registry.mark_draining(target_delivery_id)
    }

    /// # Errors
    /// Returns an error when the target session does not exist.
    pub fn close_session(&self, target_delivery_id: &str) -> Result<(), NodeCoreError> {
        self.target_shard(target_delivery_id).registry.close_session(target_delivery_id)
    }

    pub fn submit_envelope(&self, envelope: ramflux_protocol::Envelope) -> RouterSubmitOutcome {
        let now = envelope.created_at;
        self.submit_envelope_at(envelope, now)
    }

    pub fn submit_envelope_at(
        &self,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> RouterSubmitOutcome {
        if let Err(error) = self.check_envelope_replay_once(&envelope, now_unix_seconds) {
            return RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id: envelope.target_delivery_id,
                reason: error.to_string(),
            };
        }
        self.submit_envelope_after_replay_check(envelope)
    }

    fn submit_envelope_after_replay_check(
        &self,
        envelope: ramflux_protocol::Envelope,
    ) -> RouterSubmitOutcome {
        let mut shard = self.target_shard(&envelope.target_delivery_id);
        if shard.deleted_delivery_targets.contains(&envelope.target_delivery_id) {
            return RouterSubmitOutcome::RejectedDeleted {
                target_delivery_id: envelope.target_delivery_id,
            };
        }
        if shard.deactivated_delivery_targets.contains(&envelope.target_delivery_id) {
            return RouterSubmitOutcome::RejectedDeactivated {
                target_delivery_id: envelope.target_delivery_id,
            };
        }
        match shard.registry.route_envelope(&envelope) {
            DeliveryDecision::Online { gateway_id, session_id, target_delivery_id } => {
                crate::record_router_envelope_accepted();
                let entry = shard.inbox.append(envelope.clone());
                self.index_envelope_target(&entry);
                RouterSubmitOutcome::Online(OnlineDelivery {
                    gateway_id,
                    session_id,
                    target_delivery_id,
                    inbox_seq: entry.inbox_seq,
                    envelope,
                })
            }
            DeliveryDecision::OfflineWake(wake_hint) => {
                crate::record_router_envelope_accepted();
                let entry = shard.inbox.append(envelope);
                self.index_envelope_target(&entry);
                RouterSubmitOutcome::OfflineQueued(OfflineQueuedDelivery { entry, wake_hint })
            }
        }
    }

    #[must_use]
    pub fn resume(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
    ) -> Vec<InboxEntry> {
        self.target_shard(target_delivery_id).inbox.pull_after(
            target_delivery_id,
            after_inbox_seq,
            limit,
        )
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_ack(&self, ack: &ramflux_protocol::Ack) -> Result<CursorAckState, NodeCoreError> {
        crate::record_router_ack();
        let target_delivery_id = self
            .indexed_target_for_envelope(&ack.envelope_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()))?;
        self.target_shard(&target_delivery_id).inbox.apply_ack(ack)
    }

    /// # Errors
    /// Returns an error when the envelope is unknown or does not belong to `target_delivery_id`.
    pub fn apply_ack_for_target(
        &self,
        target_delivery_id: &str,
        ack: &ramflux_protocol::Ack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let actual_target_delivery_id = self
            .indexed_target_for_envelope(&ack.envelope_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()))?;
        if actual_target_delivery_id != target_delivery_id {
            return Err(NodeCoreError::EnvelopeTargetMismatch {
                envelope_id: ack.envelope_id.clone(),
                expected_target_delivery_id: target_delivery_id.to_owned(),
                actual_target_delivery_id,
            });
        }
        self.apply_ack(ack)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_nack(
        &self,
        nack: &ramflux_protocol::Nack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let target_delivery_id = self
            .indexed_target_for_envelope(&nack.envelope_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(nack.envelope_id.clone()))?;
        self.target_shard(&target_delivery_id).inbox.apply_nack(nack)
    }

    /// # Errors
    /// Returns an error when the envelope is unknown or does not belong to `target_delivery_id`.
    pub fn apply_nack_for_target(
        &self,
        target_delivery_id: &str,
        nack: &ramflux_protocol::Nack,
    ) -> Result<CursorAckState, NodeCoreError> {
        let actual_target_delivery_id = self
            .indexed_target_for_envelope(&nack.envelope_id)
            .ok_or_else(|| NodeCoreError::EnvelopeNotFound(nack.envelope_id.clone()))?;
        if actual_target_delivery_id != target_delivery_id {
            return Err(NodeCoreError::EnvelopeTargetMismatch {
                envelope_id: nack.envelope_id.clone(),
                expected_target_delivery_id: target_delivery_id.to_owned(),
                actual_target_delivery_id,
            });
        }
        self.apply_nack(nack)
    }

    /// Returns the indexed target for an envelope, including entries restored from pending inbox
    /// rows and cursor ack/nack state.
    #[must_use]
    pub fn target_for_envelope_id(&self, envelope_id: &str) -> Option<String> {
        self.indexed_target_for_envelope(envelope_id)
    }

    pub(crate) fn snapshot(&self) -> RouterCoreSnapshot {
        let mut snapshot = RouterCoreSnapshot {
            registry: SessionRegistry::new(),
            inbox: OpaqueDeviceInbox::new(),
            ..RouterCoreSnapshot::default()
        };
        for shard in &self.replay_guard_shards {
            for (key, expires_at) in lock_unpoisoned(shard).accepted_entries() {
                snapshot.replay_guard_state.restore_accepted(key.clone(), *expires_at);
            }
        }
        {
            let control = lock_unpoisoned(&self.control);
            snapshot.mvp1_identities = control.mvp1_identities.clone();
            snapshot.lifecycle_by_principal = control.lifecycle_by_principal.clone();
            snapshot.lifecycle_tombstones = control.lifecycle_tombstones.clone();
            snapshot.abuse_reports = control.abuse_reports.clone();
        }
        for shard in &self.target_shards {
            let shard = lock_unpoisoned(shard);
            snapshot.registry.merge_from(&shard.registry);
            snapshot.inbox.merge_from(&shard.inbox);
            snapshot
                .deactivated_delivery_targets
                .extend(shard.deactivated_delivery_targets.iter().cloned());
            snapshot
                .deleted_delivery_targets
                .extend(shard.deleted_delivery_targets.iter().cloned());
        }
        snapshot
    }

    pub(crate) fn from_snapshot(snapshot: RouterCoreSnapshot) -> Self {
        let target_shards = (0..ROUTER_TARGET_SHARD_COUNT)
            .map(|_index| Mutex::new(RouterTargetShard::default()))
            .collect::<Vec<_>>();
        let replay_guard_shards = (0..ROUTER_REPLAY_GUARD_SHARD_COUNT)
            .map(|_index| Mutex::new(NodeReplayGuardState::new()))
            .collect::<Vec<_>>();
        let router = Self {
            target_shards,
            envelope_target_index: Mutex::new(BTreeMap::new()),
            control: Mutex::new(RouterControlState {
                mvp1_identities: snapshot.mvp1_identities,
                lifecycle_by_principal: snapshot.lifecycle_by_principal,
                lifecycle_tombstones: snapshot.lifecycle_tombstones,
                abuse_reports: snapshot.abuse_reports,
            }),
            replay_guard_shards,
        };
        for (key, expires_at) in snapshot.replay_guard_state.accepted_entries() {
            let index = replay_guard_shard_index(key);
            lock_unpoisoned(&router.replay_guard_shards[index])
                .restore_accepted(key.clone(), *expires_at);
        }
        for session in snapshot.registry.sessions() {
            router
                .target_shard(&session.target_delivery_id)
                .registry
                .restore_session(session.clone());
        }
        for entry in snapshot.inbox.pending_entries().cloned().collect::<Vec<_>>() {
            router.index_envelope_target(&entry);
            router.target_shard(&entry.target_delivery_id).inbox.restore_pending_entry(entry);
        }
        for cursor in snapshot.inbox.cursor_states().cloned().collect::<Vec<_>>() {
            router.index_cursor_targets(&cursor);
            router.target_shard(&cursor.target_delivery_id).inbox.restore_cursor_state(cursor);
        }
        for target in snapshot.deactivated_delivery_targets {
            router.target_shard(&target).deactivated_delivery_targets.insert(target);
        }
        for target in snapshot.deleted_delivery_targets {
            router.target_shard(&target).deleted_delivery_targets.insert(target);
        }
        router
    }

    pub fn merge_restored_router(&self, restored: &RouterCore) {
        let snapshot = restored.snapshot();
        {
            let mut control = lock_unpoisoned(&self.control);
            control.lifecycle_by_principal.extend(snapshot.lifecycle_by_principal);
            control.lifecycle_tombstones.extend(snapshot.lifecycle_tombstones);
            control.abuse_reports.extend(snapshot.abuse_reports);
        }
        {
            for (key, expires_at) in snapshot.replay_guard_state.accepted_entries() {
                let index = replay_guard_shard_index(key);
                lock_unpoisoned(&self.replay_guard_shards[index])
                    .restore_accepted(key.clone(), *expires_at);
            }
        }
        for session in snapshot.registry.sessions() {
            self.target_shard(&session.target_delivery_id)
                .registry
                .restore_session(session.clone());
        }
        for entry in snapshot.inbox.pending_entries().cloned().collect::<Vec<_>>() {
            self.index_envelope_target(&entry);
            self.target_shard(&entry.target_delivery_id).inbox.restore_pending_entry(entry);
        }
        for cursor in snapshot.inbox.cursor_states().cloned().collect::<Vec<_>>() {
            self.index_cursor_targets(&cursor);
            self.target_shard(&cursor.target_delivery_id).inbox.restore_cursor_state(cursor);
        }
        for target in snapshot.deactivated_delivery_targets {
            self.target_shard(&target).deactivated_delivery_targets.insert(target);
        }
        for target in snapshot.deleted_delivery_targets {
            self.target_shard(&target).deleted_delivery_targets.insert(target);
        }
    }

    fn check_envelope_replay_once(
        &self,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
        crate::record_router_replay_guard_check();
        let replay_check_started = Instant::now();
        let replay_key = envelope_replay_tuple_key(envelope);
        let replay_check =
            lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                .check_envelope(envelope, now_unix_seconds);
        crate::record_router_replay_guard_check_us(elapsed_us(replay_check_started));
        replay_check
    }

    pub(crate) fn target_shard(
        &self,
        target_delivery_id: &str,
    ) -> MutexGuard<'_, RouterTargetShard> {
        let index = target_shard_index(target_delivery_id);
        lock_unpoisoned(&self.target_shards[index])
    }

    fn index_envelope_target(&self, entry: &InboxEntry) {
        lock_unpoisoned(&self.envelope_target_index)
            .insert(entry.envelope.envelope_id.clone(), entry.target_delivery_id.clone());
    }

    fn index_cursor_targets(&self, cursor: &CursorAckState) {
        let mut index = lock_unpoisoned(&self.envelope_target_index);
        for envelope_id in &cursor.acked_envelope_ids {
            index.insert(envelope_id.clone(), cursor.target_delivery_id.clone());
        }
        for envelope_id in cursor.nacked_envelope_ids.keys() {
            index.insert(envelope_id.clone(), cursor.target_delivery_id.clone());
        }
    }

    pub(crate) fn remove_target_index(&self, target_delivery_id: &str) {
        lock_unpoisoned(&self.envelope_target_index)
            .retain(|_envelope_id, target| target != target_delivery_id);
    }

    fn indexed_target_for_envelope(&self, envelope_id: &str) -> Option<String> {
        lock_unpoisoned(&self.envelope_target_index).get(envelope_id).cloned()
    }
}

impl Default for RouterCore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RouterCore {
    fn clone(&self) -> Self {
        Self::from_snapshot(self.snapshot())
    }
}

impl PartialEq for RouterCore {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot() == other.snapshot()
    }
}

impl Eq for RouterCore {}

fn target_shard_index(target_delivery_id: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    target_delivery_id.hash(&mut hasher);
    let shard_count = u64::try_from(ROUTER_TARGET_SHARD_COUNT).unwrap_or(1);
    let index = hasher.finish() % shard_count;
    usize::try_from(index).unwrap_or(0)
}

fn replay_guard_shard_index(replay_key: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    replay_key.hash(&mut hasher);
    let shard_count = u64::try_from(ROUTER_REPLAY_GUARD_SHARD_COUNT).unwrap_or(1);
    let index = hasher.finish() % shard_count;
    usize::try_from(index).unwrap_or(0)
}

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
