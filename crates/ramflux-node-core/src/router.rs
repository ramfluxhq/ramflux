// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    AbuseReportRecord, AccountLifecycleRecord, CursorAckState, DeliveryDecision,
    DeviceAuthKeyResponse, DeviceManifestResponse, DeviceRevokeResponse,
    FederatedEnvelopeForwardResponse, FriendRequestBudgetRequest, FriendRequestBudgetResponse,
    HomeNodeMigratedNackDelivery, HomeNodeMigrationForwardDelivery, HomeNodeMigrationForwardPlan,
    HomeNodeMigrationRecord, HomeNodeRouteRecord, HomeNodeRouteUpdateProof,
    IdentityLifecycleTombstone, IdentityLineageEventRecord, IdentityRegisterRequest,
    IdentityRegistrationResponse, IdentityRegistry, InboxEntry, InboxFetchResponse,
    ItestMvp10OwnDeviceFanoutDelivery, ItestMvp10OwnDeviceFanoutRequest,
    ItestMvp10OwnDeviceFanoutResponse, NodeCoreError, NodeReplayGuardState, NodeServiceSigningKey,
    OfflineQueuedDelivery, OnlineDelivery, OpaqueDeviceInbox, PrekeyPublishRequest, PrekeyResponse,
    RegistrationPolicy, RouterSubmitOutcome, SessionDescriptor, SessionRegistry,
    envelope_replay_tuple_key,
};
use arc_swap::ArcSwap;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod ack_batch;
mod committed_forward;
mod retention;

const ROUTER_TARGET_SHARD_COUNT: usize = 64;
const ROUTER_REPLAY_GUARD_SHARD_COUNT: usize = 64;
const ROUTER_ENVELOPE_TARGET_INDEX_SHARD_COUNT: usize = 64;
// Old-home attempts expire after 20 s; bounded forwarding uses <= 3 s DNS + 12 s IO.
// New-home Pending is 142 s (twice the 71 s router-post bound), so retries deduplicate.
const DEFAULT_FORWARD_RESERVATION_LEASE_SECONDS: u64 = 20;

#[must_use]
pub fn mvp10_fanout_envelope_id(base_envelope_id: &str, device_id: &str) -> String {
    format!("{}:{}{}:{}", base_envelope_id.len(), base_envelope_id, device_id.len(), device_id)
}

/// Source trust supplied by the server's authenticated transport peer, never an envelope field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterEnvelopeOrigin {
    Gateway,
    Federation,
}

#[derive(Debug)]
pub struct RouterCore {
    pub(crate) target_shards: Vec<Arc<Mutex<RouterTargetShard>>>,
    envelope_target_index_shards: Vec<Arc<Mutex<BTreeMap<String, String>>>>,
    forwarding_reservations: Arc<ForwardingReservations>,
    pub(crate) control: Mutex<RouterControlState>,
    migration_read_snapshot: ArcSwap<RouterMigrationReadSnapshot>,
    pub(crate) replay_guard_shards: Vec<Arc<Mutex<NodeReplayGuardState>>>,
    node_service_signer: Mutex<Option<NodeServiceSigningKey>>,
    local_home_node_id: Mutex<Option<String>>,
    publication: std::sync::OnceLock<Arc<crate::router_store::publication::PublicationCore>>,
}

#[derive(Debug)]
struct ForwardingReservations {
    shards: Vec<Mutex<HashMap<String, ForwardingReservationState>>>,
    next_attempt_id: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
struct ForwardingReservationState {
    attempt_id: u64,
    lease_until: i64,
}

#[derive(Debug)]
pub enum RouterForwardPreparation {
    Complete(Box<RouterSubmitOutcome>),
    Forward(Box<RouterForwardReservation>),
}

#[derive(Debug)]
pub struct RouterForwardReservation {
    reservations: Arc<ForwardingReservations>,
    shard_index: usize,
    key: String,
    attempt_id: u64,
    target_delivery_id: String,
    envelope: Option<ramflux_protocol::Envelope>,
    migration: HomeNodeMigrationRecord,
    plan: Option<HomeNodeMigrationForwardPlan>,
    replayed: bool,
    now_unix_seconds: i64,
}

impl RouterForwardReservation {
    #[must_use]
    pub fn plan(&self) -> Option<&HomeNodeMigrationForwardPlan> {
        self.plan.as_ref()
    }

    #[must_use]
    pub fn target_delivery_id(&self) -> &str {
        &self.target_delivery_id
    }
}

impl Drop for RouterForwardReservation {
    fn drop(&mut self) {
        let mut reservations = lock_unpoisoned(&self.reservations.shards[self.shard_index]);
        if reservations.get(&self.key).is_some_and(|state| state.attempt_id == self.attempt_id) {
            reservations.remove(&self.key);
        }
    }
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
    #[serde(skip)]
    principal_lookup_limiter: crate::principal_directory::PrincipalLookupLimiter,
    pub(crate) mvp1_identities: IdentityRegistry,
    #[serde(default)]
    pub(crate) foreign_device_heads: crate::foreign_device_heads::ForeignDeviceHeads,
    pub(crate) lifecycle_by_principal: BTreeMap<String, AccountLifecycleRecord>,
    pub(crate) lifecycle_tombstones: BTreeMap<String, IdentityLifecycleTombstone>,
    pub(crate) identity_lineage_events: BTreeMap<String, Vec<IdentityLineageEventRecord>>,
    pub(crate) identity_lineage_heads: BTreeMap<String, String>,
    pub(crate) abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub(crate) node_franking_public_key: Option<String>,
    pub(crate) home_node_migrations: BTreeMap<String, HomeNodeMigrationRecord>,
    pub(crate) home_node_routes: BTreeMap<String, HomeNodeRouteRecord>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RouterMigrationReadSnapshot {
    identity_keys_by_target: BTreeMap<String, Vec<String>>,
    home_node_migrations: BTreeMap<String, HomeNodeMigrationRecord>,
}

impl RouterMigrationReadSnapshot {
    fn from_control(control: &RouterControlState) -> Self {
        let mut identity_keys_by_target = BTreeMap::new();
        for target_delivery_id in control
            .mvp1_identities
            .devices
            .values()
            .map(|device| device.target_delivery_id.as_str())
            .collect::<BTreeSet<_>>()
        {
            let keys =
                control.mvp1_identities.identity_keys_for_target_delivery_id(target_delivery_id);
            if !keys.is_empty() {
                identity_keys_by_target.insert(target_delivery_id.to_owned(), keys);
            }
        }
        Self { identity_keys_by_target, home_node_migrations: control.home_node_migrations.clone() }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RouterCoreSnapshot {
    pub(crate) registry: SessionRegistry,
    pub(crate) inbox: OpaqueDeviceInbox,
    pub(crate) mvp1_identities: IdentityRegistry,
    #[serde(default)]
    pub(crate) foreign_device_heads: crate::foreign_device_heads::ForeignDeviceHeads,
    pub(crate) lifecycle_by_principal: BTreeMap<String, AccountLifecycleRecord>,
    pub(crate) lifecycle_tombstones: BTreeMap<String, IdentityLifecycleTombstone>,
    pub(crate) identity_lineage_events: BTreeMap<String, Vec<IdentityLineageEventRecord>>,
    pub(crate) identity_lineage_heads: BTreeMap<String, String>,
    pub(crate) deactivated_delivery_targets: BTreeSet<String>,
    pub(crate) deleted_delivery_targets: BTreeSet<String>,
    pub(crate) abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub(crate) replay_guard_state: NodeReplayGuardState,
    pub(crate) node_franking_public_key: Option<String>,
    pub(crate) home_node_migrations: BTreeMap<String, HomeNodeMigrationRecord>,
    pub(crate) home_node_routes: BTreeMap<String, HomeNodeRouteRecord>,
}

impl RouterCore {
    pub(crate) fn publication_is_bound(&self) -> bool {
        self.publication.get().is_some()
    }

    /// Install the store-owned publication authority before serving this router.
    /// # Errors
    /// Returns store initialization failures.
    pub fn bind_publication(&self, store: &crate::RouterRedbStore) -> Result<(), NodeCoreError> {
        let core = store.publication_core()?;
        if let Some(installed) = self.publication.get() {
            return if Arc::ptr_eq(installed, &core) {
                Ok(())
            } else {
                Err(NodeCoreError::Redb("router belongs to another publication store".into()))
            };
        }
        let _ = self.publication.set(Arc::clone(&core));
        let targets = self.target_shards.iter().map(Arc::downgrade).collect::<Vec<_>>();
        let indexes =
            self.envelope_target_index_shards.iter().map(Arc::downgrade).collect::<Vec<_>>();
        let replays = self.replay_guard_shards.iter().map(Arc::downgrade).collect::<Vec<_>>();
        core.install_cleanup(
            Arc::new(move |target, seq| {
                if let Some(shard) = targets[target_shard_index(target)].upgrade() {
                    let entry = lock_unpoisoned(&shard).inbox.retire_pending(target, seq);
                    if let Some(entry) = entry
                        && let Some(index) = indexes
                            [envelope_target_index_shard_index(&entry.envelope.envelope_id)]
                        .upgrade()
                    {
                        lock_unpoisoned(&index).remove(&entry.envelope.envelope_id);
                    }
                }
            }),
            Arc::new(move |resource| {
                if let Some(replay) = replays[replay_guard_shard_index(resource)].upgrade() {
                    lock_unpoisoned(&replay).retain_keys(|key| key != resource);
                }
            }),
        );
        for shard in &self.target_shards {
            lock_unpoisoned(shard).inbox.publication = Some(Arc::clone(&core));
        }
        Ok(())
    }

    /// Initialize durable identity before entering allocation synchronization.
    /// # Errors
    /// Returns identity or publication initialization failures.
    pub fn prepare_publication_target(
        &self,
        store: &crate::RouterRedbStore,
        target: &str,
    ) -> Result<(), NodeCoreError> {
        self.bind_publication(store)?;
        if self.target_shard(target).deleted_delivery_targets.contains(target) {
            return Ok(());
        }
        let id = store.provisional_inbox_incarnation(target)?;
        self.target_shard(target).inbox.restore_incarnation(target, id);
        Ok(())
    }

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
    pub fn mvp1_identities_snapshot(&self) -> IdentityRegistry {
        lock_unpoisoned(&self.control).mvp1_identities.clone()
    }

    #[must_use]
    pub fn identity_lineage_events(&self, principal_id: &str) -> Vec<IdentityLineageEventRecord> {
        lock_unpoisoned(&self.control)
            .identity_lineage_events
            .get(principal_id)
            .cloned()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn identity_lineage_head(&self, principal_id: &str) -> Option<String> {
        lock_unpoisoned(&self.control).identity_lineage_heads.get(principal_id).cloned()
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

    pub fn set_node_franking_public_key(&self, public_key_base64url: Option<String>) {
        crate::lock_unpoisoned(&self.control).node_franking_public_key = public_key_base64url;
    }

    #[must_use]
    pub fn node_franking_public_key(&self) -> Option<String> {
        crate::lock_unpoisoned(&self.control).node_franking_public_key.clone()
    }

    pub fn set_node_service_signer(&self, signer: Option<NodeServiceSigningKey>) {
        *lock_unpoisoned(&self.node_service_signer) = signer;
    }

    pub(crate) fn node_service_signer(&self) -> Option<NodeServiceSigningKey> {
        lock_unpoisoned(&self.node_service_signer).clone()
    }

    pub fn set_local_home_node_id(&self, node_id: Option<String>) {
        *lock_unpoisoned(&self.local_home_node_id) = node_id;
    }

    fn local_home_node_id(&self) -> Option<String> {
        lock_unpoisoned(&self.local_home_node_id).clone()
    }

    #[must_use]
    pub fn home_node_migration(
        &self,
        identity_commitment: &str,
    ) -> Option<HomeNodeMigrationRecord> {
        lock_unpoisoned(&self.control).home_node_migrations.get(identity_commitment).cloned()
    }

    #[must_use]
    pub fn resolve_home_node_route(
        &self,
        identity_commitment: &str,
    ) -> Option<HomeNodeRouteRecord> {
        lock_unpoisoned(&self.control).home_node_routes.get(identity_commitment).cloned()
    }

    /// # Errors
    /// Returns an error when the identity proof is invalid or the session cannot be bound.
    pub fn mvp1_register_identity(
        &self,
        request: &IdentityRegisterRequest,
    ) -> Result<IdentityRegistrationResponse, NodeCoreError> {
        self.register_identity_with_store(request, None)
    }
    /// Register root-bound keys and persist their authority before making them visible.
    /// # Errors
    /// Rejects invalid registrations or storage failures before publishing the new authority.
    pub fn register_identity_durable(
        &self,
        request: &IdentityRegisterRequest,
        store: &crate::RouterRedbStore,
    ) -> Result<IdentityRegistrationResponse, NodeCoreError> {
        self.register_identity_with_store(request, Some(store))
    }
    fn register_identity_with_store(
        &self,
        request: &IdentityRegisterRequest,
        store: Option<&crate::RouterRedbStore>,
    ) -> Result<IdentityRegistrationResponse, NodeCoreError> {
        let registration_trust_tier = {
            let mut control = lock_unpoisoned(&self.control);
            let registration_trust_tier =
                control.mvp1_identities.validate_registration_policy(request)?;
            let renewal = control
                .mvp1_identities
                .device_identity_for_root(&request.principal_commitment, &request.proof.device_id)
                .and_then(|identity| control.mvp1_identities.device_auth_key(&identity))
                .is_some_and(|prior| {
                    !prior.revoked
                        && prior.principal_id == request.proof.principal_id
                        && prior.device_epoch == request.proof.device_epoch
                        && prior.branch_public_key == request.branch_public_key
                        && prior.target_delivery_id == request.target_delivery_id
                });
            let prepared =
                control.mvp1_identities.prepare_registration(request, registration_trust_tier)?;
            let mut session = prepared.session.clone();
            let mut target = self.target_shard(&session.target_delivery_id);
            if let Some(existing) = target.registry.session(&session.target_delivery_id) {
                if renewal
                    && existing.device_id == session.device_id
                    && existing.device_epoch == session.device_epoch
                {
                    // Publishing a renewed proof does not move an established live route.
                    session = existing.clone();
                } else if existing.session_id == session.session_id {
                    session.session_seq = existing.session_seq;
                    session.last_cursor.clone_from(&existing.last_cursor);
                }
            }
            // The target lock keeps this validation true until durable publication.
            target.registry.validate_session_update(&session)?;
            let guard = prepared.apply_to(&mut control.mvp1_identities);
            if let Some(store) = store {
                store.record_registration_admission(guard.registry, &prepared.delta, &session)?;
            }
            guard.commit();
            target.registry.restore_session(session);
            self.refresh_migration_read_snapshot_from_control(&control);
            prepared.tier
        };
        Ok(IdentityRegistrationResponse {
            principal_id: request.proof.principal_id.clone(),
            device_id: request.proof.device_id.clone(),
            device_epoch: request.proof.device_epoch,
            target_delivery_id: request.target_delivery_id.clone(),
            session_bound: true,
            registration_trust_tier,
        })
    }

    pub fn mvp6_set_registration_policy(&self, policy: RegistrationPolicy) {
        lock_unpoisoned(&self.control).mvp1_identities.set_registration_policy(policy);
    }

    #[must_use]
    pub fn mvp6_registration_policy(&self) -> RegistrationPolicy {
        lock_unpoisoned(&self.control).mvp1_identities.registration_policy().clone()
    }

    /// # Errors
    /// Returns an error when the request exceeds the tier-specific budget.
    pub fn mvp6_record_friend_request(
        &self,
        request: &FriendRequestBudgetRequest,
    ) -> Result<FriendRequestBudgetResponse, NodeCoreError> {
        lock_unpoisoned(&self.control).mvp1_identities.record_friend_request(request)
    }

    /// # Errors
    /// Returns an error when the revocation is not authorized by the principal root key.
    pub fn mvp1_revoke_device(
        &self,
        request: &crate::DeviceRevokeRequest,
    ) -> Result<DeviceRevokeResponse, NodeCoreError> {
        let revoked = {
            let mut control = lock_unpoisoned(&self.control);
            let revoked = control.mvp1_identities.revoke_device(request)?;
            self.refresh_migration_read_snapshot_from_control(&control);
            revoked
        };
        Ok(DeviceRevokeResponse { device_id: request.device_id.clone(), revoked })
    }

    /// # Errors
    /// Returns an error when the prekey bundle is invalid or the device cannot publish.
    pub fn mvp1_publish_prekey(
        &self,
        request: PrekeyPublishRequest,
    ) -> Result<PrekeyResponse, NodeCoreError> {
        let device_id = request.device_id.clone();
        let lookup = IdentityRegistry::principal_device_lookup(
            &request.bundle.identity_commitment,
            &device_id,
        );
        let mut control = lock_unpoisoned(&self.control);
        control.mvp1_identities.publish_prekey(request)?;
        let identity = control
            .mvp1_identities
            .resolve_device_selector(&lookup)
            .ok_or_else(|| NodeCoreError::ItestHttp("prekey authority missing".into()))?;
        Ok(PrekeyResponse {
            device_id: device_id.clone(),
            bundle: control.mvp1_identities.prekey_bundle(&identity).cloned(),
            principal_commitment: control
                .mvp1_identities
                .principal_commitment_for_device(&identity)
                .unwrap_or_default()
                .to_owned(),
            target_delivery_id: control
                .mvp1_identities
                .target_delivery_id_for_device(&identity)
                .map(str::to_owned),
        })
    }

    /// Fetch keys only with an authenticated root-qualified device selector.
    /// # Errors
    /// Rejects missing, ambiguous or unqualified root-bound device lookups.
    pub fn mvp1_prekey_checked(&self, lookup: &str) -> Result<PrekeyResponse, NodeCoreError> {
        let control = lock_unpoisoned(&self.control);
        let identities = &control.mvp1_identities;
        let identity = identities
            .resolve_device_selector(lookup)
            .ok_or_else(|| NodeCoreError::ItestHttp("qualified device required".into()))?;
        let record = identities
            .device_record(&identity)
            .ok_or_else(|| NodeCoreError::ItestHttp("device not found".into()))?;
        Ok(PrekeyResponse {
            device_id: record.device_id.clone(),
            bundle: identities.prekey_bundle(&identity).cloned(),
            principal_commitment: identities
                .principal_commitment_for_device(&identity)
                .unwrap_or_default()
                .into(),
            target_delivery_id: identities
                .target_delivery_id_for_device(&identity)
                .map(str::to_owned),
        })
    }
    /// Authenticate a root-qualified device selected at the wire boundary.
    /// # Errors
    /// Rejects missing, ambiguous or unqualified root-bound device lookups.
    pub fn mvp1_device_auth_key_checked(
        &self,
        lookup: &str,
    ) -> Result<Option<DeviceAuthKeyResponse>, NodeCoreError> {
        let control = lock_unpoisoned(&self.control);
        let identity = control
            .mvp1_identities
            .resolve_device_selector(lookup)
            .ok_or_else(|| NodeCoreError::ItestHttp("qualified device required".into()))?;
        Ok(control.mvp1_identities.device_auth_key(&identity))
    }
    /// Looks up a name only for an authenticated live account session, charging node-wide quotas.
    #[must_use]
    pub fn mvp1_authenticated_principal_lookup(
        &self,
        request: &crate::PrincipalLookupRequest,
        now: u64,
    ) -> ramflux_protocol::PrincipalLookupResponse<DeviceManifestResponse> {
        use ramflux_protocol::{
            IdentityDirectoryReason as Reason, PrincipalLookupResponse as Response,
        };
        let denied = |reason| Response { manifest: None, reason_code: Some(reason) };
        let Some(session) = self.session(&request.target_delivery_id) else {
            return denied(Reason::AuthenticationRequired);
        };
        if session.session_id != request.session_id
            || session.device_id != request.requester_device_id
            || session.gateway_id != request.gateway_id
            || session.lifecycle != crate::SessionLifecycle::Live
        {
            return denied(Reason::AuthenticationRequired);
        }
        let mut control = lock_unpoisoned(&self.control);
        let identity = control.mvp1_identities.device_identity_for_session(&session);
        let Some(account) = identity
            .as_ref()
            .and_then(|identity| control.mvp1_identities.device_auth_key(identity))
            .filter(|device| !device.revoked)
            .map(|device| device.principal_id)
        else {
            return denied(Reason::AuthenticationRequired);
        };
        if !control.principal_lookup_limiter.admit(&account, request.source, now) {
            return denied(Reason::RateLimited);
        }
        if control.mvp1_identities.principal_manifest_ambiguous(&request.principal_id) {
            return denied(Reason::PrincipalIdAmbiguous);
        }
        let manifest = control.mvp1_identities.principal_manifest(&request.principal_id);
        Response { manifest, reason_code: None }
    }

    /// Looks up an active principal through this home node's directory.
    #[must_use]
    pub fn mvp1_principal_manifest(&self, principal_id: &str) -> Option<DeviceManifestResponse> {
        lock_unpoisoned(&self.control).mvp1_identities.principal_manifest(principal_id)
    }

    #[must_use]
    pub fn mvp1_device_manifest(
        &self,
        principal_commitment: &str,
    ) -> Option<DeviceManifestResponse> {
        lock_unpoisoned(&self.control).mvp1_identities.device_manifest(principal_commitment)
    }

    #[must_use]
    pub fn mvp1_inbox(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
    ) -> InboxFetchResponse {
        InboxFetchResponse {
            target_delivery_id: target_delivery_id.to_owned(),
            entries: self.resume(target_delivery_id, after_inbox_seq, limit),
        }
    }

    /// Reads deliveries still inside their retention deadline at server time `now`.
    #[must_use]
    pub fn mvp1_inbox_at(
        &self,
        target_delivery_id: &str,
        after_inbox_seq: u64,
        limit: usize,
        now: i64,
    ) -> InboxFetchResponse {
        InboxFetchResponse {
            target_delivery_id: target_delivery_id.to_owned(),
            entries: self.target_shard(target_delivery_id).inbox.pull_live_after(
                target_delivery_id,
                after_inbox_seq,
                limit,
                now,
            ),
        }
    }

    /// Fans out at the current server time.
    /// # Errors
    /// Returns an error when the source device is not registered under the principal.
    pub fn mvp10_own_device_fanout(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
    ) -> Result<ItestMvp10OwnDeviceFanoutResponse, NodeCoreError> {
        self.mvp10_own_device_fanout_at(request, server_now())
    }

    /// Fans out using server time `now` for replay, clock-skew and retention checks.
    /// # Errors
    /// Returns an error when the source device is not registered under the principal.
    pub fn mvp10_own_device_fanout_at(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
        now: i64,
    ) -> Result<ItestMvp10OwnDeviceFanoutResponse, NodeCoreError> {
        let plan = self.accept_own_device_fanout_replay(request, now)?;
        let delivered = plan
            .deliveries
            .into_iter()
            .map(|delivery| self.submit_replay_accepted_fanout_delivery(delivery, now).0)
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
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<ReplayAcceptedEnvelope, NodeCoreError> {
        self.check_envelope_replay_once(source, &envelope, now_unix_seconds)?;
        Ok(ReplayAcceptedEnvelope { envelope })
    }

    #[must_use]
    pub fn submit_replay_accepted_envelope(
        &self,
        accepted: ReplayAcceptedEnvelope,
        now_unix_seconds: i64,
    ) -> RouterSubmitOutcome {
        self.submit_envelope_after_replay_check(accepted.envelope, now_unix_seconds)
    }

    /// # Errors
    /// Returns an error when the source device is not registered under the principal
    /// or the fan-out envelope replay tuple has already been accepted.
    pub fn accept_own_device_fanout_replay(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
        now_unix_seconds: i64,
    ) -> Result<ReplayAcceptedFanoutPlan, NodeCoreError> {
        let targets = self.mvp10_own_device_targets(&request)?;
        self.accept_fanout_targets(request, targets, now_unix_seconds)
    }

    /// Acquire every frozen fanout target before accepting replay or assigning any sequence.
    /// # Errors
    /// Returns authority, replay or typed migration refusals without mutating delivery state.
    pub fn accept_leased_fanout(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
        store: &crate::RouterRedbStore,
        now: i64,
    ) -> Result<(ReplayAcceptedFanoutPlan, Vec<crate::SubmissionLease>), NodeCoreError> {
        let targets = self.mvp10_own_device_targets(&request)?;
        for (_, target) in &targets {
            self.prepare_publication_target(store, target)?;
        }
        let leases = targets
            .iter()
            .map(|(_, target)| store.acquire_submission(target))
            .collect::<Result<Vec<_>, _>>()?;
        let source = self.authenticated_envelope_source(&request.envelope)?;
        let replay_key = envelope_replay_tuple_key(&source, &request.envelope);
        crate::router_store::publication::operation::replay_resource_if_new(
            self.publication.get(),
            &replay_key,
            || {
                lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                    .holds_envelope(&source, &request.envelope, now)
            },
        );
        let identities = targets
            .iter()
            .map(|(_, target)| {
                store.provisional_inbox_incarnation(target).map(|id| (target.clone(), id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(core) = self.publication.get() {
            crate::router_store::publication::operation::reserve_targets(core, &identities)?;
        }
        Ok((self.accept_fanout_targets(request, targets, now)?, leases))
    }
    fn accept_fanout_targets(
        &self,
        request: ItestMvp10OwnDeviceFanoutRequest,
        targets: Vec<(String, String)>,
        now_unix_seconds: i64,
    ) -> Result<ReplayAcceptedFanoutPlan, NodeCoreError> {
        let source = self.authenticated_envelope_source(&request.envelope)?;
        self.check_envelope_replay_once(&source, &request.envelope, now_unix_seconds)?;
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
        now_unix_seconds: i64,
    ) -> (ItestMvp10OwnDeviceFanoutDelivery, Option<InboxEntry>) {
        let outcome = self.submit_envelope_after_replay_check(delivery.envelope, now_unix_seconds);
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
            RouterSubmitOutcome::RejectedSecurity { reason, .. } => {
                let outcome = crate::sender_retry::refusal_from_reason(&reason).map_or_else(
                    || "rejected_security".to_owned(),
                    |error| {
                        if matches!(error, NodeCoreError::Publication(_)) {
                            "capacity_retry_after".into()
                        } else {
                            error.to_string()
                        }
                    },
                );
                (outcome, None, None)
            }
            RouterSubmitOutcome::ForwardedHomeNodeMigrated(_) => {
                ("forwarded_home_node_migrated".to_owned(), None, None)
            }
            RouterSubmitOutcome::ForwardInProgress { .. } => {
                ("forward_in_progress".to_owned(), None, None)
            }
            RouterSubmitOutcome::DuplicateFederatedForward { .. } => {
                ("duplicate_federated_forward".to_owned(), None, None)
            }
            RouterSubmitOutcome::RejectedHomeNodeMigrated(_) => {
                ("rejected_home_node_migrated".to_owned(), None, None)
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
            .device_record_for_principal(&request.principal_id, &request.source_device_id)
            .is_none_or(|device| {
                device.principal_id != request.principal_id
                    || !control.mvp1_identities.device_record_is_usable(device)
            })
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

    /// Submits at the current server time.
    pub fn submit_envelope(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
    ) -> RouterSubmitOutcome {
        self.submit_envelope_at(source, envelope, server_now())
    }

    pub fn submit_envelope_at(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> RouterSubmitOutcome {
        let forwarding_key = forwarding_submission_key(source, &envelope.envelope_id);
        let mut forwarding = lock_unpoisoned(
            &self.forwarding_reservations.shards
                [envelope_target_index_shard_index(&envelope.envelope_id)],
        );
        if forwarding_reservation_is_active(&mut forwarding, &forwarding_key, now_unix_seconds) {
            return RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: envelope.target_delivery_id,
            };
        }
        if let Err(error) = self.check_envelope_replay_once(source, &envelope, now_unix_seconds) {
            return RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id: envelope.target_delivery_id,
                reason: error.to_string(),
            };
        }
        self.submit_envelope_after_replay_check(envelope, now_unix_seconds)
    }

    pub fn submit_envelope_with_home_node_forward_at<F>(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
        origin: RouterEnvelopeOrigin,
        forward: F,
    ) -> RouterSubmitOutcome
    where
        F: FnOnce(
            &HomeNodeMigrationForwardPlan,
        ) -> Result<FederatedEnvelopeForwardResponse, NodeCoreError>,
    {
        match self.prepare_envelope_with_home_node_forward_at(
            source,
            envelope,
            now_unix_seconds,
            origin,
            DEFAULT_FORWARD_RESERVATION_LEASE_SECONDS,
        ) {
            RouterForwardPreparation::Complete(outcome) => *outcome,
            RouterForwardPreparation::Forward(reservation) => {
                let Some(plan) = reservation.plan() else {
                    return RouterSubmitOutcome::ForwardInProgress {
                        target_delivery_id: reservation.target_delivery_id().to_owned(),
                    };
                };
                let response = forward(plan);
                self.complete_home_node_forward(reservation, response)
            }
        }
    }

    #[must_use]
    pub fn prepare_envelope_with_home_node_forward_at(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
        origin: RouterEnvelopeOrigin,
        lease_seconds: u64,
    ) -> RouterForwardPreparation {
        let shard_index = envelope_target_index_shard_index(&envelope.envelope_id);
        let forwarding_key = forwarding_submission_key(source, &envelope.envelope_id);
        let mut forwarding = lock_unpoisoned(&self.forwarding_reservations.shards[shard_index]);
        if forwarding_reservation_is_active(&mut forwarding, &forwarding_key, now_unix_seconds) {
            return complete_forward_preparation(RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: envelope.target_delivery_id,
            });
        }
        let accepted_once =
            match self.accept_envelope_replay_once(source, &envelope, now_unix_seconds) {
                Ok(accepted_once) => accepted_once,
                Err(error) => {
                    return complete_forward_preparation(RouterSubmitOutcome::RejectedSecurity {
                        target_delivery_id: envelope.target_delivery_id,
                        reason: error.to_string(),
                    });
                }
            };
        if !accepted_once && self.indexed_target_for_envelope(&envelope.envelope_id).is_some() {
            if origin == RouterEnvelopeOrigin::Federation {
                return complete_forward_preparation(
                    RouterSubmitOutcome::DuplicateFederatedForward {
                        target_delivery_id: envelope.target_delivery_id,
                    },
                );
            }
            let replay_key = envelope_replay_tuple_key(source, &envelope);
            return complete_forward_preparation(RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id: envelope.target_delivery_id,
                reason: NodeCoreError::ReplayGuard(format!("replay: {replay_key}")).to_string(),
            });
        }
        let migration = self.effective_home_node_migration_for_target(
            &envelope.target_delivery_id,
            now_unix_seconds,
        );
        if !accepted_once && migration.is_none() {
            let replay_key = envelope_replay_tuple_key(source, &envelope);
            return complete_forward_preparation(RouterSubmitOutcome::RejectedSecurity {
                target_delivery_id: envelope.target_delivery_id,
                reason: NodeCoreError::ReplayGuard(format!("replay: {replay_key}")).to_string(),
            });
        }
        let Some(migration) = migration else {
            return complete_forward_preparation(
                self.submit_envelope_after_replay_check(envelope, now_unix_seconds),
            );
        };
        let Some(plan) =
            self.home_node_migration_forward_plan(&envelope, &migration, now_unix_seconds)
        else {
            return complete_forward_preparation(RouterSubmitOutcome::RejectedHomeNodeMigrated(
                home_node_migrated_delivery(
                    &envelope,
                    &migration,
                    now_unix_seconds,
                    self.node_service_signer().as_ref(),
                ),
            ));
        };
        let attempt_id =
            self.forwarding_reservations.next_attempt_id.fetch_add(1, Ordering::Relaxed);
        let lease_seconds = i64::try_from(lease_seconds.max(1)).unwrap_or(i64::MAX);
        forwarding.insert(
            forwarding_key.clone(),
            ForwardingReservationState {
                attempt_id,
                lease_until: now_unix_seconds.saturating_add(lease_seconds),
            },
        );
        drop(forwarding);
        RouterForwardPreparation::Forward(Box::new(RouterForwardReservation {
            reservations: Arc::clone(&self.forwarding_reservations),
            shard_index,
            key: forwarding_key,
            attempt_id,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope: Some(envelope),
            migration,
            plan: Some(plan),
            replayed: !accepted_once,
            now_unix_seconds,
        }))
    }

    pub fn complete_home_node_forward(
        &self,
        mut reservation: Box<RouterForwardReservation>,
        response: Result<FederatedEnvelopeForwardResponse, NodeCoreError>,
    ) -> RouterSubmitOutcome {
        let Some(envelope) = reservation.envelope.take() else {
            return RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: reservation.target_delivery_id().to_owned(),
            };
        };
        let Some(plan) = reservation.plan.take() else {
            return RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: envelope.target_delivery_id,
            };
        };
        if let Ok(response) = response {
            if federation_forward_succeeded(&response, plan.migration_evidence.is_some()) {
                return RouterSubmitOutcome::ForwardedHomeNodeMigrated(Box::new(
                    HomeNodeMigrationForwardDelivery {
                        target_delivery_id: envelope.target_delivery_id,
                        proof_hash: reservation.migration.migration_proof_hash.clone(),
                        new_home_node_hint: reservation.migration.new_home_node.clone(),
                        route: plan.route,
                        delivery: response.delivery,
                        replayed: reservation.replayed,
                    },
                ));
            }
            if response.delivery.outcome == "forward_in_progress" {
                return RouterSubmitOutcome::ForwardInProgress {
                    target_delivery_id: envelope.target_delivery_id,
                };
            }
        }
        if plan.migration_evidence.is_some() {
            return RouterSubmitOutcome::ForwardInProgress {
                target_delivery_id: envelope.target_delivery_id,
            };
        }
        RouterSubmitOutcome::RejectedHomeNodeMigrated(home_node_migrated_delivery(
            &envelope,
            &reservation.migration,
            reservation.now_unix_seconds,
            self.node_service_signer().as_ref(),
        ))
    }

    fn submit_envelope_after_replay_check(
        &self,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> RouterSubmitOutcome {
        if let Some(migration) = self.effective_home_node_migration_for_target(
            &envelope.target_delivery_id,
            now_unix_seconds,
        ) {
            return RouterSubmitOutcome::RejectedHomeNodeMigrated(home_node_migrated_delivery(
                &envelope,
                &migration,
                now_unix_seconds,
                self.node_service_signer().as_ref(),
            ));
        }
        self.submit_local_envelope_after_migration_check(envelope, now_unix_seconds)
    }

    fn submit_local_envelope_after_migration_check(
        &self,
        envelope: ramflux_protocol::Envelope,
        now_unix_seconds: i64,
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
                let entry = match shard.inbox.append_published(envelope.clone(), now_unix_seconds) {
                    Ok(entry) => entry,
                    Err(error) => {
                        return RouterSubmitOutcome::RejectedSecurity {
                            target_delivery_id: envelope.target_delivery_id,
                            reason: error.to_string(),
                        };
                    }
                };
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
                let target = envelope.target_delivery_id.clone();
                let entry = match shard.inbox.append_published(envelope, now_unix_seconds) {
                    Ok(entry) => entry,
                    Err(error) => {
                        return RouterSubmitOutcome::RejectedSecurity {
                            target_delivery_id: target,
                            reason: error.to_string(),
                        };
                    }
                };
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
        if !ack.ext.ext.contains_key("inbox_seq") {
            let actual_target_delivery_id = self
                .indexed_target_for_envelope(&ack.envelope_id)
                .ok_or_else(|| NodeCoreError::EnvelopeNotFound(ack.envelope_id.clone()))?;
            if actual_target_delivery_id != target_delivery_id {
                return Err(NodeCoreError::EnvelopeTargetMismatch {
                    envelope_id: ack.envelope_id.clone(),
                    expected_target_delivery_id: target_delivery_id.into(),
                    actual_target_delivery_id,
                });
            }
        }
        crate::record_router_ack();
        self.target_shard(target_delivery_id).inbox.apply_ack_for_target(target_delivery_id, ack)
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
        self.target_shard(target_delivery_id).inbox.apply_nack_for_target(target_delivery_id, nack)
    }

    /// Returns the indexed target for an envelope, including entries restored from pending inbox
    /// rows and cursor ack/nack state.
    #[must_use]
    pub fn target_for_envelope_id(&self, envelope_id: &str) -> Option<String> {
        self.indexed_target_for_envelope(envelope_id)
    }

    pub(crate) fn snapshot(&self) -> RouterCoreSnapshot {
        let control = lock_unpoisoned(&self.control);
        let shards =
            self.target_shards.iter().map(|shard| lock_unpoisoned(shard)).collect::<Vec<_>>();
        if let Some(core) = self.publication.get() {
            let mut snapshot = self.raw_snapshot(&control, &shards);
            let mut snapshot = core.with_views(|views| {
                snapshot.inbox.filter_published(views);
                snapshot
            });
            snapshot.replay_guard_state.retain_keys(|key| core.resource_visible(key));
            return snapshot;
        }
        self.raw_snapshot(&control, &shards)
    }

    fn raw_snapshot(
        &self,
        control: &RouterControlState,
        shards: &[MutexGuard<'_, RouterTargetShard>],
    ) -> RouterCoreSnapshot {
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
            snapshot.mvp1_identities = control.mvp1_identities.clone();
            snapshot.foreign_device_heads = control.foreign_device_heads.clone();
            snapshot.lifecycle_by_principal = control.lifecycle_by_principal.clone();
            snapshot.lifecycle_tombstones = control.lifecycle_tombstones.clone();
            snapshot.identity_lineage_events = control.identity_lineage_events.clone();
            snapshot.identity_lineage_heads = control.identity_lineage_heads.clone();
            snapshot.abuse_reports = control.abuse_reports.clone();
            snapshot.node_franking_public_key.clone_from(&control.node_franking_public_key);
            snapshot.home_node_migrations = control.home_node_migrations.clone();
            snapshot.home_node_routes = control.home_node_routes.clone();
        }
        for shard in shards {
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
            .map(|_index| Arc::new(Mutex::new(RouterTargetShard::default())))
            .collect::<Vec<_>>();
        let envelope_target_index_shards = (0..ROUTER_ENVELOPE_TARGET_INDEX_SHARD_COUNT)
            .map(|_index| Arc::new(Mutex::new(BTreeMap::new())))
            .collect::<Vec<_>>();
        let forwarding_reservations = Arc::new(ForwardingReservations {
            shards: (0..ROUTER_ENVELOPE_TARGET_INDEX_SHARD_COUNT)
                .map(|_index| Mutex::new(HashMap::new()))
                .collect(),
            next_attempt_id: AtomicU64::new(1),
        });
        let replay_guard_shards = (0..ROUTER_REPLAY_GUARD_SHARD_COUNT)
            .map(|_index| Arc::new(Mutex::new(NodeReplayGuardState::new())))
            .collect::<Vec<_>>();
        let control = RouterControlState {
            principal_lookup_limiter: crate::principal_directory::PrincipalLookupLimiter::default(),
            mvp1_identities: snapshot.mvp1_identities,
            foreign_device_heads: snapshot.foreign_device_heads,
            lifecycle_by_principal: snapshot.lifecycle_by_principal,
            lifecycle_tombstones: snapshot.lifecycle_tombstones,
            identity_lineage_events: snapshot.identity_lineage_events,
            identity_lineage_heads: snapshot.identity_lineage_heads,
            abuse_reports: snapshot.abuse_reports,
            node_franking_public_key: snapshot.node_franking_public_key,
            home_node_migrations: snapshot.home_node_migrations,
            home_node_routes: snapshot.home_node_routes,
        };
        let migration_read_snapshot = RouterMigrationReadSnapshot::from_control(&control);
        let router = Self {
            target_shards,
            envelope_target_index_shards,
            forwarding_reservations,
            control: Mutex::new(control),
            migration_read_snapshot: ArcSwap::from_pointee(migration_read_snapshot),
            publication: std::sync::OnceLock::new(),
            replay_guard_shards,
            node_service_signer: Mutex::new(None),
            local_home_node_id: Mutex::new(None),
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
        for (entry, deadline) in snapshot.inbox.pending_entries_with_deadline() {
            router.index_envelope_target(entry);
            router
                .target_shard(&entry.target_delivery_id)
                .inbox
                .restore_pending_entry_until(entry.clone(), Some(deadline));
        }
        for cursor in snapshot.inbox.cursor_states().cloned().collect::<Vec<_>>() {
            router.index_cursor_targets(&cursor);
            if let Some(id) = snapshot.inbox.incarnation_id(&cursor.target_delivery_id) {
                router
                    .target_shard(&cursor.target_delivery_id)
                    .inbox
                    .restore_incarnation(&cursor.target_delivery_id, id.into());
            }
            router.target_shard(&cursor.target_delivery_id).inbox.restore_cursor_state(cursor);
        }
        for (target, ranges) in &snapshot.inbox.aborted_ranges {
            router.target_shard(target).inbox.aborted_ranges.insert(target.clone(), ranges.clone());
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
            control.identity_lineage_events.extend(snapshot.identity_lineage_events);
            control.identity_lineage_heads.extend(snapshot.identity_lineage_heads);
            control.abuse_reports.extend(snapshot.abuse_reports);
            control.home_node_migrations.extend(snapshot.home_node_migrations);
            control.home_node_routes.extend(snapshot.home_node_routes);
            if control.node_franking_public_key.is_none() {
                control.node_franking_public_key = snapshot.node_franking_public_key;
            }
            self.refresh_migration_read_snapshot_from_control(&control);
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
        for (entry, deadline) in snapshot.inbox.pending_entries_with_deadline() {
            self.index_envelope_target(entry);
            self.target_shard(&entry.target_delivery_id)
                .inbox
                .restore_pending_entry_until(entry.clone(), Some(deadline));
        }
        for cursor in snapshot.inbox.cursor_states().cloned().collect::<Vec<_>>() {
            self.index_cursor_targets(&cursor);
            if let Some(id) = snapshot.inbox.incarnation_id(&cursor.target_delivery_id) {
                self.target_shard(&cursor.target_delivery_id)
                    .inbox
                    .restore_incarnation(&cursor.target_delivery_id, id.into());
            }
            self.target_shard(&cursor.target_delivery_id).inbox.restore_cursor_state(cursor);
        }
        for (target, ranges) in &snapshot.inbox.aborted_ranges {
            self.target_shard(target).inbox.aborted_ranges.insert(target.clone(), ranges.clone());
        }
        for target in snapshot.deactivated_delivery_targets {
            self.target_shard(&target).deactivated_delivery_targets.insert(target);
        }
        for target in snapshot.deleted_delivery_targets {
            self.target_shard(&target).deleted_delivery_targets.insert(target);
        }
    }

    /// Authenticate the root-selected branch before using any claimed sender in a key.
    /// # Errors
    /// Rejects missing root claims, absent/revoked signed-set entries and forged signatures.
    pub fn authenticated_envelope_source(
        &self,
        envelope: &ramflux_protocol::Envelope,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        self.authenticated_envelope_source_from(envelope, None, RouterEnvelopeOrigin::Gateway)
    }

    /// Authenticate a source and persist its highest foreign authority before accepting delivery.
    /// # Errors
    /// Rejects stale or forged authority and durable storage failures.
    pub fn authenticated_envelope_source_durable(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: &crate::RouterRedbStore,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        self.authenticated_envelope_source_from(
            envelope,
            Some(store),
            RouterEnvelopeOrigin::Gateway,
        )
    }

    /// Authenticate an envelope using provenance from an already authenticated mesh peer.
    /// # Errors
    /// Rejects forged, stale, over-capacity or gateway-supplied foreign authority.
    pub fn authenticated_envelope_source_from(
        &self,
        envelope: &ramflux_protocol::Envelope,
        store: Option<&crate::RouterRedbStore>,
        origin: RouterEnvelopeOrigin,
    ) -> Result<ramflux_crypto::RootQualifiedDeviceRef, NodeCoreError> {
        let reject = || NodeCoreError::ItestHttp("envelope root authority mismatch".into());
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(reject)?;
        let lookup = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
            .map_err(|_| reject())?;
        let mut control = lock_unpoisoned(&self.control);
        let registry = &mut control.mvp1_identities;
        let registered = registry
            .resolve_device_selector(&lookup)
            .and_then(|identity| registry.device_auth_key(&identity));
        let local_registration = registered.is_some();
        let (authority, source) = if let Some(authority) = registered {
            let source = authority.verify_envelope_source(envelope)?;
            (authority, source)
        } else {
            if origin != RouterEnvelopeOrigin::Federation {
                return Err(NodeCoreError::Unauthorized(
                    "foreign authority requires an authenticated federation peer".into(),
                ));
            }
            let (authority, source) = DeviceAuthKeyResponse::forwarded_envelope_source(envelope)?;
            if registry
                .signed_device_set(root)
                .is_some_and(|current| authority.signed_device_set.as_ref() != Some(current))
            {
                return Err(reject());
            }
            (authority, source)
        };
        // Native registration already supplies the current unfenced certificate chain.
        // Its envelope signature was checked above; a legacy signed device set is absent
        // by design. Foreign evidence still requires the durable admission path below.
        if local_registration && authority.custody_authority.is_some() {
            return Ok(source);
        }
        let record = authority.signed_device_set.as_ref().ok_or_else(reject)?;
        if local_registration {
            if let Some(fence) = control.foreign_device_heads.fences.get(root) {
                fence.check(crate::foreign_device_heads::EpochFence::of(record)?)?;
            }
            return Ok(source);
        }

        let observation = if let Some(store) = store {
            store.observe_foreign_device_set(record)?
        } else {
            control.foreign_device_heads.prepare(record)?
        };
        control.foreign_device_heads.apply(record, observation);
        observation.admitted()?;
        Ok(source)
    }

    /// Refresh locally registered authority before delivery or forwarding.
    /// # Errors
    /// Rejects a revoked sender or a signature that no longer matches the current branch.
    pub fn refresh_registered_envelope_authority(
        &self,
        envelope: &mut ramflux_protocol::Envelope,
    ) -> Result<(), NodeCoreError> {
        let root = envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| NodeCoreError::Unauthorized("source root missing".into()))?;
        let lookup = ramflux_protocol::qualified_device_id(root, &envelope.source_device_id)
            .map_err(|e| NodeCoreError::Unauthorized(e.to_string()))?;
        let control = lock_unpoisoned(&self.control);
        let registry = &control.mvp1_identities;
        if let Some(identity) = registry.resolve_device_selector(&lookup) {
            let authority = registry.device_auth_key(&identity).ok_or_else(|| {
                NodeCoreError::Unauthorized("registered source authority unavailable".into())
            })?;
            authority.verify_envelope_source(envelope)?;
            envelope.ext.ext.insert(
                "source_device_authority".into(),
                serde_json::to_value(authority)
                    .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?,
            );
        }
        Ok(())
    }

    fn check_envelope_replay_once(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
        crate::record_router_replay_guard_check();
        let replay_check_started = Instant::now();
        let replay_key = envelope_replay_tuple_key(source, envelope);
        crate::router_store::publication::operation::replay_resource_if_new(
            self.publication.get(),
            &replay_key,
            || {
                lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                    .holds_envelope(source, envelope, now_unix_seconds)
            },
        );
        let replay_check =
            lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                .check_envelope(source, envelope, now_unix_seconds);
        crate::record_router_replay_guard_check_us(elapsed_us(replay_check_started));
        replay_check
    }

    fn accept_envelope_replay_once(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<bool, NodeCoreError> {
        crate::record_router_replay_guard_check();
        let replay_check_started = Instant::now();
        let replay_key = envelope_replay_tuple_key(source, envelope);
        crate::router_store::publication::operation::replay_resource_if_new(
            self.publication.get(),
            &replay_key,
            || {
                lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                    .holds_envelope(source, envelope, now_unix_seconds)
            },
        );
        let replay_check =
            lock_unpoisoned(&self.replay_guard_shards[replay_guard_shard_index(&replay_key)])
                .accept_envelope_once(source, envelope, now_unix_seconds);
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
        lock_unpoisoned(
            &self.envelope_target_index_shards
                [envelope_target_index_shard_index(&entry.envelope.envelope_id)],
        )
        .insert(entry.envelope.envelope_id.clone(), entry.target_delivery_id.clone());
    }

    fn index_cursor_targets(&self, cursor: &CursorAckState) {
        for envelope_id in &cursor.acked_envelope_ids {
            lock_unpoisoned(
                &self.envelope_target_index_shards[envelope_target_index_shard_index(envelope_id)],
            )
            .insert(envelope_id.clone(), cursor.target_delivery_id.clone());
        }
        for envelope_id in cursor.nacked_envelope_ids.keys() {
            lock_unpoisoned(
                &self.envelope_target_index_shards[envelope_target_index_shard_index(envelope_id)],
            )
            .insert(envelope_id.clone(), cursor.target_delivery_id.clone());
        }
    }

    pub(crate) fn remove_target_index(&self, target_delivery_id: &str) {
        for index in &self.envelope_target_index_shards {
            lock_unpoisoned(index).retain(|_envelope_id, target| target != target_delivery_id);
        }
    }

    fn indexed_target_for_envelope(&self, envelope_id: &str) -> Option<String> {
        lock_unpoisoned(
            &self.envelope_target_index_shards[envelope_target_index_shard_index(envelope_id)],
        )
        .get(envelope_id)
        .cloned()
    }

    fn effective_home_node_migration_for_target(
        &self,
        target_delivery_id: &str,
        now_unix_seconds: i64,
    ) -> Option<HomeNodeMigrationRecord> {
        let snapshot = self.migration_read_snapshot.load();
        snapshot.identity_keys_by_target.get(target_delivery_id).into_iter().flatten().find_map(
            |key| {
                snapshot
                    .home_node_migrations
                    .get(key.as_str())
                    .filter(|migration| migration.is_effective(now_unix_seconds))
                    .filter(|migration| self.migration_blocks_local_node(migration))
                    .cloned()
            },
        )
    }

    pub(crate) fn refresh_migration_read_snapshot_from_control(
        &self,
        control: &RouterControlState,
    ) {
        self.migration_read_snapshot
            .store(Arc::new(RouterMigrationReadSnapshot::from_control(control)));
    }

    fn migration_blocks_local_node(&self, migration: &HomeNodeMigrationRecord) -> bool {
        self.local_home_node_id()
            .as_deref()
            .is_none_or(|local_node_id| local_node_id != migration.new_home_node)
    }

    fn home_node_migration_forward_plan(
        &self,
        envelope: &ramflux_protocol::Envelope,
        migration: &HomeNodeMigrationRecord,
        now_unix_seconds: i64,
    ) -> Option<HomeNodeMigrationForwardPlan> {
        if !home_node_forward_window_is_open(migration, now_unix_seconds) {
            return None;
        }
        let forward_count = envelope_home_node_forward_count(envelope);
        if forward_count > 0 {
            return None;
        }
        let route = self.resolve_home_node_route(&migration.identity_commitment)?;
        if route.home_node != migration.new_home_node
            || (migration.format_version == 1 && route.expires_at <= now_unix_seconds)
        {
            return None;
        }
        let mut forwarded_envelope = envelope.clone();
        forwarded_envelope.ext.ext.insert(
            crate::HOME_NODE_FORWARD_COUNT_EXT_KEY.to_owned(),
            serde_json::Value::from(u64::from(forward_count.saturating_add(1))),
        );
        Some(HomeNodeMigrationForwardPlan {
            migration_evidence: None,
            target_delivery_id: envelope.target_delivery_id.clone(),
            proof_hash: migration.migration_proof_hash.clone(),
            new_home_node: migration.new_home_node.clone(),
            route,
            envelope: forwarded_envelope,
            forward_count: forward_count.saturating_add(1),
        })
    }
}

fn home_node_forward_window_is_open(
    migration: &HomeNodeMigrationRecord,
    now_unix_seconds: i64,
) -> bool {
    now_unix_seconds >= migration.effective_at
        && now_unix_seconds.saturating_sub(migration.effective_at)
            < crate::HOME_NODE_FORWARD_WINDOW_SECONDS
}

fn envelope_home_node_forward_count(envelope: &ramflux_protocol::Envelope) -> u8 {
    envelope
        .ext
        .ext
        .get(crate::HOME_NODE_FORWARD_COUNT_EXT_KEY)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(0)
}

fn federation_forward_succeeded(
    response: &FederatedEnvelopeForwardResponse,
    committed: bool,
) -> bool {
    if !committed
        && (response.delivery.outcome == "duplicate_federated_forward"
            || response.accepted && response.delivery.outcome == "federation_spooled_offline_peer")
    {
        return true;
    }
    response.accepted
        && matches!(
            response.delivery.outcome.as_str(),
            "online" | "offline_queued" | "duplicate_federated_forward"
        )
}

fn home_node_migrated_delivery(
    envelope: &ramflux_protocol::Envelope,
    migration: &HomeNodeMigrationRecord,
    now_unix_seconds: i64,
    node_service_signer: Option<&NodeServiceSigningKey>,
) -> HomeNodeMigratedNackDelivery {
    let mut nack = ramflux_protocol::Nack {
        schema: "ramflux.nack.v1".to_owned(),
        version: 1,
        domain: "ramflux.nack.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "router:home_node_migration".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        nack_id: format!("nack_home_node_migrated_{}", envelope.envelope_id),
        envelope_id: envelope.envelope_id.clone(),
        receiver_device_id: envelope.target_delivery_id.clone(),
        reason: ramflux_protocol::NackReason::HomeNodeMigrated,
        received_at: now_unix_seconds,
        retry_after: None,
        proof_hash: Some(migration.migration_proof_hash.clone()),
        new_home_node_hint: Some(migration.new_home_node.clone()),
    };
    if let Some(signer) = node_service_signer {
        let fallback_signed = nack.signed.clone();
        if signer.sign_nack(&mut nack).is_err() {
            nack.signed = fallback_signed;
        }
    }
    HomeNodeMigratedNackDelivery {
        target_delivery_id: envelope.target_delivery_id.clone(),
        proof_hash: migration.migration_proof_hash.clone(),
        new_home_node_hint: migration.new_home_node.clone(),
        nack,
    }
}

impl Default for RouterCore {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RouterCore {
    fn clone(&self) -> Self {
        let cloned = Self::from_snapshot(self.snapshot());
        cloned.set_node_service_signer(self.node_service_signer());
        cloned.set_local_home_node_id(self.local_home_node_id());
        cloned
    }
}

impl PartialEq for RouterCore {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot() == other.snapshot()
    }
}

impl Eq for RouterCore {}

/// Router decisions use the server clock, never a client-chosen timestamp.
fn server_now() -> i64 {
    i64::try_from(crate::now_unix_seconds()).unwrap_or(i64::MAX)
}

fn target_shard_index(target_delivery_id: &str) -> usize {
    hash_shard_index(target_delivery_id, ROUTER_TARGET_SHARD_COUNT)
}

fn replay_guard_shard_index(replay_key: &str) -> usize {
    hash_shard_index(replay_key, ROUTER_REPLAY_GUARD_SHARD_COUNT)
}

fn envelope_target_index_shard_index(envelope_id: &str) -> usize {
    hash_shard_index(envelope_id, ROUTER_ENVELOPE_TARGET_INDEX_SHARD_COUNT)
}

fn forwarding_submission_key(
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope_id: &str,
) -> String {
    format!("{}:{}{}", source.root_commitment().len(), source.root_commitment(), envelope_id)
}

fn complete_forward_preparation(outcome: RouterSubmitOutcome) -> RouterForwardPreparation {
    RouterForwardPreparation::Complete(Box::new(outcome))
}

fn forwarding_reservation_is_active(
    reservations: &mut HashMap<String, ForwardingReservationState>,
    key: &str,
    now_unix_seconds: i64,
) -> bool {
    if reservations.get(key).is_some_and(|state| state.lease_until > now_unix_seconds) {
        return true;
    }
    reservations.remove(key);
    false
}

fn hash_shard_index(value: &str, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let shard_count = u64::try_from(shard_count).unwrap_or(1);
    let index = hasher.finish() % shard_count;
    usize::try_from(index).unwrap_or(0)
}

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

mod sender_fanout;
pub use sender_fanout::PreparedFanout;
