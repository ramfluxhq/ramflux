// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! First-use trust is staged until the signed request proves the discovered node key.
use crate::{
    FederationDiscoverySurface, SharedFederationTrustState,
    peer_pin::{self, LocalNode},
};
use ramflux_node_core::{FederatedEnvelopeForwardRequest, FederationRedbStore, NodeCoreError};
use std::{
    collections::{BTreeMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{Duration, Instant},
};

const ATTEMPTS_PER_HOUR: usize = 64;
const ATTEMPTS_PER_IP: usize = 4;
const NEGATIVE_SECONDS: u64 = 60;
const MAX_NODES: usize = 128;

#[derive(Default)]
struct DiscoveryBudget {
    attempts: VecDeque<(u64, IpAddr)>,
    nodes: BTreeMap<String, Arc<NodeSlot>>,
}
#[derive(Default)]
struct Candidate {
    record: Option<ramflux_node_core::FederationServerRecord>,
    cached_at: u64,
    failed_at: Option<u64>,
}
#[derive(Default)]
struct NodeSlot {
    candidate: Mutex<Candidate>,
    busy: Mutex<bool>,
    ready: Condvar,
}
struct CandidateOwner<'a>(&'a NodeSlot);
impl NodeSlot {
    fn claim(&self, deadline: Instant) -> Result<CandidateOwner<'_>, NodeCoreError> {
        let mut busy = self.busy.lock().map_err(|_| refused())?;
        while *busy {
            let left = deadline.checked_duration_since(Instant::now()).ok_or_else(refused)?;
            busy = self.ready.wait_timeout(busy, left).map_err(|_| refused())?.0;
        }
        if Instant::now() >= deadline {
            return Err(refused());
        }
        *busy = true;
        Ok(CandidateOwner(self))
    }
}
impl Drop for CandidateOwner<'_> {
    fn drop(&mut self) {
        if let Ok(mut busy) = self.0.busy.lock() {
            *busy = false;
            self.0.ready.notify_all();
        }
    }
}
static BUDGET: OnceLock<Mutex<DiscoveryBudget>> = OnceLock::new();

pub(crate) fn refused() -> NodeCoreError {
    NodeCoreError::Unauthorized("federation request authentication failed".into())
}

/// Cheap policy precedes any lookup, network fetch or durable side effect.
pub(crate) fn precheck(
    request: &FederatedEnvelopeForwardRequest,
    local: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    let envelope = &request.envelope;
    let created = u64::try_from(envelope.created_at).map_err(|_| refused())?;
    let signature = &request.signed.signature;
    if request.target_node_id != local
        || !peer_pin::node_id_ok(&request.source_node_id)
        || request.source_node_id == local
        || request.delivery_class != "opaque_event"
        || envelope.ttl == 0
        || envelope.ttl > 604_800
        || created > now.saturating_add(60)
        || created.saturating_add(u64::from(envelope.ttl)) <= now
        || request.signed.signing_key_id != format!("{}#federation", request.source_node_id)
        || request.signed.signature_alg != ramflux_protocol::SignatureAlg::Ed25519
        || signature.len() > 128
        || ramflux_protocol::decode_base64url(signature).map_err(|_| refused())?.len() != 64
        || serde_json::to_vec(request).map_err(|_| refused())?.len()
            > crate::mesh_auth::ENVELOPE_BODY_LIMIT
    {
        return Err(refused());
    }
    Ok(())
}

/// Pinned sources never enter discovery or change their capability snapshot.
pub(crate) fn authenticate(
    request: &FederatedEnvelopeForwardRequest,
    state: &SharedFederationTrustState,
    store: &FederationRedbStore,
    local: &FederationDiscoverySurface,
    ip: IpAddr,
    deadline: Instant,
) -> Result<(), NodeCoreError> {
    let now = crate::now_unix_seconds()?;
    precheck(request, &local.node_id, now)?;
    crate::node_directory::sanction::release_revoked_pin(&request.source_node_id, state, store)
        .map_err(|_| refused())?;
    let snapshot = state.snapshot()?;
    let pinned_key = snapshot.pinned_node_public_key(&request.source_node_id);
    crate::node_directory::sanction::check_peer(
        &request.source_node_id,
        pinned_key.as_deref(),
        "inbound",
    )
    .map_err(|_| refused())?;
    if pinned(request, &snapshot, now)? {
        return Ok(());
    }
    snapshot.admit_inbound_peer_pin(&request.source_node_id, now).map_err(|_| refused())?;
    let node = candidate(&request.source_node_id, now)?;
    // Wait on the same node's work within this request's deadline, without another charge.
    let _owner = node.claim(deadline)?;
    let now = crate::now_unix_seconds()?;
    precheck(request, &local.node_id, now)?;
    if pinned(request, state.snapshot()?.as_ref(), now)? {
        return Ok(());
    }
    let mut candidate = node.candidate.lock().map_err(|_| refused())?;
    if candidate.failed_at.is_some_and(|time| now.saturating_sub(time) < NEGATIVE_SECONDS) {
        return Err(refused());
    }
    let local =
        LocalNode { node_id: local.node_id.clone(), capabilities: local.node_capabilities.clone() };
    let context = Bootstrap { request, state, store, local: &local, ip, deadline, now };
    let result = context.authenticate_candidate(&mut candidate);
    result.map_err(|_| refused())
}

fn pinned(
    request: &FederatedEnvelopeForwardRequest,
    snapshot: &ramflux_node_core::FederationTrustState,
    now: u64,
) -> Result<bool, NodeCoreError> {
    if snapshot.peer_pin_blocked(&request.source_node_id, now) {
        if let Some(key) = snapshot.pinned_node_public_key(&request.source_node_id) {
            ramflux_node_core::verify_federated_envelope_forward(request, &key)
                .map_err(|_| refused())?;
            return Ok(true); // The common receive policy returns the signed request's blocked outcome.
        }
        return Err(refused());
    }
    if let Some(key) = snapshot.pinned_node_public_key(&request.source_node_id) {
        ramflux_node_core::verify_federated_envelope_forward(request, &key)
            .map_err(|_| refused())?;
        snapshot
            .ensure_federated_envelope_allowed(request, &request.source_node_id, now)
            .map_err(|_| refused())?;
        return Ok(true);
    }
    if snapshot.discovery_pin(&request.source_node_id).is_some() {
        return Err(refused());
    }
    Ok(false)
}

fn candidate(node: &str, now: u64) -> Result<Arc<NodeSlot>, NodeCoreError> {
    let mut budget = BUDGET.get_or_init(Mutex::default).lock().map_err(|_| refused())?;
    budget.nodes.retain(|_, row| {
        Arc::strong_count(row) > 1
            || row.candidate.try_lock().is_ok_and(|row| {
                row.failed_at.is_some_and(|time| now.saturating_sub(time) < NEGATIVE_SECONDS)
                    || (now.saturating_sub(row.cached_at) < NEGATIVE_SECONDS
                        && row.record.as_ref().is_some_and(|r| r.expires_at > now))
            })
    });
    if let Some(row) = budget.nodes.get(node) {
        return Ok(Arc::clone(row));
    }
    if budget.nodes.len() >= MAX_NODES {
        return Err(refused());
    }
    let row = Arc::new(NodeSlot::default());
    budget.nodes.insert(node.into(), Arc::clone(&row));
    Ok(row)
}

fn charge(ip: IpAddr, now: u64) -> Result<(), NodeCoreError> {
    let mut budget = BUDGET.get_or_init(Mutex::default).lock().map_err(|_| refused())?;
    while budget.attempts.front().is_some_and(|(time, _)| now.saturating_sub(*time) >= 3600) {
        budget.attempts.pop_front();
    }
    if budget.attempts.len() >= ATTEMPTS_PER_HOUR
        || budget.attempts.iter().filter(|(_, source)| *source == ip).count() >= ATTEMPTS_PER_IP
    {
        return Err(refused());
    }
    budget.attempts.push_back((now, ip));
    Ok(())
}

#[derive(Clone, Copy)]
struct Bootstrap<'a> {
    request: &'a FederatedEnvelopeForwardRequest,
    state: &'a SharedFederationTrustState,
    store: &'a FederationRedbStore,
    local: &'a LocalNode,
    ip: IpAddr,
    deadline: Instant,
    now: u64,
}
impl Bootstrap<'_> {
    fn authenticate_candidate(&self, candidate: &mut Candidate) -> Result<(), NodeCoreError> {
        let Self { request, state, local, ip, deadline, now, .. } = *self;
        if Instant::now() >= deadline {
            return Err(refused());
        }
        let _discovery = crate::mesh_auth::discovery_worker()?;
        if now.saturating_sub(candidate.cached_at) >= NEGATIVE_SECONDS
            || candidate.record.as_ref().is_none_or(|record| record.expires_at <= now)
        {
            charge(ip, now)?;
            // Discovery owns a fresh budget. A late/cancelled caller cannot poison this slot.
            let discovery_deadline = Instant::now() + Duration::from_secs(10);
            let discovered = (|| {
                let record = peer_pin::fetch_record_classified(
                    &request.source_node_id,
                    now,
                    discovery_deadline,
                )?;
                if record.node_id != request.source_node_id {
                    return Err(peer_pin::RecordFailure { error: refused(), authoritative: true });
                }
                peer_pin::checked_forward_endpoint_until(
                    &record.node_id,
                    &record.node_endpoint,
                    discovery_deadline,
                )
                .map_err(|error| peer_pin::RecordFailure { error, authoritative: false })?;
                Ok(record)
            })();
            match discovered {
                Ok(record) => {
                    candidate.record = Some(record);
                    candidate.cached_at = now;
                    candidate.failed_at = None;
                }
                Err(failure) => {
                    candidate.failed_at =
                        failure.authoritative.then_some(crate::now_unix_seconds()?);
                    candidate.record = None;
                    return Err(failure.error);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(refused());
        }
        let record = candidate.record.as_ref().ok_or_else(refused)?;
        let mut staged = (*state.snapshot()?).clone();
        staged.admit_inbound_peer_pin(&record.node_id, now)?;
        peer_pin::install_candidate(&mut staged, local, record, now)?;
        staged.ensure_federated_envelope_allowed(request, &record.node_id, now)?;
        ramflux_node_core::verify_federated_envelope_forward(request, &record.node_public_key)?;
        self.commit_candidate(record)
    }

    fn commit_candidate(
        &self,
        record: &ramflux_node_core::FederationServerRecord,
    ) -> Result<(), NodeCoreError> {
        let Self { request, state, store, local, deadline, .. } = *self;
        state.update_and_save(store, |trust| {
            let now = crate::now_unix_seconds()?;
            precheck(request, &local.node_id, now)?;
            if record.expires_at <= now
                || Instant::now() >= deadline
                || trust.peer_pin_blocked(&record.node_id, now)
            {
                return Err(refused());
            }
            if let Some(key) = trust.pinned_node_public_key(&record.node_id) {
                ramflux_node_core::verify_federated_envelope_forward(request, &key)?;
                return trust.ensure_federated_envelope_allowed(request, &record.node_id, now);
            }
            if trust.discovery_pin(&record.node_id).is_some() {
                return Err(refused());
            }
            trust.admit_inbound_peer_pin(&record.node_id, now)?;
            peer_pin::install_candidate(trust, local, record, now)?;
            trust.ensure_federated_envelope_allowed(request, &record.node_id, now)?;
            trust.mark_inbound_peer_pin(&record.node_id)
        })
    }
}
