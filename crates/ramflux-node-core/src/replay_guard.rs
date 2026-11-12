// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::NodeCoreError;

#[path = "replay_guard/current_entries.rs"]
mod current_entries;

/// Admission caps retain the protocol's full seven-day validity; exhaustion rejects
/// new requests rather than forgetting any unexpired identity.
pub const GATEWAY_REPLAY_SHARE: usize = 32_768;
pub const GATEWAY_REPLAY_ROOTS: usize = 64;
/// Two signed operations/minute for seven days plus 120s skew = 20,164, below each reserved share.
pub const GATEWAY_REPLAY_CAPACITY: usize = GATEWAY_REPLAY_SHARE * GATEWAY_REPLAY_ROOTS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GatewayReplayLimits {
    share: usize,
    roots: usize,
}
impl Default for GatewayReplayLimits {
    fn default() -> Self {
        Self { share: GATEWAY_REPLAY_SHARE, roots: GATEWAY_REPLAY_ROOTS }
    }
}
const PRUNE_BATCH: usize = 64;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "ReplaySnapshot")]
pub struct NodeReplayGuardState {
    accepted_by_key: BTreeMap<String, i64>,
    root_by_key: BTreeMap<String, String>,
    #[serde(skip)]
    expiry_order: BTreeSet<(i64, String)>,
    #[serde(skip)]
    count_by_root: BTreeMap<String, usize>,
    admitted_roots: BTreeSet<String>,
    #[serde(skip)]
    gateway_limits: GatewayReplayLimits,
}

#[derive(Default, Deserialize)]
struct ReplaySnapshot {
    #[serde(default, deserialize_with = "current_entries::deserialize_entries")]
    accepted_by_key: BTreeMap<String, i64>,
    #[serde(default)]
    root_by_key: BTreeMap<String, String>,
    #[serde(default)]
    admitted_roots: BTreeSet<String>,
}

impl From<ReplaySnapshot> for NodeReplayGuardState {
    fn from(snapshot: ReplaySnapshot) -> Self {
        let mut state = Self {
            accepted_by_key: snapshot.accepted_by_key,
            root_by_key: snapshot.root_by_key,
            admitted_roots: snapshot.admitted_roots,
            ..Self::default()
        };
        state.rebuild_indexes();
        state
    }
}

impl NodeReplayGuardState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when the request is expired, valid for too long, or
    /// duplicates an already accepted root-qualified device, nonce and request-id tuple.
    pub fn check_signed_request(
        &mut self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
        let mut guard = ramflux_protocol::ReplayGuard::new();
        guard
            .check_signed_request(source, request, now_unix_seconds)
            .map_err(|source| NodeCoreError::ReplayGuard(source.to_string()))?;
        self.prune(now_unix_seconds);
        let key = request
            .replay_tuple_key(source)
            .map_err(|source| NodeCoreError::ReplayGuard(source.to_string()))?;
        if self.accepted_by_key.contains_key(&key) {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {key}")));
        }
        self.insert_entry(key, request.expires_at);
        Ok(())
    }

    /// Gateway-only signed-request admission with durable reserved account-root shares.
    /// # Errors
    /// Rejects invalid/replayed requests or exhaustion of this root's reserved share/root budget.
    pub fn check_gateway_signed_request(
        &mut self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        request: &ramflux_protocol::SignedRequest,
        now: i64,
    ) -> Result<(), NodeCoreError> {
        let mut validation = ramflux_protocol::ReplayGuard::new();
        validation
            .check_signed_request(source, request, now)
            .map_err(|error| NodeCoreError::ReplayGuard(error.to_string()))?;
        self.prune(now);
        let key = request
            .replay_tuple_key(source)
            .map_err(|error| NodeCoreError::ReplayGuard(error.to_string()))?;
        self.accept_gateway_request_key(
            key,
            source.root_commitment().to_owned(),
            request.expires_at,
        )
    }

    /// # Errors
    /// Returns an error when the envelope TTL has expired or the same
    /// root-qualified device, envelope-id and target replay tuple has already been accepted.
    pub fn check_envelope(
        &mut self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
        if self.accept_envelope_once(source, envelope, now_unix_seconds)? {
            return Ok(());
        }
        Err(NodeCoreError::ReplayGuard(format!(
            "replay: {}",
            envelope_replay_tuple_key(source, envelope)
        )))
    }

    /// Validates an envelope and records its replay identity if it is new.
    ///
    /// Returns `false` for an already-recorded identity. Callers may use that result only when
    /// their downstream operation has its own durable idempotency receipt.
    ///
    /// # Errors
    /// Returns an error when identity binding, TTL, or timestamp validation fails.
    pub fn accept_envelope_once(
        &mut self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<bool, NodeCoreError> {
        if envelope.source_device_id != source.device_id()
            && envelope.source_device_id != source.storage_key()
        {
            return Err(NodeCoreError::ReplayGuard("envelope source identity mismatch".into()));
        }
        if envelope
            .ext
            .ext
            .get("source_root_commitment")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|root| root != source.root_commitment())
        {
            return Err(NodeCoreError::ReplayGuard("envelope source root mismatch".into()));
        }
        let ttl = i64::from(envelope.ttl);
        if ttl > ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS {
            return Err(NodeCoreError::ReplayGuard(format!(
                "envelope ttl exceeds maximum accepted ttl: {}",
                envelope.envelope_id
            )));
        }
        let expires_at = envelope.created_at.checked_add(ttl).ok_or_else(|| {
            NodeCoreError::TtlExpired { envelope_id: envelope.envelope_id.clone() }
        })?;
        if now_unix_seconds > expires_at {
            return Err(NodeCoreError::TtlExpired { envelope_id: envelope.envelope_id.clone() });
        }
        if envelope.created_at > now_unix_seconds + ramflux_protocol::MAX_CLOCK_SKEW_SECONDS {
            return Err(NodeCoreError::ReplayGuard(format!(
                "envelope created in future: {}",
                envelope.envelope_id
            )));
        }
        self.prune(now_unix_seconds);
        let key = envelope_replay_tuple_key(source, envelope);
        if self.accepted_by_key.contains_key(&key) {
            return Ok(false);
        }
        self.insert_entry(key, expires_at);
        Ok(true)
    }

    pub(crate) fn holds_envelope(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        envelope: &ramflux_protocol::Envelope,
        now: i64,
    ) -> bool {
        let key = envelope_replay_tuple_key(source, envelope);
        self.accepted_by_key.get(&key).is_some_and(|expiry| *expiry >= now)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted_by_key.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted_by_key.is_empty()
    }

    pub(crate) fn retain_keys(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.accepted_by_key.retain(|key, _| keep(key));
        self.rebuild_indexes();
    }

    pub(crate) fn accepted_entries(&self) -> impl Iterator<Item = (&String, &i64)> {
        self.accepted_by_key.iter()
    }

    pub(crate) fn restore_accepted(&mut self, key: String, expires_at: i64) {
        self.insert_entry(key, expires_at);
    }

    pub(crate) fn prune(&mut self, now_unix_seconds: i64) {
        for _ in 0..PRUNE_BATCH {
            let Some((expiry, key)) = self.expiry_order.first() else { break };
            if *expiry >= now_unix_seconds {
                break;
            }
            let key = key.clone();
            self.remove_entry(&key);
        }
    }

    fn accept_gateway_request_key(
        &mut self,
        key: String,
        owner: String,
        expiry: i64,
    ) -> Result<(), NodeCoreError> {
        if self.accepted_by_key.contains_key(&key) {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {key}")));
        }
        if self.count_by_root.get(&owner).copied().unwrap_or(0) >= self.gateway_limits.share
            || (!self.admitted_roots.contains(&owner)
                && self.admitted_roots.len() >= self.gateway_limits.roots)
        {
            return Err(NodeCoreError::GatewayReplayCapacity);
        }
        self.admitted_roots.insert(owner.clone());
        self.root_by_key.insert(key.clone(), owner.clone());
        *self.count_by_root.entry(owner).or_default() += 1;
        self.insert_entry(key, expiry);
        Ok(())
    }

    fn insert_entry(&mut self, key: String, expiry: i64) {
        if let Some(old) = self.accepted_by_key.insert(key.clone(), expiry) {
            self.expiry_order.remove(&(old, key.clone()));
        }
        self.expiry_order.insert((expiry, key));
    }

    fn remove_entry(&mut self, key: &str) {
        if let Some(expiry) = self.accepted_by_key.remove(key) {
            self.expiry_order.remove(&(expiry, key.to_owned()));
        }
        if let Some(owner) = self.root_by_key.remove(key)
            && let Some(count) = self.count_by_root.get_mut(&owner)
        {
            *count -= 1;
            if *count == 0 {
                self.count_by_root.remove(&owner);
            }
        }
    }

    fn rebuild_indexes(&mut self) {
        self.expiry_order =
            self.accepted_by_key.iter().map(|(key, expiry)| (*expiry, key.clone())).collect();
        self.root_by_key.retain(|key, _| self.accepted_by_key.contains_key(key));
        self.count_by_root.clear();
        for owner in self.root_by_key.values() {
            *self.count_by_root.entry(owner.clone()).or_default() += 1;
        }
    }

    pub(crate) fn restore_owned_request(&mut self, key: String, owner: String, expiry: i64) {
        self.remove_entry(&key);
        self.admitted_roots.insert(owner.clone());
        self.root_by_key.insert(key.clone(), owner.clone());
        *self.count_by_root.entry(owner).or_default() += 1;
        self.insert_entry(key, expiry);
    }

    pub(crate) fn restore_gateway_root(&mut self, root: String) {
        self.admitted_roots.insert(root);
    }
}

#[cfg(test)]
#[path = "replay_guard/bounds_tests.rs"]
mod bounds_tests;

#[must_use]
pub fn envelope_replay_tuple_key(
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    envelope: &ramflux_protocol::Envelope,
) -> String {
    format!(
        "envelope/v3/{}/{}/{}",
        source.storage_key(),
        ramflux_protocol::encode_base64url(&envelope.envelope_id),
        ramflux_protocol::encode_base64url(&envelope.target_delivery_id)
    )
}
