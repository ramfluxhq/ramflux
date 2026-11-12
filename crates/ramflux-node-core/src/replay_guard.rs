// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::NodeCoreError;

#[path = "replay_guard/legacy_replay.rs"]
mod legacy_replay;

/// Admission caps retain the protocol's full seven-day validity; exhaustion rejects
/// new requests rather than forgetting any unexpired identity.
pub const MAX_REQUESTS_PER_DEVICE: usize = 4096;
pub const MAX_REPLAY_ENTRIES: usize = 262_144;
const PRUNE_BATCH: usize = 64;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "ReplaySnapshot")]
pub struct NodeReplayGuardState {
    accepted_by_key: BTreeMap<String, i64>,
    owners_by_key: BTreeMap<String, String>,
    #[serde(skip)]
    expiry_order: BTreeSet<(i64, String)>,
    #[serde(skip)]
    count_by_owner: BTreeMap<String, usize>,
    #[serde(skip)]
    unowned_requests: usize,
}

#[derive(Default, Deserialize)]
struct ReplaySnapshot {
    #[serde(default, deserialize_with = "legacy_replay::deserialize_entries")]
    accepted_by_key: BTreeMap<String, i64>,
    #[serde(default)]
    owners_by_key: BTreeMap<String, String>,
}

impl From<ReplaySnapshot> for NodeReplayGuardState {
    fn from(snapshot: ReplaySnapshot) -> Self {
        let mut state = Self {
            accepted_by_key: snapshot.accepted_by_key,
            owners_by_key: snapshot.owners_by_key,
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
        self.accept_request_key(key, source.storage_key().to_owned(), request.expires_at)
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
        let legacy = format!(
            "envelope/v2/{}/{}",
            source.storage_key(),
            ramflux_protocol::encode_base64url(&envelope.envelope_id)
        );
        let isolated = format!("legacy/replay/{}", ramflux_protocol::encode_base64url(&legacy));
        if self.accepted_by_key.contains_key(&key)
            || self.accepted_by_key.contains_key(&legacy)
            || self.accepted_by_key.contains_key(&isolated)
        {
            return Ok(false);
        }
        if self.accepted_by_key.len() >= MAX_REPLAY_ENTRIES {
            return Err(NodeCoreError::ReplayGuard("replay capacity exhausted".into()));
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
        let legacy = format!(
            "envelope/v2/{}/{}",
            source.storage_key(),
            ramflux_protocol::encode_base64url(&envelope.envelope_id)
        );
        let isolated = format!("legacy/replay/{}", ramflux_protocol::encode_base64url(&legacy));
        [key, legacy, isolated]
            .iter()
            .any(|key| self.accepted_by_key.get(key).is_some_and(|expiry| *expiry >= now))
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
        let key = legacy_replay::isolate_unknown_key(key);
        if !self.accepted_by_key.contains_key(&key) && Self::unowned_request_key(&key) {
            self.unowned_requests += 1;
        }
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

    fn accept_request_key(
        &mut self,
        key: String,
        owner: String,
        expiry: i64,
    ) -> Result<(), NodeCoreError> {
        if self.accepted_by_key.contains_key(&key) {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {key}")));
        }
        // Old hashed request rows carry no recoverable owner. Charge them to
        // every device conservatively until they expire.
        let unknown = self.unowned_requests;
        if self.accepted_by_key.len() >= MAX_REPLAY_ENTRIES
            || self.count_by_owner.get(&owner).copied().unwrap_or(0).saturating_add(unknown)
                >= MAX_REQUESTS_PER_DEVICE
        {
            return Err(NodeCoreError::ReplayGuard("replay capacity exhausted".into()));
        }
        self.owners_by_key.insert(key.clone(), owner.clone());
        *self.count_by_owner.entry(owner).or_default() += 1;
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
            if !self.owners_by_key.contains_key(key) && Self::unowned_request_key(key) {
                self.unowned_requests -= 1;
            }
        }
        if let Some(owner) = self.owners_by_key.remove(key)
            && let Some(count) = self.count_by_owner.get_mut(&owner)
        {
            *count -= 1;
            if *count == 0 {
                self.count_by_owner.remove(&owner);
            }
        }
    }

    fn rebuild_indexes(&mut self) {
        self.expiry_order =
            self.accepted_by_key.iter().map(|(key, expiry)| (*expiry, key.clone())).collect();
        self.owners_by_key.retain(|key, _| self.accepted_by_key.contains_key(key));
        self.unowned_requests = self
            .accepted_by_key
            .keys()
            .filter(|key| !self.owners_by_key.contains_key(*key) && Self::unowned_request_key(key))
            .count();
        self.count_by_owner.clear();
        for owner in self.owners_by_key.values() {
            *self.count_by_owner.entry(owner.clone()).or_default() += 1;
        }
    }

    fn unowned_request_key(key: &str) -> bool {
        key.starts_with("request/v2/") || key.starts_with("legacy/replay/")
    }

    pub(crate) fn restore_owned_request(&mut self, key: String, owner: String, expiry: i64) {
        self.remove_entry(&key);
        self.owners_by_key.insert(key.clone(), owner.clone());
        *self.count_by_owner.entry(owner).or_default() += 1;
        self.insert_entry(key, expiry);
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
