// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::NodeCoreError;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeReplayGuardState {
    #[serde(default)]
    accepted_by_key: BTreeMap<String, i64>,
}

impl NodeReplayGuardState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when the request is expired, valid for too long, or
    /// duplicates an already accepted `(source_device_id, nonce, request_id)` tuple.
    pub fn check_signed_request(
        &mut self,
        request: &ramflux_protocol::SignedRequest,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
        let mut guard = ramflux_protocol::ReplayGuard::new();
        guard
            .check_signed_request(request, now_unix_seconds)
            .map_err(|source| NodeCoreError::ReplayGuard(source.to_string()))?;
        self.prune(now_unix_seconds);
        let key = request.replay_tuple_key();
        if self.accepted_by_key.insert(key.clone(), request.expires_at).is_some() {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {key}")));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when the envelope TTL has expired or the same
    /// `(source_device_id, envelope_id, envelope_id)` replay tuple has already been accepted.
    pub fn check_envelope(
        &mut self,
        envelope: &ramflux_protocol::Envelope,
        now_unix_seconds: i64,
    ) -> Result<(), NodeCoreError> {
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
        let key = envelope_replay_tuple_key(envelope);
        if self.accepted_by_key.insert(key.clone(), expires_at).is_some() {
            return Err(NodeCoreError::ReplayGuard(format!("replay: {key}")));
        }
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted_by_key.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted_by_key.is_empty()
    }

    pub(crate) fn accepted_entries(&self) -> impl Iterator<Item = (&String, &i64)> {
        self.accepted_by_key.iter()
    }

    pub(crate) fn restore_accepted(&mut self, key: String, expires_at: i64) {
        self.accepted_by_key.insert(key, expires_at);
    }

    fn prune(&mut self, now_unix_seconds: i64) {
        self.accepted_by_key.retain(|_key, expires_at| *expires_at >= now_unix_seconds);
    }
}

#[must_use]
pub fn envelope_replay_tuple_key(envelope: &ramflux_protocol::Envelope) -> String {
    format!("{}:{}:{}", envelope.source_device_id, envelope.envelope_id, envelope.envelope_id)
}
