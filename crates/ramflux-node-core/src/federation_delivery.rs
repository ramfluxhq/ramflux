// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    BadNodeAdvisory, FederatedEnvelopeForwardRequest, FederatedFriendRequestEnvelope,
    FederatedLifecycleTombstoneResponse, FederationPeerRoute, FederationTrustState,
    FederationTrustStatus, NodeCoreError,
};
use ramflux_protocol::DeliveryClass;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FEDERATION_OPAQUE_DELIVERY_CAPABILITY: &str = "opaque_delivery";
const MAX_ACTIVE_NODE_BLOCKS: usize = 1024;

impl FederationTrustState {
    /// Record an operator or peer advisory. Cleared rows are dropped. A new active
    /// block is refused at the cap so a live denial is never evicted to make room.
    ///
    /// # Errors
    /// Returns [`NodeCoreError::Capacity`] when another active block would exceed the cap.
    pub fn apply_bad_node_advisory(
        &mut self,
        advisory: BadNodeAdvisory,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        self.advisories_by_id.retain(|_, row| row.expires_at > now);
        if advisory.reason_code != "block" || advisory.expires_at <= now {
            if advisory.expires_at <= now {
                self.advisories_by_id.remove(&advisory.advisory_id);
            } else {
                self.advisories_by_id.insert(advisory.advisory_id.clone(), advisory);
            }
            return Ok(());
        }
        let replacing = self
            .advisories_by_id
            .get(&advisory.advisory_id)
            .is_some_and(|row| row.reason_code == "block" && row.expires_at > now);
        if !replacing && active_block_count(self, now) >= MAX_ACTIVE_NODE_BLOCKS {
            return Err(NodeCoreError::Capacity { resource: "federation node blocks" });
        }
        self.advisories_by_id.insert(advisory.advisory_id.clone(), advisory);
        Ok(())
    }

    pub fn record_lifecycle_tombstone(&mut self, response: FederatedLifecycleTombstoneResponse) {
        self.lifecycle_tombstones_by_target.insert(response.target_delivery_id.clone(), response);
    }

    #[must_use]
    pub fn can_deliver_to(&self, node_id: &str, now: u64) -> bool {
        let route_is_active = self.routes_by_node.get(node_id).is_some_and(|route| {
            matches!(
                route.trust_status,
                FederationTrustStatus::Active | FederationTrustStatus::Migrated
            ) && route.expires_at > now
        });
        let locally_blocked = self.advisories_by_id.values().any(|advisory| {
            advisory.subject_node_id == node_id
                && advisory.reason_code == "block"
                && advisory.expires_at > now
        });
        route_is_active && !locally_blocked
    }

    #[must_use]
    pub fn route(&self, node_id: &str) -> Option<&FederationPeerRoute> {
        self.routes_by_node.get(node_id)
    }

    #[must_use]
    pub fn advisory_count(&self) -> usize {
        self.advisories_by_id.len()
    }

    #[must_use]
    pub fn lifecycle_tombstone(
        &self,
        target_delivery_id: &str,
    ) -> Option<&FederatedLifecycleTombstoneResponse> {
        self.lifecycle_tombstones_by_target.get(target_delivery_id)
    }

    #[must_use]
    pub fn negotiated_capabilities(&self, node_id: &str) -> Option<&BTreeSet<String>> {
        self.negotiated_capabilities_by_node.get(node_id)
    }

    /// # Errors
    /// Returns an error when trust is not active or the negotiated capability is missing.
    pub fn ensure_cross_node_friend_request_allowed(
        &self,
        request: &FederatedFriendRequestEnvelope,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if request.delivery_class != "opaque_event" {
            return Err(NodeCoreError::ItestHttp(
                "cross-node friend request must be opaque_event".to_owned(),
            ));
        }
        if !self.can_deliver_to(&request.target_node_id, now) {
            return Err(NodeCoreError::ItestHttp(format!(
                "federation delivery paused for {}",
                request.target_node_id
            )));
        }
        let capabilities =
            self.negotiated_capabilities_by_node.get(&request.target_node_id).ok_or_else(|| {
                NodeCoreError::ItestHttp(format!(
                    "missing negotiated capabilities for {}",
                    request.target_node_id
                ))
            })?;
        if !capabilities.contains(&request.required_capability) {
            return Err(NodeCoreError::ItestHttp(format!(
                "missing federation capability {} for {}",
                request.required_capability, request.target_node_id
            )));
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error when trust is not active or the negotiated capability is missing.
    pub fn ensure_federated_envelope_allowed(
        &self,
        request: &FederatedEnvelopeForwardRequest,
        peer_node_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if request.delivery_class != "opaque_event" {
            return Err(NodeCoreError::ItestHttp(
                "federated envelope must be opaque_event".to_owned(),
            ));
        }
        let required_capability =
            required_capability_for_federated_envelope(&request.envelope.delivery_class)?;
        if !self.can_deliver_to(peer_node_id, now) {
            return Err(NodeCoreError::ItestHttp(format!(
                "federation delivery paused for {peer_node_id}"
            )));
        }
        let capabilities =
            self.negotiated_capabilities_by_node.get(peer_node_id).ok_or_else(|| {
                NodeCoreError::ItestHttp(format!(
                    "missing negotiated capabilities for {peer_node_id}"
                ))
            })?;
        if !capabilities.contains(required_capability) {
            return Err(NodeCoreError::ItestHttp(format!(
                "missing federation capability {required_capability} for {peer_node_id}"
            )));
        }
        Ok(())
    }
}

fn active_block_count(state: &FederationTrustState, now: u64) -> usize {
    state
        .advisories_by_id
        .values()
        .filter(|row| row.reason_code == "block" && row.expires_at > now)
        .count()
}

fn required_capability_for_federated_envelope(
    delivery_class: &DeliveryClass,
) -> Result<&'static str, NodeCoreError> {
    candidate_federation_capability(delivery_class)
}

fn candidate_federation_capability(
    delivery_class: &DeliveryClass,
) -> Result<&'static str, NodeCoreError> {
    match delivery_class {
        DeliveryClass::Message | DeliveryClass::CallWake => {
            Ok(FEDERATION_OPAQUE_DELIVERY_CAPABILITY)
        }
        DeliveryClass::OpaqueEvent
        | DeliveryClass::NotificationWake
        | DeliveryClass::ObjectManifest
        | DeliveryClass::ObjectChunk
        | DeliveryClass::FederationControl => Err(NodeCoreError::DeliveryClassRefused),
    }
}
