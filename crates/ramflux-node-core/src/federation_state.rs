// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::{
    FederatedLifecycleTombstoneResponse, FederationDiscoveryRequest, FederationDiscoveryResult,
    FederationDiscoverySource, FederationHandshakeAdmissionRequest,
    FederationHandshakeAdmissionResponse, FederationNodeInvitation, FederationNodeKeyRotation,
    FederationNodePin, FederationPeerRoute, FederationPinSource, FederationPinState,
    FederationServerRecord, FederationTrustStatus, NodeCoreError, choose_srv_record, has_overlap,
    is_bootstrap_ip_literal, verify_federation_handshake, verify_federation_key_rotation,
    verify_federation_server_record, verify_node_invitation,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct FederationDiscoveryCandidate {
    node_id: String,
    node_endpoint: String,
    node_public_key: String,
    node_ca_cert_pem: String,
    protocol_versions: Vec<String>,
    transport_backends: Vec<String>,
    node_capabilities: Vec<String>,
    expires_at: u64,
    source: FederationDiscoverySource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BadNodeAdvisory {
    pub advisory_id: String,
    pub issuer_node_id: String,
    pub subject_node_id: String,
    pub reason_code: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_hash: String,
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationTrustState {
    pub(crate) routes_by_node: BTreeMap<String, FederationPeerRoute>,
    pub(crate) advisories_by_id: BTreeMap<String, BadNodeAdvisory>,
    #[serde(default)]
    pub(crate) node_signing_seed: Option<[u8; 32]>,
    #[serde(default)]
    pub(crate) lifecycle_tombstones_by_target:
        BTreeMap<String, FederatedLifecycleTombstoneResponse>,
    #[serde(default)]
    pub(crate) invitations_by_id: BTreeMap<String, FederationNodeInvitation>,
    #[serde(default)]
    pub(crate) negotiated_capabilities_by_node: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub(crate) seen_handshakes: BTreeSet<String>,
    #[serde(default)]
    pub(crate) discovery_pins_by_node: BTreeMap<String, FederationNodePin>,
}

impl fmt::Debug for FederationTrustState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederationTrustState")
            .field("routes_by_node", &self.routes_by_node)
            .field("advisories_by_id", &self.advisories_by_id)
            .field("node_signing_seed", &self.node_signing_seed.as_ref().map(|_seed| "<redacted>"))
            .field("lifecycle_tombstones_by_target", &self.lifecycle_tombstones_by_target)
            .field("invitations_by_id", &self.invitations_by_id)
            .field("negotiated_capabilities_by_node", &self.negotiated_capabilities_by_node)
            .field("seen_handshakes", &self.seen_handshakes)
            .field("discovery_pins_by_node", &self.discovery_pins_by_node)
            .finish()
    }
}

impl Drop for FederationTrustState {
    fn drop(&mut self) {
        if let Some(seed) = self.node_signing_seed.as_mut() {
            seed.fill(0);
        }
    }
}

impl FederationTrustState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn node_signing_seed(&self) -> Option<[u8; 32]> {
        self.node_signing_seed
    }

    pub fn set_node_signing_seed(&mut self, seed: [u8; 32]) {
        self.node_signing_seed = Some(seed);
    }

    pub fn upsert_route(&mut self, route: FederationPeerRoute) {
        self.routes_by_node.insert(route.node_id.clone(), route);
    }

    /// # Errors
    /// Returns an error when the record is stale, has an invalid signature, or conflicts with a pin.
    pub fn resolve_discovery_result(
        &mut self,
        request: &FederationDiscoveryRequest,
        well_known_record: Option<&FederationServerRecord>,
        rotation: Option<&FederationNodeKeyRotation>,
    ) -> Result<FederationDiscoveryResult, NodeCoreError> {
        if let Some(invite_endpoint) = request.invite_endpoint.as_ref()
            && is_bootstrap_ip_literal(invite_endpoint)
        {
            return self.resolve_basic_discovery_candidate(
                self.basic_discovery_candidate(
                    request,
                    invite_endpoint.clone(),
                    FederationDiscoverySource::Invitation,
                    request.now.saturating_add(86_400),
                ),
                request.now,
                FederationPinSource::Invitation,
                rotation,
            );
        }
        if let Some(record) = well_known_record {
            verify_federation_server_record(record, request.now)?;
            if record.node_id != request.node_id {
                return Err(NodeCoreError::ItestHttp("well-known node_id mismatch".to_owned()));
            }
            return self.pin_discovery_candidate(
                FederationDiscoveryCandidate {
                    node_id: record.node_id.clone(),
                    node_endpoint: record.node_endpoint.clone(),
                    node_public_key: record.node_public_key.clone(),
                    node_ca_cert_pem: record.node_ca_cert_pem.clone(),
                    protocol_versions: record.protocol_versions.clone(),
                    transport_backends: record.transport_backends.clone(),
                    node_capabilities: record.node_capabilities.clone(),
                    expires_at: record.expires_at,
                    source: FederationDiscoverySource::WellKnown,
                },
                request.now,
                FederationPinSource::Tofu,
                rotation,
            );
        }
        if request.dns_srv_records.len() == 1 && request.dns_srv_records[0].target == "." {
            return Err(NodeCoreError::ItestHttp(
                "federation dns srv explicit no-service".to_owned(),
            ));
        }
        if let Some(record) = choose_srv_record(&request.dns_srv_records) {
            let endpoint = format!("{}:{}", record.target, record.port);
            return self.resolve_basic_discovery_candidate(
                self.basic_discovery_candidate(
                    request,
                    endpoint,
                    FederationDiscoverySource::DnsSrv,
                    request.now.saturating_add(3_600),
                ),
                request.now,
                FederationPinSource::Tofu,
                rotation,
            );
        }
        if let Some(address) = request.address_records.first() {
            return self.resolve_basic_discovery_candidate(
                self.basic_discovery_candidate(
                    request,
                    format!("{address}:443"),
                    FederationDiscoverySource::Address,
                    request.now.saturating_add(3_600),
                ),
                request.now,
                FederationPinSource::Tofu,
                rotation,
            );
        }
        if let Some(endpoint) = request.directory_endpoint.as_ref() {
            return self.resolve_basic_discovery_candidate(
                self.basic_discovery_candidate(
                    request,
                    endpoint.clone(),
                    FederationDiscoverySource::DirectoryCache,
                    request.now.saturating_add(3_600),
                ),
                request.now,
                FederationPinSource::DirectoryCacheConfirmed,
                rotation,
            );
        }
        Err(NodeCoreError::ItestHttp(format!(
            "no federation discovery candidate for {}",
            request.node_id
        )))
    }

    #[must_use]
    pub fn discovery_pin(&self, node_id: &str) -> Option<&FederationNodePin> {
        self.discovery_pins_by_node.get(node_id)
    }

    #[must_use]
    pub fn pinned_node_public_key(&self, node_id: &str) -> Option<String> {
        self.discovery_pins_by_node
            .get(node_id)
            .filter(|pin| pin.state == FederationPinState::Pinned)
            .map(|pin| pin.pinned_node_public_key.clone())
    }

    #[must_use]
    pub fn pinned_peer_ca_cert_pem(&self, node_id: &str) -> Option<String> {
        self.discovery_pins_by_node
            .get(node_id)
            .filter(|pin| pin.state == FederationPinState::Pinned)
            .and_then(|pin| {
                if pin.pinned_ca_cert_pem.is_empty() {
                    None
                } else {
                    Some(pin.pinned_ca_cert_pem.clone())
                }
            })
    }

    #[must_use]
    pub fn pinned_peer_ca_cert_pems(&self) -> Vec<String> {
        self.discovery_pins_by_node
            .values()
            .filter(|pin| pin.state == FederationPinState::Pinned)
            .filter_map(|pin| {
                if pin.pinned_ca_cert_pem.is_empty() {
                    None
                } else {
                    Some(pin.pinned_ca_cert_pem.clone())
                }
            })
            .collect()
    }

    fn basic_discovery_candidate(
        &self,
        request: &FederationDiscoveryRequest,
        endpoint: String,
        source: FederationDiscoverySource,
        expires_at: u64,
    ) -> FederationDiscoveryCandidate {
        FederationDiscoveryCandidate {
            node_id: request.node_id.clone(),
            node_endpoint: endpoint,
            node_public_key: self.pinned_node_public_key(&request.node_id).unwrap_or_default(),
            node_ca_cert_pem: self.pinned_peer_ca_cert_pem(&request.node_id).unwrap_or_default(),
            protocol_versions: vec!["v1".to_owned()],
            transport_backends: vec!["quic_quinn".to_owned()],
            node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
            expires_at,
            source,
        }
    }

    fn resolve_basic_discovery_candidate(
        &mut self,
        candidate: FederationDiscoveryCandidate,
        now: u64,
        pin_source: FederationPinSource,
        rotation: Option<&FederationNodeKeyRotation>,
    ) -> Result<FederationDiscoveryResult, NodeCoreError> {
        if candidate.node_public_key.is_empty() {
            return Err(NodeCoreError::ItestHttp(format!(
                "unverified federation discovery candidate for {} lacks pinned node key",
                candidate.node_id
            )));
        }
        self.pin_discovery_candidate(candidate, now, pin_source, rotation)
    }

    fn pin_discovery_candidate(
        &mut self,
        candidate: FederationDiscoveryCandidate,
        now: u64,
        pin_source: FederationPinSource,
        rotation: Option<&FederationNodeKeyRotation>,
    ) -> Result<FederationDiscoveryResult, NodeCoreError> {
        let mut result = FederationDiscoveryResult {
            node_id: candidate.node_id,
            node_endpoint: candidate.node_endpoint,
            node_public_key: candidate.node_public_key,
            node_ca_cert_pem: candidate.node_ca_cert_pem,
            protocol_versions: candidate.protocol_versions,
            transport_backends: candidate.transport_backends,
            node_capabilities: candidate.node_capabilities,
            expires_at: candidate.expires_at,
            source: candidate.source,
            pin_state: FederationPinState::Unpinned,
        };
        match self.discovery_pins_by_node.get_mut(&result.node_id) {
            Some(pin) if pin.pinned_node_public_key == result.node_public_key => {
                if result.node_ca_cert_pem.is_empty() && pin.pinned_ca_cert_pem.is_empty() {
                    return Err(NodeCoreError::ItestHttp(format!(
                        "federation discovery candidate for {} lacks peer CA root",
                        result.node_id
                    )));
                }
                if !result.node_ca_cert_pem.is_empty()
                    && !pin.pinned_ca_cert_pem.is_empty()
                    && pin.pinned_ca_cert_pem != result.node_ca_cert_pem
                {
                    return Err(NodeCoreError::ItestHttp(format!(
                        "federation discovery CA pin mismatch for {}",
                        result.node_id
                    )));
                }
                if result.node_ca_cert_pem.is_empty() {
                    result.node_ca_cert_pem.clone_from(&pin.pinned_ca_cert_pem);
                } else {
                    pin.pinned_ca_cert_pem.clone_from(&result.node_ca_cert_pem);
                }
                pin.last_verified_at = now;
                pin.state = FederationPinState::Pinned;
                result.pin_state = FederationPinState::Pinned;
                Ok(result)
            }
            Some(pin) => {
                if let Some(rotation) = rotation {
                    verify_federation_key_rotation(rotation, &pin.pinned_node_public_key)?;
                    if rotation.node_id == result.node_id
                        && rotation.new_node_public_key == result.node_public_key
                    {
                        pin.pinned_node_public_key.clone_from(&result.node_public_key);
                        pin.pinned_ca_cert_pem.clone_from(&result.node_ca_cert_pem);
                        pin.last_verified_at = now;
                        pin.pin_epoch = pin.pin_epoch.saturating_add(1);
                        pin.state = FederationPinState::Pinned;
                        result.pin_state = FederationPinState::Pinned;
                        return Ok(result);
                    }
                }
                Err(NodeCoreError::ItestHttp(format!(
                    "federation discovery key pin mismatch for {}",
                    result.node_id
                )))
            }
            None => {
                if result.node_ca_cert_pem.is_empty() {
                    return Err(NodeCoreError::ItestHttp(format!(
                        "federation discovery candidate for {} lacks peer CA root",
                        result.node_id
                    )));
                }
                self.discovery_pins_by_node.insert(
                    result.node_id.clone(),
                    FederationNodePin {
                        node_id: result.node_id.clone(),
                        pinned_node_public_key: result.node_public_key.clone(),
                        pinned_ca_cert_pem: result.node_ca_cert_pem.clone(),
                        pin_source,
                        first_seen_at: now,
                        last_verified_at: now,
                        pin_epoch: 1,
                        state: FederationPinState::Pinned,
                    },
                );
                result.pin_state = FederationPinState::Pinned;
                Ok(result)
            }
        }
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn update_trust_status(
        &mut self,
        node_id: &str,
        status: FederationTrustStatus,
        updated_at: u64,
    ) -> Result<(), NodeCoreError> {
        let route = self
            .routes_by_node
            .get_mut(node_id)
            .ok_or_else(|| NodeCoreError::SessionNotFound(node_id.to_owned()))?;
        if route.trust_status == FederationTrustStatus::Revoked
            && status != FederationTrustStatus::Revoked
        {
            return Err(NodeCoreError::ItestHttp(format!(
                "revoked federation node is terminal: {node_id}"
            )));
        }
        route.trust_status = status;
        route.updated_at = updated_at;
        Ok(())
    }

    /// # Errors
    /// Returns an error when the peer has not been pinned by a verified discovery record or when
    /// there is no common federation capability.
    pub fn admit_verified_discovered_peer(
        &mut self,
        mut route: FederationPeerRoute,
        source_capabilities: &[String],
        local_capabilities: &[String],
    ) -> Result<FederationHandshakeAdmissionResponse, NodeCoreError> {
        let pin = self
            .discovery_pins_by_node
            .get(&route.node_id)
            .filter(|pin| pin.state == FederationPinState::Pinned)
            .ok_or_else(|| {
                NodeCoreError::ItestHttp(format!(
                    "federation peer {} lacks verified discovery pin",
                    route.node_id
                ))
            })?;
        let pinned_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            pin.pinned_node_public_key.as_bytes(),
        );
        if route.node_public_key_hash != pinned_hash {
            return Err(NodeCoreError::ItestHttp(
                "federation route key hash does not match pinned node key".to_owned(),
            ));
        }
        let source: BTreeSet<String> = source_capabilities.iter().cloned().collect();
        let local: BTreeSet<String> = local_capabilities.iter().cloned().collect();
        let negotiated: BTreeSet<String> = source.intersection(&local).cloned().collect();
        if negotiated.is_empty() || !negotiated.contains("opaque_delivery") {
            return Err(NodeCoreError::ItestHttp(
                "required federation capability missing".to_owned(),
            ));
        }
        let previous =
            self.negotiated_capabilities_by_node.get(&route.node_id).cloned().unwrap_or_default();
        if !previous.is_empty() && !negotiated.is_superset(&previous) {
            return Err(NodeCoreError::ItestHttp(
                "federation capability downgrade rejected".to_owned(),
            ));
        }
        route.trust_status = FederationTrustStatus::Active;
        route.node_capabilities = negotiated.iter().cloned().collect();
        route.node_capabilities.sort();
        let node_id = route.node_id.clone();
        self.routes_by_node.insert(node_id.clone(), route);
        self.negotiated_capabilities_by_node.insert(node_id.clone(), negotiated.clone());
        let mut negotiated_capabilities: Vec<String> = negotiated.iter().cloned().collect();
        negotiated_capabilities.sort();
        let mut capability_added: Vec<String> = negotiated.difference(&previous).cloned().collect();
        capability_added.sort();
        let mut capability_removed: Vec<String> =
            previous.difference(&negotiated).cloned().collect();
        capability_removed.sort();
        Ok(FederationHandshakeAdmissionResponse {
            accepted: true,
            node_id,
            trust_status: FederationTrustStatus::Active,
            negotiated_capabilities,
            capability_added,
            capability_removed,
        })
    }

    /// # Errors
    /// Returns an error when the invitation, handshake, or capability negotiation is invalid.
    pub fn admit_handshake(
        &mut self,
        request: FederationHandshakeAdmissionRequest,
    ) -> Result<FederationHandshakeAdmissionResponse, NodeCoreError> {
        let invitation = request
            .invitation
            .as_ref()
            .ok_or_else(|| NodeCoreError::ItestHttp("missing node invitation".to_owned()))?;
        verify_node_invitation(invitation, &request.route, &request.handshake, request.now)?;
        let pinned_public_key = self.pin_or_verify_invited_candidate(
            &request.route.node_id,
            &invitation.candidate_node_public_key,
            &invitation.candidate_node_ca_cert_pem,
            u64::try_from(request.now).unwrap_or_default(),
        )?;
        verify_federation_handshake(&request.handshake, &pinned_public_key)?;
        let replay_key =
            format!("{}:{}", request.handshake.source_node_id, request.handshake.handshake_id);
        if !self.seen_handshakes.insert(replay_key) {
            return Err(NodeCoreError::ItestHttp("federation handshake replay".to_owned()));
        }
        if request.handshake.source_node_id != request.route.node_id {
            return Err(NodeCoreError::ItestHttp("handshake source route mismatch".to_owned()));
        }
        if !has_overlap(&request.handshake.protocol_versions, &request.local_protocol_versions) {
            return Err(NodeCoreError::ItestHttp("no federation protocol overlap".to_owned()));
        }
        if !has_overlap(&request.handshake.transport_backends, &request.local_transport_backends) {
            return Err(NodeCoreError::ItestHttp("no federation transport overlap".to_owned()));
        }
        let allowed: BTreeSet<String> = invitation.allowed_capabilities.iter().cloned().collect();
        let local: BTreeSet<String> = request.local_capabilities.iter().cloned().collect();
        let source: BTreeSet<String> =
            request.handshake.source_capabilities.iter().cloned().collect();
        if !source.is_subset(&allowed) {
            return Err(NodeCoreError::ItestHttp(
                "source capabilities exceed invitation".to_owned(),
            ));
        }
        let negotiated: BTreeSet<String> = source.intersection(&local).cloned().collect();
        if negotiated.is_empty() || !negotiated.contains("opaque_delivery") {
            return Err(NodeCoreError::ItestHttp(
                "required federation capability missing".to_owned(),
            ));
        }
        let previous = self
            .negotiated_capabilities_by_node
            .get(&request.route.node_id)
            .cloned()
            .unwrap_or_default();
        if !previous.is_empty() && !negotiated.is_superset(&previous) {
            return Err(NodeCoreError::ItestHttp(
                "federation capability downgrade rejected".to_owned(),
            ));
        }
        let mut route = request.route;
        route.trust_status = FederationTrustStatus::Active;
        route.node_capabilities = negotiated.iter().cloned().collect();
        route.node_capabilities.sort();
        let node_id = route.node_id.clone();
        self.invitations_by_id.insert(invitation.invitation_id.clone(), invitation.clone());
        self.routes_by_node.insert(node_id.clone(), route);
        self.negotiated_capabilities_by_node.insert(node_id.clone(), negotiated.clone());
        let mut negotiated_capabilities: Vec<String> = negotiated.iter().cloned().collect();
        negotiated_capabilities.sort();
        let mut capability_added: Vec<String> = negotiated.difference(&previous).cloned().collect();
        capability_added.sort();
        let mut capability_removed: Vec<String> =
            previous.difference(&negotiated).cloned().collect();
        capability_removed.sort();
        Ok(FederationHandshakeAdmissionResponse {
            accepted: true,
            node_id,
            trust_status: FederationTrustStatus::Active,
            negotiated_capabilities,
            capability_added,
            capability_removed,
        })
    }

    fn pin_or_verify_invited_candidate(
        &mut self,
        node_id: &str,
        candidate_public_key: &str,
        candidate_ca_cert_pem: &str,
        now: u64,
    ) -> Result<String, NodeCoreError> {
        if candidate_ca_cert_pem.is_empty() {
            return Err(NodeCoreError::ItestHttp(
                "federation invitation missing candidate CA root".to_owned(),
            ));
        }
        match self.discovery_pins_by_node.get(node_id) {
            Some(pin)
                if pin.state == FederationPinState::Pinned
                    && pin.pinned_node_public_key == candidate_public_key
                    && pin.pinned_ca_cert_pem == candidate_ca_cert_pem =>
            {
                Ok(pin.pinned_node_public_key.clone())
            }
            Some(pin)
                if pin.state == FederationPinState::Pinned
                    && pin.pinned_node_public_key == candidate_public_key =>
            {
                Err(NodeCoreError::ItestHttp(
                    "federation invitation CA does not match pinned peer CA".to_owned(),
                ))
            }
            Some(pin) if pin.state == FederationPinState::Pinned => Err(NodeCoreError::ItestHttp(
                "federation invitation key does not match pinned node key".to_owned(),
            )),
            _ => {
                self.discovery_pins_by_node.insert(
                    node_id.to_owned(),
                    FederationNodePin {
                        node_id: node_id.to_owned(),
                        pinned_node_public_key: candidate_public_key.to_owned(),
                        pinned_ca_cert_pem: candidate_ca_cert_pem.to_owned(),
                        pin_source: FederationPinSource::Invitation,
                        first_seen_at: now,
                        last_verified_at: now,
                        pin_epoch: 1,
                        state: FederationPinState::Pinned,
                    },
                );
                Ok(candidate_public_key.to_owned())
            }
        }
    }
}
