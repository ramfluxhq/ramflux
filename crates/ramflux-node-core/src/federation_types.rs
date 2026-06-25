// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(unused_imports)]

use crate::ItestMvp0SubmitResponse;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FederationTrustStatus {
    Invited,
    Active,
    Suspended,
    Revoked,
    Migrated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationPeerRoute {
    pub node_id: String,
    pub endpoint: String,
    pub node_public_key_hash: String,
    #[serde(default)]
    pub node_capabilities: Vec<String>,
    pub trust_status: FederationTrustStatus,
    pub updated_at: u64,
    pub expires_at: u64,
    pub route_update_proof_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationServerRecord {
    pub schema: String,
    pub node_id: String,
    pub node_public_key: String,
    #[serde(default)]
    pub node_ca_cert_pem: String,
    pub node_endpoint: String,
    pub protocol_versions: Vec<String>,
    pub transport_backends: Vec<String>,
    pub node_capabilities: Vec<String>,
    pub node_policy_hash: String,
    pub updated_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationSrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub target: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationDiscoveryRequest {
    pub node_id: String,
    pub now: u64,
    #[serde(default)]
    pub invite_endpoint: Option<String>,
    #[serde(default)]
    pub well_known_url: Option<String>,
    #[serde(default)]
    pub dns_srv_records: Vec<FederationSrvRecord>,
    #[serde(default)]
    pub address_records: Vec<String>,
    #[serde(default)]
    pub directory_endpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FederationDiscoverySource {
    Invitation,
    WellKnown,
    DnsSrv,
    Address,
    DirectoryCache,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationDiscoveryResult {
    pub node_id: String,
    pub node_endpoint: String,
    pub node_public_key: String,
    #[serde(default)]
    pub node_ca_cert_pem: String,
    pub protocol_versions: Vec<String>,
    pub transport_backends: Vec<String>,
    pub node_capabilities: Vec<String>,
    pub expires_at: u64,
    pub source: FederationDiscoverySource,
    pub pin_state: FederationPinState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FederationPinSource {
    Invitation,
    Tofu,
    Operator,
    DirectoryCacheConfirmed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FederationPinState {
    Unpinned,
    Pinned,
    RotationPending,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationNodeKeyRotation {
    pub node_id: String,
    pub old_node_public_key: String,
    pub new_node_public_key: String,
    pub rotated_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationNodePin {
    pub node_id: String,
    pub pinned_node_public_key: String,
    #[serde(default)]
    pub pinned_ca_cert_pem: String,
    pub pin_source: FederationPinSource,
    pub first_seen_at: u64,
    pub last_verified_at: u64,
    pub pin_epoch: u64,
    pub state: FederationPinState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationNodeInvitation {
    pub invitation_id: String,
    pub inviter_node_id: String,
    pub candidate_node_id: String,
    pub candidate_node_public_key: String,
    #[serde(default)]
    pub candidate_node_ca_cert_pem: String,
    pub candidate_node_public_key_hash: String,
    pub allowed_capabilities: Vec<String>,
    pub expires_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationHandshakeAdmissionRequest {
    pub route: FederationPeerRoute,
    pub handshake: ramflux_protocol::FederationHandshake,
    pub invitation: Option<FederationNodeInvitation>,
    pub local_capabilities: Vec<String>,
    pub local_protocol_versions: Vec<String>,
    pub local_transport_backends: Vec<String>,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederationHandshakeAdmissionResponse {
    pub accepted: bool,
    pub node_id: String,
    pub trust_status: FederationTrustStatus,
    pub negotiated_capabilities: Vec<String>,
    pub capability_added: Vec<String>,
    pub capability_removed: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedFriendRequestEnvelope {
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery_class: String,
    pub required_capability: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedFriendRequestResponse {
    pub accepted: bool,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery: ItestMvp0SubmitResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedEnvelopeForwardRequest {
    #[serde(default = "default_federation_forward_signed_fields", flatten)]
    pub signed: ramflux_protocol::SignedFields,
    #[serde(default, skip_serializing)]
    pub admin_token: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery_class: String,
    pub required_capability: String,
    pub envelope: ramflux_protocol::Envelope,
}

#[must_use]
pub fn default_federation_forward_signed_fields() -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: String::new(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: String::new(),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FederatedEnvelopeForwardResponse {
    pub accepted: bool,
    pub source_node_id: String,
    pub target_node_id: String,
    pub delivery: ItestMvp0SubmitResponse,
}
