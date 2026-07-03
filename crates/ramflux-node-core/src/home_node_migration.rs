// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::NodeCoreError;
use serde::{Deserialize, Serialize};

pub const HOME_NODE_ROUTE_RECORD_DOMAIN: &str = "ramflux.home_node_route_record.v1";
pub const HOME_NODE_ROUTE_UPDATE_PROOF_DOMAIN: &str = "ramflux.home_node_route_update_proof.v1";
pub const HOME_NODE_FORWARD_WINDOW_SECONDS: i64 = 24 * 60 * 60;
pub const HOME_NODE_FORWARD_COUNT_EXT_KEY: &str = "home_node_migration_forward_count";

/// Applied home-node migration state for one identity binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationRecord {
    pub identity_commitment: String,
    pub old_home_node: String,
    pub new_home_node: String,
    pub new_home_node_key_hash: String,
    pub route_record_hash: String,
    pub effective_at: i64,
    pub issued_at: i64,
    pub migration_proof_hash: String,
    pub migrated_at: i64,
}

impl HomeNodeMigrationRecord {
    #[must_use]
    pub fn is_effective(&self, now: i64) -> bool {
        now >= self.effective_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigratedNackDelivery {
    pub target_delivery_id: String,
    pub proof_hash: String,
    pub new_home_node_hint: String,
    pub nack: ramflux_protocol::Nack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationForwardPlan {
    pub target_delivery_id: String,
    pub proof_hash: String,
    pub new_home_node: String,
    pub route: HomeNodeRouteRecord,
    pub envelope: ramflux_protocol::Envelope,
    pub forward_count: u8,
}

impl HomeNodeMigrationForwardPlan {
    #[must_use]
    pub fn federated_forward_request(
        &self,
        source_node_id: &str,
    ) -> crate::FederatedEnvelopeForwardRequest {
        crate::FederatedEnvelopeForwardRequest {
            signed: crate::default_federation_forward_signed_fields(),
            admin_token: String::new(),
            source_node_id: source_node_id.to_owned(),
            target_node_id: self.route.home_node.clone(),
            delivery_class: "opaque_event".to_owned(),
            required_capability: "opaque_delivery".to_owned(),
            envelope: self.envelope.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationForwardDelivery {
    pub target_delivery_id: String,
    pub proof_hash: String,
    pub new_home_node_hint: String,
    pub route: HomeNodeRouteRecord,
    pub delivery: crate::EnvelopeSubmitResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationApplyRequest {
    #[serde(default)]
    pub admin_token: String,
    pub proof: ramflux_protocol::HomeNodeMigrationProof,
    pub branch_proof: ramflux_crypto::BranchProofDocument,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeMigrationApplyResponse {
    pub record: HomeNodeMigrationRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeRouteUpdateApplyRequest {
    #[serde(default)]
    pub admin_token: String,
    pub proof: HomeNodeRouteUpdateProof,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeRouteUpdateApplyResponse {
    pub record: HomeNodeRouteRecord,
}

/// Canonical route commitment referenced by a home-node migration proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HomeNodeRouteRecordCommitment {
    pub schema: String,
    pub domain: String,
    pub new_home_node: String,
    pub new_home_node_key_hash: String,
    pub node_public_key: String,
    pub node_endpoint: String,
    pub expires_at: i64,
}

/// Directory route update proof that binds a migrated identity to its new home node route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HomeNodeRouteUpdateProof {
    pub schema: String,
    pub domain: String,
    #[serde(flatten)]
    pub signed: ramflux_protocol::SignedFields,
    pub identity_commitment: String,
    pub new_home_node: String,
    pub new_home_node_key_hash: String,
    pub node_public_key: String,
    pub node_endpoint: String,
    pub route_record_hash: String,
    pub migration_proof_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Applied directory route projection for one identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeNodeRouteRecord {
    pub identity_commitment: String,
    pub home_node: String,
    pub home_node_key_hash: String,
    pub node_public_key: String,
    pub node_endpoint: String,
    pub route_record_hash: String,
    pub migration_proof_hash: String,
    pub route_update_proof_hash: String,
    pub updated_at: i64,
    pub expires_at: i64,
}

/// # Errors
/// Returns an error when the route commitment cannot be canonicalized.
pub fn home_node_route_record_hash(
    commitment: &HomeNodeRouteRecordCommitment,
) -> Result<String, NodeCoreError> {
    let canonical = ramflux_protocol::canonical_json_bytes(commitment)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(HOME_NODE_ROUTE_RECORD_DOMAIN, &canonical))
}

/// # Errors
/// Returns an error when the proof cannot be canonicalized.
pub fn home_node_route_update_proof_hash(
    proof: &HomeNodeRouteUpdateProof,
) -> Result<String, NodeCoreError> {
    let signed_bytes = ramflux_protocol::signed_bytes(proof)
        .map_err(|source| NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ramflux_crypto::blake3_256_base64url(HOME_NODE_ROUTE_UPDATE_PROOF_DOMAIN, &signed_bytes))
}

#[must_use]
pub fn home_node_route_commitment_from_update(
    proof: &HomeNodeRouteUpdateProof,
) -> HomeNodeRouteRecordCommitment {
    HomeNodeRouteRecordCommitment {
        schema: HOME_NODE_ROUTE_RECORD_DOMAIN.to_owned(),
        domain: HOME_NODE_ROUTE_RECORD_DOMAIN.to_owned(),
        new_home_node: proof.new_home_node.clone(),
        new_home_node_key_hash: proof.new_home_node_key_hash.clone(),
        node_public_key: proof.node_public_key.clone(),
        node_endpoint: proof.node_endpoint.clone(),
        expires_at: proof.expires_at,
    }
}
