// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]

use crate::{
    FederatedEnvelopeForwardRequest, FederationNodeInvitation, FederationNodeKeyRotation,
    FederationPeerRoute, FederationServerRecord, FederationSrvRecord, NodeCoreError,
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn verify_node_invitation(
    invitation: &FederationNodeInvitation,
    route: &FederationPeerRoute,
    handshake: &ramflux_protocol::FederationHandshake,
    now: i64,
) -> Result<(), NodeCoreError> {
    if invitation.expires_at <= now {
        return Err(NodeCoreError::ItestHttp("node invitation expired".to_owned()));
    }
    if invitation.candidate_node_id != route.node_id
        || invitation.candidate_node_id != handshake.source_node_id
    {
        return Err(NodeCoreError::ItestHttp("node invitation candidate mismatch".to_owned()));
    }
    if invitation.candidate_node_ca_cert_pem.trim().is_empty() {
        return Err(NodeCoreError::ItestHttp("node invitation missing candidate CA".to_owned()));
    }
    let expected_key_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::FEDERATION_HANDSHAKE,
        invitation.candidate_node_public_key.as_bytes(),
    );
    if invitation.candidate_node_public_key_hash != expected_key_hash
        || invitation.candidate_node_public_key_hash != route.node_public_key_hash
    {
        return Err(NodeCoreError::ItestHttp("node invitation key hash mismatch".to_owned()));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(invitation)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &invitation.signature,
        &invitation.candidate_node_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

pub(crate) fn verify_federation_handshake(
    handshake: &ramflux_protocol::FederationHandshake,
    pinned_public_key: &str,
) -> Result<(), NodeCoreError> {
    let signed_bytes = ramflux_protocol::signed_bytes(handshake)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &handshake.signed.signature,
        pinned_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

/// # Errors
/// Returns an error when canonical signing fails.
pub fn sign_federated_envelope_forward(
    request: &mut FederatedEnvelopeForwardRequest,
    signing_seed: [u8; 32],
) -> Result<(), NodeCoreError> {
    request.signed.signing_key_id = format!("{}#federation", request.source_node_id);
    request.signed.signature_alg = ramflux_protocol::SignatureAlg::Ed25519;
    request.signed.signature.clear();
    request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(request, signing_seed)
            .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

/// # Errors
/// Returns an error when the forward proof is missing or cannot be verified with the pinned key.
pub fn verify_federated_envelope_forward(
    request: &FederatedEnvelopeForwardRequest,
    pinned_public_key: &str,
) -> Result<(), NodeCoreError> {
    verify_federated_envelope_forward_with_timings(request, pinned_public_key).map(|_timings| ())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FederatedEnvelopeForwardVerifyTimings {
    pub signing_body: Duration,
    pub signature_parse: Duration,
    pub public_key_parse: Duration,
    pub verify: Duration,
}

/// Verifies a federation envelope forward proof and returns internal timing segments.
///
/// # Errors
/// Returns an error when the forward proof is missing or cannot be verified with the pinned key.
pub fn verify_federated_envelope_forward_with_timings(
    request: &FederatedEnvelopeForwardRequest,
    pinned_public_key: &str,
) -> Result<FederatedEnvelopeForwardVerifyTimings, NodeCoreError> {
    if request.signed.signing_key_id != format!("{}#federation", request.source_node_id) {
        return Err(NodeCoreError::ItestHttp(
            "federation forward signing key id mismatch".to_owned(),
        ));
    }
    if request.signed.signature.is_empty() {
        return Err(NodeCoreError::ItestHttp("missing federation forward signature".to_owned()));
    }
    let signing_body_started = Instant::now();
    let signed_bytes = ramflux_protocol::signed_bytes(request)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    let signing_body = signing_body_started.elapsed();
    let verify_timings = ramflux_crypto::verify_canonical_signature_with_timings(
        &signed_bytes,
        &request.signed.signature,
        pinned_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(FederatedEnvelopeForwardVerifyTimings {
        signing_body,
        signature_parse: verify_timings.signature_parse,
        public_key_parse: verify_timings.public_key_parse,
        verify: verify_timings.verify,
    })
}

pub(crate) fn has_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.iter().any(|candidate| candidate == value))
}

/// # Errors
/// Returns an error when canonical signing or fixture signing fails.
pub fn sign_federation_server_record(
    record: &mut FederationServerRecord,
) -> Result<(), NodeCoreError> {
    record.signature = ramflux_crypto::sign_protocol_object(record)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

/// # Errors
/// Returns an error when canonical signing or seed signing fails.
pub fn sign_federation_server_record_with_seed(
    record: &mut FederationServerRecord,
    seed: [u8; 32],
) -> Result<(), NodeCoreError> {
    record.signature = ramflux_crypto::sign_protocol_object_with_seed(record, seed)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

/// # Errors
/// Returns an error when the record is stale, too far in the future, or has an invalid signature.
pub fn verify_federation_server_record(
    record: &FederationServerRecord,
    now: u64,
) -> Result<(), NodeCoreError> {
    if record.schema != "ramflux.well_known_server.v1" {
        return Err(NodeCoreError::ItestHttp("invalid federation discovery schema".to_owned()));
    }
    if record.node_ca_cert_pem.trim().is_empty() {
        return Err(NodeCoreError::ItestHttp("federation discovery record missing CA".to_owned()));
    }
    let allowed_clock_skew = 300_u64;
    if record.expires_at.saturating_add(allowed_clock_skew) < now {
        return Err(NodeCoreError::ItestHttp("federation discovery record expired".to_owned()));
    }
    if record.updated_at > now.saturating_add(allowed_clock_skew) {
        return Err(NodeCoreError::ItestHttp(
            "federation discovery record issued in the future".to_owned(),
        ));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(record)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &record.signature,
        &record.node_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

/// # Errors
/// Returns an error when the rotation proof is not signed by the old pinned key.
pub fn sign_federation_key_rotation(
    rotation: &mut FederationNodeKeyRotation,
) -> Result<(), NodeCoreError> {
    rotation.signature = ramflux_crypto::sign_protocol_object(rotation)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

pub(crate) fn verify_federation_key_rotation(
    rotation: &FederationNodeKeyRotation,
    pinned_public_key: &str,
) -> Result<(), NodeCoreError> {
    if rotation.old_node_public_key != pinned_public_key {
        return Err(NodeCoreError::ItestHttp(
            "federation key rotation old key mismatch".to_owned(),
        ));
    }
    let signed_bytes = ramflux_protocol::signed_bytes(rotation)
        .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))?;
    ramflux_crypto::verify_canonical_signature(
        &signed_bytes,
        &rotation.signature,
        pinned_public_key,
    )
    .map_err(|source| NodeCoreError::ItestHttp(source.to_string()))
}

pub(crate) fn choose_srv_record(records: &[FederationSrvRecord]) -> Option<&FederationSrvRecord> {
    records
        .iter()
        .filter(|record| record.target != ".")
        .min_by_key(|record| (record.priority, u16::MAX.saturating_sub(record.weight)))
}

pub(crate) fn is_bootstrap_ip_literal(endpoint: &str) -> bool {
    let host = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split_once(':')
        .map_or(endpoint, |(host, _port)| host);
    host.parse::<std::net::IpAddr>().is_ok()
}
