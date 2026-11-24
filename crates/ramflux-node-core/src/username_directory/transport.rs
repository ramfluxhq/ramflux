// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reporting-home requests bind exact body bytes, endpoint, audience and the live TLS channel.
use super::{CheckpointError, Result, canonical, config::validate_node, fixed, require};
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{home_migration::ResolveResult, username_directory as wire};
use serde::{Deserialize, Serialize};

// One bounded historical custody record accompanies a signed reach policy in addition to
// the existing home history. The complete frame remains below the private 2 MiB frame cap.
pub const MAX_EVIDENCE_BYTES: usize =
    1024 * 1024 + ramflux_protocol::custody::MAX_RECORD_BYTES + 8192;
pub const MAX_REPORT_BYTES: usize = MAX_EVIDENCE_BYTES + 16 * 1024;
pub const REPORT_PROOF_DOMAIN: &str = "ramflux.identity.username_reporting_home.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPhase {
    Reserve,
    Commit,
    Abort,
}

/// Exact canonical inner document; transported separately so its hash covers received bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectoryRequest {
    Mutate {
        phase: MutationPhase,
        operation: Box<wire::UsernameOperation>,
        profile: Option<Box<wire::SignedIdentityProfileV2>>,
    },
    Status {
        operation_id: Option<String>,
    },
    Resolve {
        name: String,
        nonce: String,
    },
    Revalidate {
        request: wire::HomeRevalidateRequest,
    },
}

impl DirectoryRequest {
    #[must_use]
    pub const fn path(&self) -> &'static str {
        match self {
            Self::Mutate { .. } => "/v1/usernames/mutate",
            Self::Status { .. } => "/v1/usernames/status",
            Self::Resolve { .. } => "/v1/usernames/resolve",
            Self::Revalidate { .. } => "/v1/usernames/revalidate",
        }
    }

    /// # Errors
    /// Refuses malformed inner records, names, IDs and all avatar candidates in this module.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Mutate { operation, profile, .. } => {
                wire::encode(operation.as_ref())?;
                if let Some(profile) = profile {
                    wire::encode(profile.as_ref())?;
                    require(profile.body.avatar.is_none(), "avatar_out_of_scope")?;
                }
            }
            Self::Status { operation_id } => {
                if let Some(id) = operation_id {
                    fixed(id)?;
                }
            }
            Self::Resolve { name, nonce } => {
                wire::validate_username(name)?;
                fixed(nonce)?;
            }
            Self::Revalidate { request } => {
                wire::encode(request)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingProofBody {
    pub version: u8,
    pub audience: String,
    pub generation: u64,
    pub home: String,
    pub root: String,
    pub method: String,
    pub path: String,
    pub body_hash: String,
    pub evidence_hash: String,
    pub channel_binding: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingEvidence {
    pub reach: Option<ramflux_protocol::account_reach::ReachRecord>,
    pub discovery: crate::FederationServerRecord,
    pub history: ResolveResult,
    pub service: super::SignedHomeServiceAddress,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingRequest {
    pub proof: wire::Signed<ReportingProofBody>,
    pub evidence: ReportingEvidence,
    pub request: DirectoryRequest,
}

/// Facts supplied only by the authenticated TLS adapter, not by JSON or forwarded headers.
pub struct ReportingChannel<'a> {
    pub node_id: &'a str,
    pub node_key: &'a str,
    pub exporter: &'a [u8; 32],
}

pub struct VerifiedReporter {
    pub(crate) root: String,
    pub(crate) home: String,
    pub(crate) master: ed25519_dalek::VerifyingKey,
    pub(crate) history: ramflux_crypto::home_migration::VerifiedHome,
    pub(crate) nonce: String,
    pub(crate) expires_at: u64,
    pub(crate) service: super::SignedHomeServiceAddress,
    pub(crate) reach: Option<ramflux_protocol::account_reach::ReachRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFloor {
    pub reach: Option<ramflux_protocol::account_reach::ReachRecord>,
    pub epoch: u64,
    pub hash: String,
    pub home: String,
    pub master_public_key: String,
    pub service: super::SignedHomeServiceAddress,
}

impl VerifiedReporter {
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }
}

/// # Errors
/// Bounds input before parsing, rejects duplicate/unknown fields and requires exact canonical bytes.
pub fn decode_reporting_request(bytes: &[u8]) -> Result<ReportingRequest> {
    require(bytes.len() <= MAX_REPORT_BYTES, "report_size")?;
    let value: ReportingRequest = ramflux_protocol::parse_i_json(bytes)
        .map_err(|_| CheckpointError::Refused("report_json"))?;
    require(canonical(&value)? == bytes, "report_canonical")?;
    value.request.validate()?;
    require(canonical(&value.evidence)?.len() <= MAX_EVIDENCE_BYTES, "evidence_size")?;
    Ok(value)
}

/// Fresh proof uses the existing node signer, never an account-master ceremony.
/// # Errors
/// Refuses malformed fields; the receiver independently verifies transport and account history.
pub fn sign_reporting_proof(
    key: &SigningKey,
    body: ReportingProofBody,
) -> Result<wire::Signed<ReportingProofBody>> {
    validate_proof(&body)?;
    Ok(wire::Signed {
        signature: ramflux_protocol::encode_base64url(key.sign(&proof_bytes(&body)?).to_bytes()),
        body,
    })
}

/// Signature/history admission only. The service must durably consume nonce before dispatch,
/// enforce quotas, and retain the verified home-history floor in the same protected authority.
/// # Errors
/// Refuses wrong channel/audience/body, stale proofs, malformed history and nonterminal reporters.
pub fn verify_reporting_request(
    value: &ReportingRequest,
    channel: &ReportingChannel<'_>,
    pin: &super::CenterPin,
    retained: Option<&HomeFloor>,
    now: u64,
) -> Result<VerifiedReporter> {
    let p = &value.proof.body;
    validate_proof(p)?;
    value.request.validate()?;
    require(
        canonical(value)?.len() <= MAX_REPORT_BYTES
            && canonical(&value.evidence)?.len() <= MAX_EVIDENCE_BYTES,
        "report_size",
    )?;
    require(p.audience == pin.id && p.generation == pin.generation, "proof_audience")?;
    require(p.method == "POST" && p.path == value.request.path(), "proof_endpoint")?;
    require(
        p.home == channel.node_id
            && p.channel_binding == ramflux_protocol::encode_base64url(channel.exporter),
        "proof_channel",
    )?;
    require(p.issued_at <= now && now < p.expires_at, "proof_expired")?;
    require(
        p.body_hash == digest(&value.request)? && p.evidence_hash == digest(&value.evidence)?,
        "proof_hash",
    )?;
    let discovery = &value.evidence.discovery;
    require(
        discovery.node_id == channel.node_id && discovery.node_public_key == channel.node_key,
        "proof_discovery",
    )?;
    crate::verify_federation_server_record(discovery, now)
        .map_err(|_| CheckpointError::Refused("proof_discovery"))?;
    value.evidence.service.verify(channel.node_id, channel.node_key, now)?;
    require(value.evidence.service.body.ca_cert_pem == discovery.node_ca_cert_pem, "service_ca")?;
    ramflux_crypto::verify_canonical_signature(
        &proof_bytes(p)?,
        &value.proof.signature,
        channel.node_key,
    )
    .map_err(|_| CheckpointError::Refused("proof_signature"))?;
    let history = &value.evidence.history;
    let first = history.predecessors.first().unwrap_or(&history.home);
    require(
        matches!(first.record, ramflux_protocol::home_migration::HomeRecord::Genesis { .. }),
        "home_genesis",
    )?;
    let verified = ramflux_crypto::home_migration::verify_home_chain(history, first, now)
        .map_err(|_| CheckpointError::Refused("home_history"))?;
    if let Some(retained) = retained {
        require(verified.extends(retained.epoch, &retained.hash), "home_floor")?;
    }
    require(
        verified.evidence().record.account_anchor() == p.root
            && verified.home() == (channel.node_id, channel.node_key),
        "home_terminal",
    )?;
    let master = ramflux_crypto::verifying_key_from_base64url(
        &verified.evidence().authority.record.body.master_certificate.body.master_public_key,
    )
    .map_err(|_| CheckpointError::Refused("master_key"))?;
    if let Some(reach) = &value.evidence.reach {
        ramflux_crypto::account_reach::verify_reach_policy(&reach.policy, &reach.authority)
            .map_err(|_| CheckpointError::Refused("reach_signature"))?;
        require(reach.policy.body.account_anchor == p.root, "reach_report_root")?;
    }
    if let Some(old) = retained.and_then(|floor| floor.reach.as_ref()) {
        let new =
            value.evidence.reach.as_ref().ok_or(CheckpointError::Refused("reach_downgrade"))?;
        require(new.policy.body.revision >= old.policy.body.revision, "reach_rollback")?;
        require(
            new.policy.body.revision != old.policy.body.revision || new == old,
            "reach_equivocation",
        )?;
    }
    if let DirectoryRequest::Mutate { operation, profile, .. } = &value.request {
        require(operation.body.principal_commitment == p.root, "operation_root")?;
        if let Some(profile) = profile {
            require(profile.body.principal_commitment == p.root, "profile_root")?;
        }
        if let Some(binding) = &operation.body.binding {
            require(binding.body.node == p.home, "binding_home")?;
        }
    }
    if let DirectoryRequest::Revalidate { request } = &value.request {
        require(request.root == p.root, "revalidation_root")?;
    }
    Ok(VerifiedReporter {
        root: p.root.clone(),
        home: p.home.clone(),
        master,
        history: verified,
        nonce: p.nonce.clone(),
        expires_at: p.expires_at,
        service: value.evidence.service.clone(),
        reach: value.evidence.reach.clone(),
    })
}

pub(crate) fn digest(value: &impl Serialize) -> Result<String> {
    Ok(ramflux_protocol::encode_base64url(blake3::hash(&canonical(value)?).as_bytes()))
}

fn proof_bytes(body: &ReportingProofBody) -> Result<Vec<u8>> {
    let mut bytes = REPORT_PROOF_DOMAIN.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(canonical(body)?);
    Ok(bytes)
}

fn validate_proof(p: &ReportingProofBody) -> Result<()> {
    require(
        p.version == 1
            && p.generation > 0
            && p.generation <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
        "proof_version",
    )?;
    validate_node(&p.audience)?;
    validate_node(&p.home)?;
    for field in [&p.root, &p.body_hash, &p.evidence_hash, &p.channel_binding, &p.nonce] {
        fixed(field)?;
    }
    require(
        p.issued_at <= ramflux_protocol::MAX_SAFE_JSON_INTEGER
            && p.expires_at <= ramflux_protocol::MAX_SAFE_JSON_INTEGER
            && p.expires_at.checked_sub(p.issued_at).is_some_and(|n| n > 0 && n <= 10),
        "proof_validity",
    )?;
    require(
        p.method == "POST"
            && matches!(
                p.path.as_str(),
                "/v1/usernames/mutate"
                    | "/v1/usernames/status"
                    | "/v1/usernames/resolve"
                    | "/v1/usernames/revalidate"
            ),
        "proof_endpoint",
    )
}
