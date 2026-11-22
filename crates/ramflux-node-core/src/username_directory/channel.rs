// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Channel identity proves node-key possession on this TLS session; it is not a serving permit.
use super::{CheckpointError, Result, canonical, config::validate_node, fixed, require};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "ramflux.identity.username_transport.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryChannelIdentity {
    pub node: String,
    pub public_key: String,
    pub exporter: String,
    pub challenge: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl DirectoryChannelIdentity {
    /// # Errors
    /// Refuses wrong peers, substituted TLS sessions/challenges and expired signatures.
    pub fn verify(
        &self,
        node: &str,
        key: &str,
        exporter: &[u8; 32],
        challenge: &str,
        now: u64,
    ) -> Result<()> {
        self.validate()?;
        require(
            self.node == node
                && self.public_key == key
                && self.exporter == ramflux_protocol::encode_base64url(exporter)
                && self.challenge == challenge,
            "channel_identity",
        )?;
        require(self.issued_at <= now && now < self.expires_at, "channel_expired")?;
        ramflux_crypto::verify_canonical_signature(&self.bytes()?, &self.signature, key)
            .map_err(|_| CheckpointError::Refused("channel_signature"))
    }

    fn validate(&self) -> Result<()> {
        validate_node(&self.node)?;
        for value in [&self.public_key, &self.exporter, &self.challenge] {
            fixed(value)?;
        }
        require(
            self.expires_at <= ramflux_protocol::MAX_SAFE_JSON_INTEGER
                && self.expires_at.checked_sub(self.issued_at).is_some_and(|v| v > 0 && v <= 10),
            "channel_time",
        )
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        let mut body = self.clone();
        body.signature.clear();
        let mut bytes = DOMAIN.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(canonical(&body)?);
        Ok(bytes)
    }
}

/// Closed node-signing adapter; account documents still require their master signatures.
pub struct DirectorySigner(SigningKey);

pub struct ReportingRequestInput<'a> {
    pub root: &'a str,
    pub request: super::DirectoryRequest,
    pub exporter: &'a [u8; 32],
    pub now: u64,
}

impl DirectorySigner {
    /// Build the exact canonical reporting request after authenticating the provisioned centre.
    /// # Errors
    /// Refuses malformed requests, oversized evidence, unsafe time or unavailable randomness.
    pub fn reporting_request(
        &self,
        pin: &super::CenterPin,
        evidence: super::ReportingEvidence,
        input: ReportingRequestInput<'_>,
    ) -> Result<Vec<u8>> {
        let ReportingRequestInput { root, request, exporter, now } = input;
        request.validate()?;
        let proof = self.reporting_proof(super::ReportingProofBody {
            version: 1,
            audience: pin.id.clone(),
            generation: pin.generation,
            home: evidence.discovery.node_id.clone(),
            root: root.into(),
            method: "POST".into(),
            path: request.path().into(),
            body_hash: super::transport::digest(&request)?,
            evidence_hash: super::transport::digest(&evidence)?,
            channel_binding: ramflux_protocol::encode_base64url(exporter),
            nonce: super::fence::random_id()?,
            issued_at: now,
            expires_at: now.checked_add(10).ok_or(CheckpointError::Refused("clock"))?,
        })?;
        let bytes = canonical(&super::ReportingRequest { proof, evidence, request })?;
        super::decode_reporting_request(&bytes)?;
        Ok(bytes)
    }
    /// # Errors
    /// Refuses stale/missing contexts or an oversized framed candidate.
    pub fn prepare_http_response(
        &self,
        authority: &mut super::DirectoryAuthority,
        writer: &super::WriterIdentity,
        call: &str,
        channel: &str,
    ) -> Result<()> {
        authority.prepare_http_response(writer, call, channel, &self.0)
    }
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    #[must_use]
    pub fn public_key(&self) -> String {
        ramflux_protocol::encode_base64url(self.0.verifying_key().to_bytes())
    }

    /// # Errors
    /// Refuses malformed channel facts or unsafe time arithmetic.
    pub fn channel_identity(
        &self,
        node: &str,
        exporter: &[u8; 32],
        challenge: &str,
        now: u64,
    ) -> Result<DirectoryChannelIdentity> {
        use ed25519_dalek::Signer;
        let mut body = DirectoryChannelIdentity {
            node: node.into(),
            public_key: self.public_key(),
            exporter: ramflux_protocol::encode_base64url(exporter),
            challenge: challenge.into(),
            issued_at: now,
            expires_at: now.checked_add(10).ok_or(CheckpointError::Refused("clock"))?,
            signature: String::new(),
        };
        body.validate()?;
        body.signature = ramflux_protocol::encode_base64url(self.0.sign(&body.bytes()?).to_bytes());
        Ok(body)
    }

    /// # Errors
    /// Refuses malformed reporting proof fields.
    pub fn reporting_proof(
        &self,
        body: super::ReportingProofBody,
    ) -> Result<ramflux_protocol::username_directory::Signed<super::ReportingProofBody>> {
        super::sign_reporting_proof(&self.0, body)
    }

    /// # Errors
    /// Refuses malformed home transport advertisements.
    pub fn home_service(
        &self,
        body: super::HomeServiceAddress,
    ) -> Result<super::SignedHomeServiceAddress> {
        super::sign_home_service(&self.0, body)
    }

    /// The actor must verify this signer's identity against its independent centre pin first.
    /// # Errors
    /// Refuses stale, missing or mismatched live serving contexts.
    pub fn prepare_response(
        &self,
        authority: &mut super::DirectoryAuthority,
        writer: &super::WriterIdentity,
        call: &str,
        channel: &str,
    ) -> Result<()> {
        authority.prepare_response(writer, call, channel, &self.0)
    }
}
