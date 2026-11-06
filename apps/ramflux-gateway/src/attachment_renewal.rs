// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Dormant home forwarding. No session frame or source ingress is activated here.
use crate::state::{GatewayQuicContext, GatewaySessionRuntime};
use ed25519_dalek::Signer;
use ramflux_protocol::large_attachment::{
    FormatError, ForwardAttestation, QualifiedOwner, RenewalRequest, RequesterPop,
    VerifiedScopedGrant,
};

/// Trusted source routing and home signing material. Activation must obtain these
/// from current node authority, never the request or a redirect.
pub(crate) struct HomeRenewalConfig {
    pub(crate) source_issuer: String,
    pub(crate) relay_audience: String,
    pub(crate) authority_generation: u64,
    pub(crate) source_peer: String,
    pub(crate) home_key: ed25519_dalek::SigningKey,
}
pub(crate) struct HomeRenewalAttempt<'a> {
    pub(crate) request: &'a RenewalRequest,
    pub(crate) grant: &'a VerifiedScopedGrant,
    pub(crate) challenge: [u8; 32],
    pub(crate) now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedHomeForward {
    pub(crate) attestation: ForwardAttestation,
    pub(crate) signature: [u8; 64],
}

fn session_requester(
    runtime: &GatewaySessionRuntime,
    home: &str,
) -> Result<QualifiedOwner, FormatError> {
    let key = ramflux_protocol::decode_base64url(&runtime.branch_public_key)
        .map_err(|_| FormatError("session key"))?;
    Ok(QualifiedOwner {
        account_anchor: runtime.source_identity.root_commitment().into(),
        device_id: runtime.source_identity.device_id().into(),
        device_epoch: runtime.device_epoch,
        signing_public_key: key.try_into().map_err(|_| FormatError("session key"))?,
        home_node_id: home.into(),
    })
}
fn attest(
    runtime: &GatewaySessionRuntime,
    home: &str,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
) -> Result<SignedHomeForward, FormatError> {
    attest_requester(session_requester(runtime, home)?, home, config, attempt)
}
fn attest_requester(
    requester: QualifiedOwner,
    home: &str,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
) -> Result<SignedHomeForward, FormatError> {
    attempt.request.validate(
        attempt.grant,
        &requester,
        &config.source_issuer,
        &config.relay_audience,
        attempt.now,
    )?;
    if attempt.request.target()?.0.authority_generation != config.authority_generation {
        return Err(FormatError("renewal source generation"));
    }
    let g = attempt.grant.grant();
    let w = ForwardAttestation {
        requester,
        grant_hash: g.hash()?,
        grant_id: g.grant_id,
        grant_epoch: g.epoch,
        source_issuer: config.source_issuer.clone(),
        home_issuer: home.into(),
        challenge: attempt.challenge,
        operation_hash: attempt.request.target()?.0.hash()?,
        issued_at: attempt.now,
        expires_at: attempt
            .now
            .checked_add(30)
            .ok_or(FormatError("forward time"))?
            .min(g.expires_at),
    };
    let signature = config.home_key.sign(&w.signing_bytes()?).to_bytes();
    Ok(SignedHomeForward { attestation: w, signature })
}
/// Refresh current device authority before signing; stale sessions cannot attest.
#[allow(dead_code)] // Deliberately dormant until the complete S9 endpoint is activated.
pub(crate) async fn attest_current_session(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
) -> anyhow::Result<SignedHomeForward> {
    let key: Option<ramflux_node_core::DeviceAuthKeyResponse> = crate::router_get_json_async(
        &context.router,
        &format!("/mvp1/device-auth-key/{}", runtime.source_identity.storage_key()),
    )
    .await?;
    let key = key.ok_or_else(|| anyhow::anyhow!("renewal authority unavailable"))?;
    check_current(runtime, &key, attempt.now)?;
    Ok(attest(runtime, &context.node_id, config, attempt)?)
}
fn check_current(
    runtime: &GatewaySessionRuntime,
    key: &ramflux_node_core::DeviceAuthKeyResponse,
    now: u64,
) -> Result<(), FormatError> {
    if key
        .authenticated_device_identity_for("message", now)
        .map_err(|_| FormatError("session authority"))?
        != runtime.source_identity
        || key.device_epoch != runtime.device_epoch
        || key.branch_public_key != runtime.branch_public_key
        || key.device_id != runtime.device_id
        || key.principal_id != runtime.principal_id
    {
        return Err(FormatError("session authority"));
    }
    Ok(())
}
/// JSON carries byte arrays only; signed native bytes are never reserialized.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ForwardedRenewal {
    pub(crate) operation: Vec<u8>,
    pub(crate) body: Vec<u8>,
    pub(crate) attestation: Vec<u8>,
    pub(crate) home_signature: Vec<u8>,
    pub(crate) proof: Vec<u8>,
    pub(crate) requester_signature: Vec<u8>,
    pub(crate) grant: Vec<u8>,
}
fn forward_bytes(
    requester: &QualifiedOwner,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
    w: &SignedHomeForward,
    pop: &RequesterPop,
    signature: &[u8; 64],
) -> Result<ForwardedRenewal, FormatError> {
    attempt.request.validate(
        attempt.grant,
        requester,
        &config.source_issuer,
        &config.relay_audience,
        attempt.now,
    )?;
    if attempt.request.target()?.0.authority_generation != config.authority_generation {
        return Err(FormatError("renewal source generation"));
    }
    w.attestation.validate(
        attempt.request,
        attempt.grant,
        requester,
        &attempt.challenge,
        attempt.now,
    )?;
    w.attestation.verify(&config.home_key.verifying_key().to_bytes(), &w.signature)?;
    pop.validate(&w.attestation, attempt.now)?;
    pop.verify(&requester.signing_public_key, signature)?;
    Ok(ForwardedRenewal {
        operation: attempt.request.operation.clone(),
        body: attempt.request.body.clone(),
        attestation: w.attestation.canonical_bytes()?,
        home_signature: w.signature.to_vec(),
        proof: pop.canonical_bytes()?,
        requester_signature: signature.to_vec(),
        grant: attempt.grant.signed_bytes()?,
    })
}
pub(crate) struct SignedRequesterProof<'a> {
    pub(crate) proof: &'a RequesterPop,
    pub(crate) signature: &'a [u8; 64],
}
/// Explicit source POST over authenticated mesh QUIC. Replies are opaque signed
/// token bytes; source validation/issuance is P25. No redirect or local mint fallback.
#[allow(dead_code)] // P24 prepares the complete dormant egress; P25 owns ingress.
pub(crate) async fn forward_current_session(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
    w: &SignedHomeForward,
    proof: SignedRequesterProof<'_>,
) -> anyhow::Result<Vec<u8>> {
    let key: Option<ramflux_node_core::DeviceAuthKeyResponse> = crate::router_get_json_async(
        &context.router,
        &format!("/mvp1/device-auth-key/{}", runtime.source_identity.storage_key()),
    )
    .await?;
    check_current(
        runtime,
        &key.ok_or_else(|| anyhow::anyhow!("renewal authority unavailable"))?,
        attempt.now,
    )?;
    let requester = session_requester(runtime, &context.node_id)?;
    let bytes = forward_bytes(&requester, config, attempt, w, proof.proof, proof.signature)?;
    let peer = context
        .peers
        .peer(&config.source_peer)
        .ok_or_else(|| anyhow::anyhow!("renewal source peer unavailable"))?;
    post_forwarded(
        &peer.endpoint,
        context.peers.tls(),
        &peer.server_name,
        context.peers.peer_ca_pems(),
        &bytes,
    )
    .await
}
async fn post_forwarded(
    endpoint: &str,
    tls: &ramflux_transport::MeshTlsConfig,
    server_name: &str,
    roots: &[String],
    bytes: &ForwardedRenewal,
) -> anyhow::Result<Vec<u8>> {
    Ok(ramflux_transport::mesh_quic_post_json_with_peer_ca_pems_async(
        endpoint,
        "/s9/attachments/renew",
        tls,
        server_name,
        roots,
        bytes,
    )
    .await?)
}

#[cfg(test)]
#[path = "attachment_renewal_tests.rs"]
mod tests;
