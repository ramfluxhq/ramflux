// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used)]
use super::{
    ScopedRegistrationAuth, SigningKey, VerifiedContentManifest, VerifiedScopedGrant, hex,
};
use crate::relay::native_fixture_crypto::{
    V3_AUDIENCE_NODE, v3_certificate, v3_owner_session_token, v3_resign_token, v3_sign,
    v3_signed_owner_proof, v3_signed_pop, v3_trust_snapshot,
};
use crate::{
    ObjectRelayCapability, OwnerAuthorizationProof, RelayInvocationV3, RelayTokenV3,
    RelayTrustSnapshotCache, RequesterProofOfPossession, owner_authorization_proof_binding_hash,
    owner_authorization_proof_signing_bytes, requester_pop_signing_bytes,
};
use ed25519_dalek::Signer;
use ramflux_protocol::large_attachment::{ContentManifest, QualifiedOwner, ScopedAttachmentGrant};
fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect()
}
#[cfg(test)]
pub(super) fn fixtures() -> (VerifiedContentManifest, VerifiedScopedGrant) {
    fixtures_case(0)
}
pub(super) fn fixtures_case(case: usize) -> (VerifiedContentManifest, VerifiedScopedGrant) {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let c = &j["cases"][case];
    let mc = bytes(c["content_manifest_unsigned_hex"].as_str().unwrap());
    let mut signed = u32::try_from(mc.len()).unwrap().to_be_bytes().to_vec();
    signed.extend(mc);
    signed.extend(64_u32.to_be_bytes());
    signed.extend(bytes(c["content_signature_hex"].as_str().unwrap()));
    let g = bytes(c["grant_unsigned_hex"].as_str().unwrap());
    let mut grant = b"RFC1".to_vec();
    grant.extend(u32::try_from(g.len()).unwrap().to_be_bytes());
    grant.extend(g);
    grant.extend(64_u32.to_be_bytes());
    grant.extend(bytes(c["grant_signature_hex"].as_str().unwrap()));
    (
        ContentManifest::decode_signed(&signed).unwrap(),
        ScopedAttachmentGrant::decode_signed(&grant).unwrap(),
    )
}
pub(super) fn owner_seed() -> [u8; 32] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}
pub(super) struct Auth {
    pub(super) token: RelayTokenV3,
    proof: OwnerAuthorizationProof,
    pop: RequesterProofOfPossession,
    pub(super) cache: RelayTrustSnapshotCache,
    body: String,
    audience: String,
}
impl Auth {
    pub(super) fn context(&self) -> ScopedRegistrationAuth<'_> {
        ScopedRegistrationAuth {
            invocation: RelayInvocationV3 {
                token: &self.token,
                issuer_public_key: &self.token.issuer_certificate.attestation_public_key,
                grant: None,
                owner_proof: Some(&self.proof),
                pop: &self.pop,
                expected_audience_node_id: &self.audience,
                expected_body_hash: &self.body,
                capability: self.proof.capability,
                now: self.token.issued_at,
            },
            certificate: &self.token.issuer_certificate,
            pinned_trust: &self.cache,
        }
    }
}
pub(super) fn authority_token(
    native: &VerifiedContentManifest,
    mut token: RelayTokenV3,
    now: u64,
) -> (RelayTokenV3, RelayTrustSnapshotCache) {
    let owner = &native.manifest().owner;
    let cert = v3_certificate(now, |c| {
        c.node_id.clone_from(&owner.home_node_id);
    })
    .unwrap();
    token.issuer_certificate = cert;
    token.issuer_node_id.clone_from(&owner.home_node_id);
    token.object_id = hex(&native.manifest().object_id);
    token.manifest_hash = hex(&native.manifest().hash().unwrap());
    token.owner_home_node_id.clone_from(&owner.home_node_id);
    token.owner_principal_id.clone_from(&owner.account_anchor);
    token.owner_device_epoch = owner.device_epoch;
    token.owner_signing_key_id.clone_from(&owner.device_id);
    token.owner_public_key = ramflux_protocol::encode_base64url(owner.signing_public_key);
    let mut cache = RelayTrustSnapshotCache::new();
    cache
        .update(
            v3_trust_snapshot(now, |s| {
                s.node_id.clone_from(&owner.home_node_id);
                s.roots[0].node_id.clone_from(&owner.home_node_id);
            }),
            &owner.home_node_id,
            now,
        )
        .unwrap();
    (token, cache)
}
#[cfg(test)]
pub(super) fn auth(
    native: &VerifiedContentManifest,
    grant: &VerifiedScopedGrant,
    now: u64,
) -> Auth {
    auth_for(native, now, ObjectRelayCapability::Put, hex(&grant.grant().hash().unwrap()))
}
#[cfg(test)]
pub(super) fn auth_for(
    native: &VerifiedContentManifest,
    now: u64,
    cap: ObjectRelayCapability,
    body: String,
) -> Auth {
    auth_for_device(native, now, cap, body, &native.manifest().owner, owner_seed())
}
#[cfg(test)]
pub(super) fn auth_for_device(
    native: &VerifiedContentManifest,
    now: u64,
    cap: ObjectRelayCapability,
    body: String,
    owner: &QualifiedOwner,
    seed: [u8; 32],
) -> Auth {
    auth_for_device_at(native, now, cap, body, owner, seed, V3_AUDIENCE_NODE)
}
/// Same as [`auth_for_device`] for a source authority named `audience`.
#[allow(clippy::too_many_arguments)]
pub(super) fn auth_for_device_at(
    native: &VerifiedContentManifest,
    now: u64,
    cap: ObjectRelayCapability,
    body: String,
    owner: &QualifiedOwner,
    seed: [u8; 32],
    audience: &str,
) -> Auth {
    let mut proof = v3_signed_owner_proof(now, cap).unwrap();
    proof.object_id = hex(&native.manifest().object_id);
    proof.manifest_hash = Some(hex(&native.manifest().hash().unwrap()));
    proof.owner_home_node_id.clone_from(&owner.home_node_id);
    proof.owner_principal_id.clone_from(&owner.account_anchor);
    proof.owner_device_epoch = owner.device_epoch;
    proof.owner_signing_key_id.clone_from(&owner.device_id);
    proof.owner_public_key = ramflux_protocol::encode_base64url(owner.signing_public_key);
    proof.body_hash.clone_from(&body);
    proof.owner_signature =
        v3_sign(&owner_authorization_proof_signing_bytes(&proof).unwrap(), seed);
    let binding = owner_authorization_proof_binding_hash(&proof).unwrap();
    let (token, cache) =
        authority_token(native, v3_owner_session_token(now, cap, binding).unwrap(), now);
    let mut token = token;
    token.owner_signing_key_id.clone_from(&owner.device_id);
    token.owner_device_epoch = owner.device_epoch;
    token.owner_public_key = ramflux_protocol::encode_base64url(owner.signing_public_key);
    token.requester_device_id.clone_from(&owner.device_id);
    token.requester_public_key.clone_from(&token.owner_public_key);
    token.requester_device_epoch = owner.device_epoch;
    token.requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        owner.device_id.as_bytes(),
    );
    audience.clone_into(&mut token.audience_node_id);
    v3_resign_token(&mut token).unwrap();
    let mut pop = v3_signed_pop(&token, cap, seed, now).unwrap();
    pop.body_hash.clone_from(&body);
    pop.signature = v3_sign(&requester_pop_signing_bytes(&pop).unwrap(), seed);
    Auth { token, proof, pop, cache, body, audience: audience.to_owned() }
}
pub(super) fn signed(g: &ScopedAttachmentGrant) -> VerifiedScopedGrant {
    let signature =
        SigningKey::from_bytes(&owner_seed()).sign(&g.signing_bytes().unwrap()).to_bytes();
    ScopedAttachmentGrant::decode_signed(&g.signed_bytes(&signature).unwrap()).unwrap()
}
