// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use ramflux_protocol::large_attachment::{
    AttachmentOperation, ScopedAttachmentGrant, requester_digest,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or("hex string")?;
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| Ok(u8::from_str_radix(std::str::from_utf8(p)?, 16)?))
        .collect()
}
fn fixture() -> Result<serde_json::Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../crates/ramflux-protocol/tests/fixtures/large_attachment_renewal_v1.json"
    ))?)
}
fn grant(j: &serde_json::Value) -> Result<VerifiedScopedGrant> {
    let c = &j["case"];
    let g = bytes(&c["grant_unsigned_hex"])?;
    let mut b = b"RFC1".to_vec();
    b.extend(u32::try_from(g.len())?.to_be_bytes());
    b.extend(g);
    b.extend(64_u32.to_be_bytes());
    b.extend(bytes(&c["grant_signature_hex"])?);
    Ok(ScopedAttachmentGrant::decode_signed(&b)?)
}
#[tokio::test]
async fn large_home_forwarding_preserves_authenticated_foreign_requester() -> Result {
    let j = fixture()?;
    let r = &j["renewal"];
    let grant = grant(&j)?;
    let request = RenewalRequest {
        operation: bytes(&r["renewal_operation_hex"])?,
        body: bytes(&r["renewal_body_hex"])?,
    };
    let (renew, target) = request.target()?;
    assert_eq!(renew.hash()?.as_slice(), bytes(&r["renewal_ohash_hex"])?);
    assert_eq!(target.hash()?.as_slice(), bytes(&r["target_ohash_hex"])?);
    assert_ne!(target.hash()?, renew.hash()?);
    assert_eq!(request, RenewalRequest::new(&target, &renew.audience, renew.operation_id)?);
    let q = grant.grant().grantee.clone();
    let config = HomeRenewalConfig {
        source_issuer: renew.audience.clone(),
        relay_audience: target.audience.clone(),
        authority_generation: 3,
        home_key: ed25519_dalek::SigningKey::from_bytes(
            &bytes(&r["source_home_seed_hex"])?.try_into().map_err(|_| "seed")?,
        ),
    };
    let cap = capability(&grant);
    let attempt = HomeRenewalAttempt {
        request: &request,
        grant: &grant,
        challenge: [0xc1; 32],
        challenge_expires_at: 1_700_000_031,
        capability: &cap,
        now: 1_700_000_001,
    };
    let w = attest_requester(q.clone(), &q.home_node_id, &config, &attempt)?;
    assert_eq!(w.attestation.canonical_bytes()?, bytes(&r["home"]["bytes_hex"])?);
    assert_eq!(w.attestation.signing_bytes()?, bytes(&r["home"]["signing_bytes_hex"])?);
    assert_eq!(w.signature.as_slice(), bytes(&r["home"]["signature_hex"])?);
    assert_eq!(w.attestation.hash()?.as_slice(), bytes(&r["attestation_digest_hex"])?);
    let pop = RequesterPop {
        operation_hash: renew.hash()?,
        requester_digest: requester_digest(&q)?,
        nonce: [0xb1; 32],
        issued_at: attempt.now,
        expires_at: attempt.now + 30,
        forward_digest: w.attestation.hash()?,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(
        &bytes(&j["grantee_seed_hex"])?.try_into().map_err(|_| "seed")?,
    );
    let signature = key.sign(&pop.signing_bytes()?).to_bytes();
    assert_eq!(pop.canonical_bytes()?, bytes(&r["renewal_pop"]["bytes_hex"])?);
    assert_eq!(pop.signing_bytes()?, bytes(&r["renewal_pop"]["signing_bytes_hex"])?);
    assert_eq!(signature.as_slice(), bytes(&r["renewal_pop"]["signature_hex"])?);
    let forwarded = forward_bytes(&q, &config, &attempt, &w, &pop, &signature)?;
    assert_eq!(forwarded.operation, request.operation);
    assert_eq!(forwarded.body, request.body);
    assert_eq!(forwarded.attestation, w.attestation.canonical_bytes()?);
    assert_eq!(forwarded.proof, pop.canonical_bytes()?);
    assert_eq!(forward_bytes(&q, &config, &attempt, &w, &pop, &signature)?, forwarded);
    assert_forwarding_refusals(&q, &config, &attempt, &w, (&pop, &signature), r)?;
    assert_eq!(forwarded.grant, cap, "the full registered capability rides in the envelope");
    assert_eq!(
        serde_json::from_value::<ForwardedRenewal>(serde_json::to_value(&forwarded)?)?,
        forwarded
    );
    Ok(())
}
#[test]
fn large_home_egress_clamps_w_and_never_falls_back() -> Result {
    let j = fixture()?;
    let r = &j["renewal"];
    let grant = grant(&j)?;
    let request = RenewalRequest {
        operation: bytes(&r["renewal_operation_hex"])?,
        body: bytes(&r["renewal_body_hex"])?,
    };
    let (renew, target) = request.target()?;
    let q = grant.grant().grantee.clone();
    let config = HomeRenewalConfig {
        source_issuer: renew.audience.clone(),
        relay_audience: target.audience.clone(),
        authority_generation: 3,
        home_key: ed25519_dalek::SigningKey::from_bytes(
            &bytes(&r["source_home_seed_hex"])?.try_into().map_err(|_| "seed")?,
        ),
    };
    let cap = capability(&grant);
    let attempt = HomeRenewalAttempt {
        request: &request,
        grant: &grant,
        challenge: [0xc1; 32],
        challenge_expires_at: 1_700_000_031,
        capability: &cap,
        now: 1_700_000_001,
    };
    assert_home_egress_rules(&q, &config, &attempt, &request, r)?;
    // The only egress is the home router; there is no source-peer path to fall back to.
    assert_eq!(CHALLENGE_PATH, "/s9/attachments/renew/challenge");
    assert_eq!(FORWARD_PATH, "/s9/attachments/renew/forward");
    Ok(())
}
#[test]
fn renewal_session_binding_refreshes_current_authority_and_never_rewrites_requester() -> Result {
    let root = ramflux_crypto::create_identity_root("resident", [31; 32]);
    let branch = ramflux_crypto::create_device_branch("resident", "device", 1, [32; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([33; 32]);
    let public = ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let (signing_key_commitment, agreement_key_commitment) =
        ramflux_crypto::device_key_commitments(
            &public,
            &ramflux_protocol::encode_base64url(agreement.public),
        )?;
    let set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: "device".into(),
                device_epoch: 1,
                signing_key_commitment,
                agreement_key_commitment,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
    let runtime = GatewaySessionRuntime {
        session_push: None,
        push_limit: 256,
        source_identity: source.clone(),
        session_id: "s".into(),
        resume_token: "r".into(),
        principal_id: "resident".into(),
        device_id: "device".into(),
        target_delivery_id: source.storage_key().into(),
        branch_public_key: public.clone(),
        device_epoch: 1,
        supports_forward_ack: false,
    };
    let key = ramflux_node_core::DeviceAuthKeyResponse {
        custody_authority: None,
        root_public_key: Some(ramflux_protocol::encode_base64url(
            root.signing_key.verifying_key().to_bytes(),
        )),
        signed_device_set: Some(set),
        principal_id: "resident".into(),
        device_id: "device".into(),
        device_epoch: 1,
        branch_public_key: public,
        target_delivery_id: source.storage_key().into(),
        revoked: false,
    };
    check_current(&runtime, &key, 100)?;
    let requester = session_requester(&runtime, "home")?;
    assert_eq!(requester.account_anchor, source.root_commitment());
    assert_eq!(requester.device_id, "device");
    assert_eq!(requester.signing_public_key, branch.signing_key.verifying_key().to_bytes());
    for field in 0..5 {
        let mut stale = runtime.clone();
        match field {
            0 => stale.principal_id.push('x'),
            1 => stale.device_id.push('x'),
            2 => stale.device_epoch += 1,
            3 => stale.branch_public_key.push('x'),
            _ => {
                stale.source_identity =
                    ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
                        &root, "other",
                    )?;
            }
        }
        assert_eq!(check_current(&stale, &key, 100), Err(FormatError("session authority")));
    }
    let mut revoked = key.clone();
    revoked.revoked = true;
    assert_eq!(check_current(&runtime, &revoked, 100), Err(FormatError("session authority")));
    let j = fixture()?;
    let g = grant(&j)?;
    let r = &j["renewal"];
    let request = RenewalRequest {
        operation: bytes(&r["renewal_operation_hex"])?,
        body: bytes(&r["renewal_body_hex"])?,
    };
    assert_eq!(
        request.validate(
            &g,
            &requester,
            "https://gateway.owner.example",
            "https://relay.example",
            1_700_000_001
        ),
        Err(FormatError("renewal requester"))
    );
    // The challenge envelope's requester and home come from the session, not from input.
    let envelope = challenge_envelope(&runtime, "home", &capability(&g), &[7])?;
    assert_eq!(envelope.requester.account_anchor, source.root_commitment());
    assert_eq!(envelope.requester.device_id, "device");
    assert_eq!(envelope.requester.home_node_id, "home");
    assert_eq!(envelope.home_node, "home");
    assert_eq!(envelope.requester.signing_public_key, requester.signing_public_key);
    assert_eq!(envelope.capability, capability(&g));
    Ok(())
}

fn capability(grant: &VerifiedScopedGrant) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let receipt = ramflux_protocol::large_attachment::AttachmentRegistrationReceipt {
        grant_hash: grant.grant().hash().unwrap_or_default(),
        grant_epoch: grant.grant().epoch,
        source_authority: "node-owner".into(),
        authority_generation: 3,
        expires_at: grant.grant().expires_at,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x60; 32]);
    let signature = key.sign(&receipt.signing_bytes().unwrap_or_default()).to_bytes();
    receipt.capability(grant, &signature, &key.verifying_key().to_bytes()).unwrap_or_default()
}

fn assert_home_egress_rules(
    q: &QualifiedOwner,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
    request: &RenewalRequest,
    vectors: &serde_json::Value,
) -> Result {
    let expires = |at: HomeRenewalAttempt<'_>| -> std::result::Result<u64, FormatError> {
        Ok(attest_requester(q.clone(), &q.home_node_id, config, &at)?.attestation.expires_at)
    };
    let now = attempt.now;
    let grant_expiry = attempt.grant.grant().expires_at;
    assert!(grant_expiry > now + 30, "{vectors}");
    // Delayed positive: the challenge outlives the clamp by 20 s, so W stops there.
    let at = |challenge_expires_at: u64, now: u64| HomeRenewalAttempt {
        request,
        grant: attempt.grant,
        challenge: attempt.challenge,
        challenge_expires_at,
        capability: attempt.capability,
        now,
    };
    assert_eq!(expires(at(now + 20, now))?, now + 20);
    // A challenge that lasts longer than the default 30 s does not extend W.
    assert_eq!(expires(at(now + 31, now))?, now + 30);
    assert_eq!(expires(at(now + 30, now))?, now + 30);
    // Inclusive boundary: at the challenge expiry nothing is signed; one second before it, W
    // lasts exactly one second.
    assert_eq!(expires(at(now + 1, now))?, now + 1);
    assert_eq!(expires(at(now, now)), Err(FormatError("challenge expired")));
    assert_eq!(expires(at(now - 1, now)), Err(FormatError("challenge expired")));
    // Capability: receipt-free grant bytes and a capability for another grant are refused
    // before anything is signed into an envelope.
    let signed = attempt.grant.signed_bytes()?;
    assert_eq!(
        checked_capability(&HomeRenewalAttempt { capability: &signed, ..*attempt }),
        Err(FormatError("capability receipt"))
    );
    let mut other = attempt.capability.to_vec();
    other[10] ^= 1;
    assert_eq!(
        checked_capability(&HomeRenewalAttempt { capability: &other, ..*attempt }),
        Err(FormatError("capability grant"))
    );
    assert_eq!(checked_capability(attempt)?, attempt.capability);
    Ok(())
}

fn assert_forwarding_refusals(
    requester: &QualifiedOwner,
    config: &HomeRenewalConfig,
    attempt: &HomeRenewalAttempt<'_>,
    forward: &SignedHomeForward,
    signed_proof: (&RequesterPop, &[u8; 64]),
    vectors: &serde_json::Value,
) -> Result {
    let (pop, signature) = signed_proof;
    let (renew, target) = attempt.request.target()?;
    let forwarded = forward_bytes(requester, config, attempt, forward, pop, signature)?;
    for rejected in vectors["rejected_target_operations_hex"].as_array().ok_or("targets")? {
        let target_operation = AttachmentOperation::decode(&bytes(rejected)?)?;
        let changed = RenewalRequest::new(&target_operation, &renew.audience, renew.operation_id)?;
        let changed_attempt = HomeRenewalAttempt { request: &changed, ..*attempt };
        let expected = if target_operation.audience == target.audience {
            "forward request binding"
        } else {
            "renewal audience"
        };
        assert_eq!(
            forward_bytes(requester, config, &changed_attempt, forward, pop, signature),
            Err(FormatError(expected))
        );
    }
    for field in 0..5 {
        let mut other = (*requester).clone();
        match field {
            0 => other.account_anchor.push('x'),
            1 => other.device_id.push('x'),
            2 => other.device_epoch += 1,
            3 => other.signing_public_key[0] ^= 1,
            _ => other.home_node_id.push('x'),
        }
        assert_eq!(
            forward_bytes(&other, config, attempt, forward, pop, signature),
            Err(FormatError("renewal requester"))
        );
    }
    let mut bad = (*forward).clone();
    bad.attestation.home_issuer.push('x');
    assert_eq!(
        forward_bytes(requester, config, attempt, &bad, pop, signature),
        Err(FormatError("forward home binding"))
    );
    let mut bad_pop = (*pop).clone();
    bad_pop.operation_hash = target.hash()?;
    assert_eq!(
        forward_bytes(requester, config, attempt, forward, &bad_pop, signature),
        Err(FormatError("pop binding"))
    );
    let mut bad_signature = *signature;
    bad_signature[0] ^= 1;
    assert_eq!(
        forward_bytes(requester, config, attempt, forward, pop, &bad_signature),
        Err(FormatError("grant signature"))
    );
    // Real unrelated signed grants cannot replace the exact request-bound grant.
    let owner = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    for i in 0..256_u16 {
        let mut unrelated = attempt.grant.grant().clone();
        unrelated.grant_id[..2].copy_from_slice(&i.to_be_bytes());
        unrelated.owner.signing_public_key = owner.verifying_key().to_bytes();
        let encoded =
            unrelated.signed_bytes(&owner.sign(&unrelated.signing_bytes()?).to_bytes())?;
        let unrelated = ScopedAttachmentGrant::decode_signed(&encoded)?;
        let changed_attempt = HomeRenewalAttempt { grant: &unrelated, ..*attempt };
        assert_eq!(
            forward_bytes(requester, config, &changed_attempt, forward, pop, signature),
            Err(FormatError("renewal grant binding"))
        );
    }
    assert_eq!(forward_bytes(requester, config, attempt, forward, pop, signature)?, forwarded);
    Ok(())
}
