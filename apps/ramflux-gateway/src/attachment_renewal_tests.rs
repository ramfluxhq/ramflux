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
/// The exact refusal for a grant whose bytes were altered after signing.
const TAMPERED: &str = "grant signature";

#[test]
fn challenge_preflight_refuses_each_predicate_in_isolation_before_any_egress() -> Result {
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
    let now = grant.grant().issued_at + 1;
    let encoded = |t: &AttachmentOperation| t.canonical_bytes();
    let run = |q: &QualifiedOwner,
               config: &HomeRenewalConfig,
               cap: &[u8],
               t: &AttachmentOperation,
               now: u64| { preflight_challenge(q, config, cap, &encoded(t)?, now) };
    // Valid from the start, and at both inclusive ends of the grant window.
    run(&q, &config, &cap, &target, now)?;
    run(&q, &config, &cap, &target, grant.grant().issued_at)?;
    run(&q, &config, &cap, &target, grant.grant().expires_at - 1)?;
    let err = |name: &'static str| Err(FormatError(name));
    // Capability shape.
    let garbage = vec![1, 2, 3];
    assert_eq!(run(&q, &config, &garbage, &target, now), err("capability grant"));
    let receipt_free = grant.signed_bytes()?;
    assert_eq!(run(&q, &config, &receipt_free, &target, now), err("capability receipt"));
    let mut tampered = cap.clone();
    tampered[20] ^= 1;
    assert_eq!(run(&q, &config, &tampered, &target, now), err(TAMPERED));
    // Requester: the session identity must be the grantee.
    let mut other = q.clone();
    other.device_id.push('x');
    assert_eq!(run(&other, &config, &cap, &target, now), err("renewal requester"));
    // Target audience and generation (config side).
    let mut t = target.clone();
    t.audience.push('x');
    assert_eq!(run(&q, &config, &cap, &t, now), err("renewal audience"));
    let mut other_gen = config_with_generation(&config, 4);
    assert_eq!(run(&q, &other_gen, &cap, &target, now), err("renewal source generation"));
    other_gen = config_with_generation(&config, 3);
    run(&q, &other_gen, &cap, &target, now)?;
    // Grant binding, one operand at a time.
    for field in 0..4 {
        let mut t = target.clone();
        match field {
            0 => t.object_id[0] ^= 1,
            1 => t.manifest_hash[0] ^= 1,
            2 => t.grant_id[0] ^= 1,
            _ => t.grant_epoch += 1,
        }
        // The endpoint embeds both ids, so keep it consistent: only the binding differs.
        t.path = format!(
            "/attachments/{}/{}/segments/{}",
            hex_of(&t.object_id),
            hex_of(&t.manifest_hash),
            t.segment_index
        );
        assert_eq!(run(&q, &config, &cap, &t, now), err("renewal grant binding"), "{field}");
    }
    // Rights: an operation the grant does not allow.
    let missing = (1..=5).find(|op| grant.grant().rights & (1 << (op - 1)) == 0);
    if let Some(op) = missing {
        let mut t = target.clone();
        t.op = op;
        assert_eq!(run(&q, &config, &cap, &t, now), err("renewal rights"));
    }
    // Grant window: not yet valid, and expired (inclusive).
    assert_eq!(
        run(&q, &config, &cap, &target, grant.grant().issued_at - 1),
        err("renewal grant time")
    );
    assert_eq!(
        run(&q, &config, &cap, &target, grant.grant().expires_at),
        err("renewal grant time")
    );
    Ok(())
}
fn hex_of(raw: &[u8]) -> String {
    raw.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
        out
    })
}
fn config_with_generation(config: &HomeRenewalConfig, generation: u64) -> HomeRenewalConfig {
    HomeRenewalConfig {
        source_issuer: config.source_issuer.clone(),
        relay_audience: config.relay_audience.clone(),
        authority_generation: generation,
        home_key: config.home_key.clone(),
    }
}

fn resident_runtime(
    source: &ramflux_crypto::RootQualifiedDeviceRef,
    public: &str,
) -> GatewaySessionRuntime {
    GatewaySessionRuntime {
        session_push: None,
        ephemeral: false,
        push_limit: 256,
        source_identity: source.clone(),
        session_id: "s".into(),
        resume_token: "r".into(),
        principal_id: "resident".into(),
        device_id: "device".into(),
        target_delivery_id: source.storage_key().into(),
        branch_public_key: public.to_owned(),
        device_epoch: 1,
        supports_forward_ack: false,
        ephemeral_rate: std::sync::Arc::default(),
    }
}
#[test]
#[allow(clippy::too_many_lines)]
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
    let runtime = resident_runtime(&source, &public);
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

mod relay_clamp {
    //! The clamp is proved against the relay's own challenge row, not against the gateway's
    //! arithmetic: a W that outlives its challenge is refused with `ChallengeMismatch`.
    use super::*;
    use ramflux_node_core::attachment::{
        AttachmentReplayProof, ChallengeMint, HomeVerdict, RenewalAdmission, RenewalPolicy,
        RenewalRefusal,
        fixture::{FixtureSpec, RetirementFixture},
    };
    use ramflux_protocol::large_attachment::body_digest;

    const RELAY: &str = "https://relay.example";
    const ISSUER: &str = "https://gateway.owner.example";
    const NOW: u64 = 1_700_000_001;

    fn target_of(g: &ScopedAttachmentGrant) -> AttachmentOperation {
        let object = |raw: &[u8]| {
            raw.iter().fold(String::new(), |mut out, b| {
                use std::fmt::Write;
                let _ = write!(out, "{b:02x}");
                out
            })
        };
        AttachmentOperation {
            op: 1,
            method: "GET".into(),
            path: format!(
                "/attachments/{}/{}/segments/0",
                object(&g.object_id),
                object(&g.manifest_hash)
            ),
            audience: RELAY.into(),
            object_id: g.object_id,
            manifest_hash: g.manifest_hash,
            grant_id: g.grant_id,
            grant_epoch: g.epoch,
            authority_generation: 3,
            operation_id: [0xa1; 32],
            payload_generation: 1,
            segment_index: 0,
            offset: 0,
            length: 16,
            body_digest: body_digest(&[]),
        }
    }

    #[test]
    fn relay_refuses_a_w_that_outlives_its_challenge_and_accepts_the_clamped_one() -> Result {
        let path = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!(
                "rf-gw-clamp-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
            ));
        let spec = FixtureSpec {
            case: 1,
            source: "node-owner".into(),
            generation: 3,
            signer_seed: std::array::from_fn(|i| 0x60 + u8::try_from(i).unwrap_or(0)),
        };
        let f = RetirementFixture::new_with(&path, NOW, &spec);
        let g = f.grant.grant().clone();
        let capability = ramflux_protocol::decode_base64url(
            &f.registry.lookup(&g.grant_id)?.ok_or("row")?.capability,
        )?;
        let policy = RenewalPolicy { relay_audience: RELAY.into(), token_issuer: ISSUER.into() };
        let target = target_of(&g);
        let verdict = HomeVerdict {
            account_anchor: g.grantee.account_anchor.clone(),
            home_node: g.grantee.home_node_id.clone(),
            home_node_key: [9; 32],
            home_epoch: 1,
            home_record_hash: [3; 32],
            checked_at: NOW,
        };
        let encoded = target.canonical_bytes()?;
        let minted = f
            .registry
            .mint_renewal_challenge(
                &policy,
                &ChallengeMint {
                    capability: &capability,
                    target_operation: &encoded,
                    requester: &g.grantee,
                    home_node: &g.grantee.home_node_id,
                    peer_node: &g.grantee.home_node_id,
                    verdict: &verdict,
                },
                NOW,
            )
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(minted.expires_at, NOW + 30);
        let request = RenewalRequest::new(&target, ISSUER, [0xb2; 32])?;
        let config = HomeRenewalConfig {
            source_issuer: ISSUER.into(),
            relay_audience: RELAY.into(),
            authority_generation: 3,
            home_key: ed25519_dalek::SigningKey::from_bytes(&[0x40; 32]),
        };
        // The delayed signature: W is made 20 s after the mint, so the default +30 s would
        // outlive the challenge by 20 s.
        let at = NOW + 20;
        let sign = |challenge_expires_at: u64| -> Result<SignedHomeForward> {
            let attempt = HomeRenewalAttempt {
                request: &request,
                grant: &f.grant,
                challenge: minted.challenge,
                challenge_expires_at,
                capability: &capability,
                now: at,
            };
            Ok(attest_requester(g.grantee.clone(), &g.grantee.home_node_id, &config, &attempt)?)
        };
        let admit = |w: &SignedHomeForward, nonce: u8| {
            f.registry.admit_renewal_after_authentication(
                &RenewalAdmission {
                    grant: &f.grant,
                    challenge: minted.challenge,
                    target_hash: target.hash().unwrap_or_default(),
                    requester: &g.grantee,
                    home_node: &g.grantee.home_node_id,
                    home_epoch: 1,
                    payload_generation: 1,
                    authority_generation: 3,
                    w_issued_at: w.attestation.issued_at,
                    w_expires_at: w.attestation.expires_at,
                    verdict_checked_at: NOW,
                    proof: &AttachmentReplayProof {
                        nonce: [nonce; 32],
                        issued_at: at,
                        expires_at: at + 30,
                    },
                },
                &|| at + 5,
            )
        };
        // Without the clamp (the challenge expiry treated as unbounded) W outlives the row.
        let unclamped = sign(u64::MAX)?;
        assert_eq!(unclamped.attestation.expires_at, at + 30);
        assert_eq!(admit(&unclamped, 1).err(), Some(RenewalRefusal::ChallengeMismatch));
        // With the real challenge expiry W stops exactly there and the relay admits it.
        let clamped = sign(minted.expires_at)?;
        assert_eq!(clamped.attestation.expires_at, minted.expires_at);
        assert!(admit(&clamped, 2).is_ok());
        let _ = std::fs::remove_dir_all(&path);
        Ok(())
    }
}

mod entrypoint {
    //! `challenge_via` is the egress entrypoint: refusals must happen before the session is
    //! refreshed and before the single POST, proven with independently signed grants.
    use super::*;
    use ed25519_dalek::Signer;
    use std::cell::{Cell, RefCell};

    struct Counting {
        refreshes: Cell<usize>,
        posts: RefCell<Vec<(String, serde_json::Value)>>,
    }
    impl HomeLink for Counting {
        fn node_id(&self) -> &'static str {
            "home"
        }
        fn refresh(
            &self,
            _: &GatewaySessionRuntime,
            _: u64,
        ) -> impl std::future::Future<Output = anyhow::Result<()>> {
            self.refreshes.set(self.refreshes.get() + 1);
            std::future::ready(Ok(()))
        }
        fn post(
            &self,
            path: &str,
            body: serde_json::Value,
        ) -> impl std::future::Future<Output = anyhow::Result<Vec<u8>>> {
            self.posts.borrow_mut().push((path.into(), body));
            std::future::ready(Ok(b"reply".to_vec()))
        }
    }

    fn runtime() -> Result<GatewaySessionRuntime> {
        let root = ramflux_crypto::create_identity_root("resident", [31; 32]);
        let branch = ramflux_crypto::create_device_branch("resident", "device", 1, [32; 32]);
        let source = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(&root, &branch)?;
        Ok(GatewaySessionRuntime {
            session_push: None,
            ephemeral: false,
            push_limit: 256,
            source_identity: source.clone(),
            session_id: "s".into(),
            resume_token: "r".into(),
            principal_id: "resident".into(),
            device_id: "device".into(),
            target_delivery_id: source.storage_key().into(),
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            device_epoch: 1,
            supports_forward_ack: false,
            ephemeral_rate: std::sync::Arc::default(),
        })
    }

    /// A grant for the session's requester, signed by an owner key of our own, carrying
    /// exactly `rights`, wrapped in a source-signed registration receipt.
    fn capability_with_rights(
        base: &VerifiedScopedGrant,
        requester: &QualifiedOwner,
        rights: u32,
    ) -> Result<Vec<u8>> {
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
        let mut g = base.grant().clone();
        g.owner.signing_public_key = owner_key.verifying_key().to_bytes();
        g.grantee = requester.clone();
        g.rights = rights;
        let signature = owner_key.sign(&g.signing_bytes()?).to_bytes();
        let verified = ScopedAttachmentGrant::decode_signed(&g.signed_bytes(&signature)?)?;
        let receipt = ramflux_protocol::large_attachment::AttachmentRegistrationReceipt {
            grant_hash: g.hash()?,
            grant_epoch: g.epoch,
            source_authority: "node-owner".into(),
            authority_generation: 3,
            expires_at: g.expires_at,
        };
        let source = ed25519_dalek::SigningKey::from_bytes(&[0x60; 32]);
        let receipt_sig = source.sign(&receipt.signing_bytes()?).to_bytes();
        Ok(receipt.capability(&verified, &receipt_sig, &source.verifying_key().to_bytes())?)
    }

    #[tokio::test]
    async fn challenge_entrypoint_refuses_missing_rights_with_zero_posts() -> Result {
        let j = fixture()?;
        let r = &j["renewal"];
        let base = grant(&j)?;
        let request = RenewalRequest {
            operation: bytes(&r["renewal_operation_hex"])?,
            body: bytes(&r["renewal_body_hex"])?,
        };
        let (renew, target) = request.target()?;
        assert_eq!(target.op, 1, "the target is a GET");
        let config = HomeRenewalConfig {
            source_issuer: renew.audience.clone(),
            relay_audience: target.audience.clone(),
            authority_generation: 3,
            home_key: ed25519_dalek::SigningKey::from_bytes(&[0x40; 32]),
        };
        let runtime = runtime()?;
        let requester = session_requester(&runtime, "home")?;
        let encoded = target.canonical_bytes()?;
        let now = base.grant().issued_at + 1;
        let run = |rights: u32| {
            let link = Counting { refreshes: Cell::new(0), posts: RefCell::default() };
            let cap = capability_with_rights(&base, &requester, rights);
            let (runtime, config, encoded) = (&runtime, &config, &encoded);
            async move {
                let out = challenge_via(&link, runtime, config, &cap?, encoded, now).await;
                Ok::<_, Box<dyn std::error::Error>>((out, link))
            }
        };
        // GET + Renew: reaches the single POST on the challenge path.
        let (out, link) = run(1 | 8).await?;
        assert_eq!(out?, b"reply".to_vec());
        assert_eq!(link.refreshes.get(), 1);
        let posted: Vec<String> = link.posts.borrow().iter().map(|p| p.0.clone()).collect();
        assert_eq!(posted, vec![CHALLENGE_PATH.to_owned()]);
        // Missing the Renew right (GET only), and missing the target's own right (Renew
        // only): each exact refusal, before the refresh and with zero posts.
        for (name, rights) in [("missing Renew", 1_u32), ("missing target right", 8)] {
            let (out, link) = run(rights).await?;
            let error = out.err().ok_or(name)?;
            assert_eq!(
                error.downcast_ref::<FormatError>(),
                Some(&FormatError("renewal rights")),
                "{name}"
            );
            assert_eq!(link.refreshes.get(), 0, "{name}");
            assert!(link.posts.borrow().is_empty(), "{name}");
        }
        Ok(())
    }
}
