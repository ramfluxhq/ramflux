// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial branch binding and independently pinned node authority vectors.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use ramflux_protocol::{custody::*, domain, encode_base64url};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn node_body() -> NodeIdentityRecord {
    NodeIdentityRecord {
        schema: domain::CUSTODY_NODE_RECORD.into(),
        version: 1,
        node_id: "node".into(),
        node_signing_public_key: encode_base64url(key(8).verifying_key().to_bytes()),
        client_tls_certificate_sha256: Some(encode_base64url([29; 32])),
        epoch: 1,
        previous_record_hash: None,
        issued_at: NOW,
        receipt_keys: vec![ReceiptKey {
            key_id: encode_base64url([12; 32]),
            public_key: encode_base64url(key(6).verifying_key().to_bytes()),
            not_before: NOW - 100,
            sign_until: NOW + 2_591_900,
            overlap_until: NOW + 2_591_900 + 605_400,
            status: ReceiptKeyStatus::Active,
        }],
        revoked_receipt_key_ids: vec![],
        proxy_keys: vec![ProxyKey {
            key_id: encode_base64url([11; 32]),
            public_key: encode_base64url(key(7).verifying_key().to_bytes()),
            not_before: NOW - 100,
            sign_until: NOW + 2_591_900,
            overlap_until: NOW + 2_591_900 + 605_400,
            status: ReceiptKeyStatus::Active,
            proxy_id: "gateway".into(),
            audiences: vec!["node".into()],
        }],
        revoked_proxy_key_ids: vec![],
        channel_binding_modes: vec![BindingMode::DirectExporter, BindingMode::HomeRelayReceipt],
        web_listeners: Vec::new(),
    }
}
fn node(body: NodeIdentityRecord) -> TestResult<VerifiedNodeRecord> {
    let envelope = sign_node_identity_record(&key(8), body)?;
    Ok(verify_node_identity_record(
        &envelope,
        "node",
        &encode_base64url(key(8).verifying_key().to_bytes()),
        NOW,
    )?)
}
fn authority() -> TestResult<VerifiedRecord> {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/custody_v3.json"))?;
    let record: Envelope<DeviceSet> = serde_json::from_value(vector["record"].clone())?;
    Ok(verify_record(&record, NOW, None, None)?)
}
fn challenge(mode: BindingMode) -> BranchChallenge {
    BranchChallenge {
        challenge_nonce: encode_base64url([9; 32]),
        action_hash: encode_base64url([8; 32]),
        audience: "node".into(),
        binding_mode: mode,
        issued_at: NOW,
        expires_at: NOW + 300,
    }
}
fn proof(mode: BindingMode) -> TestResult<Envelope<BranchProofV3>> {
    let authority = authority()?;
    let body = &authority.envelope().body;
    let branch = ramflux_protocol::custody::object_hash(
        body.devices[0].branch_certificate.as_ref().ok_or("branch")?,
    )?;
    Ok(sign_branch_proof_v3(
        &crate::create_device_branch("vector.example", "primary", 1, [3; 32]),
        BranchProofV3 {
            schema: domain::BRANCH_PROOF_V3.into(),
            version: 3,
            device_ref: DeviceRef {
                account_anchor: body.account_anchor.clone(),
                device_id: "primary".into(),
                device_epoch: 1,
            },
            certificate_hash: branch,
            record_hash: object_hash(authority.envelope())?,
            proof_id: encode_base64url([10; 32]),
            challenge_nonce: encode_base64url([9; 32]),
            action_hash: encode_base64url([8; 32]),
            audience: "node".into(),
            binding_mode: mode,
            transport_binding: branch_exporter_hash(&[20; 32]),
            issued_at: NOW,
            expires_at: NOW + 300,
        },
    )?)
}
fn check_proxy(
    proof: &Envelope<BranchProofV3>,
    receipt: &Envelope<RelayAcceptance>,
    old: &VerifiedNodeRecord,
    current: &VerifiedNodeRecord,
) -> TestResult {
    Ok(verify_branch_proof_v3(
        &authority()?,
        proof,
        &challenge(BindingMode::HomeRelayReceipt),
        "register",
        ProofChannel::HomeRelayReceipt { receipt, historical_node: old, current_node: current },
        NOW,
    )?)
}
fn resign_receipt(receipt: &mut Envelope<RelayAcceptance>, seed: u8) -> TestResult {
    receipt.signature = encode_base64url(
        key(seed).sign(&signing_bytes(domain::CUSTODY_RELAY_ACCEPTANCE, &receipt.body)?).to_bytes(),
    );
    Ok(())
}
#[test]
fn direct_proof_requires_the_same_live_tls_exporter_challenge_audience_and_domain() -> TestResult {
    let node = node(node_body())?;
    let authority = authority()?;
    let proof = proof(BindingMode::DirectExporter)?;
    let binding = branch_exporter_hash(&[20; 32]);
    verify_branch_proof_v3(
        &authority,
        &proof,
        &challenge(BindingMode::DirectExporter),
        "register",
        ProofChannel::DirectExporter { observed_hash: &binding, receiving_node: &node },
        NOW,
    )?;
    let wrong_binding = branch_exporter_hash(&[21; 32]);
    assert!(
        verify_branch_proof_v3(
            &authority,
            &proof,
            &challenge(BindingMode::DirectExporter),
            "register",
            ProofChannel::DirectExporter { observed_hash: &wrong_binding, receiving_node: &node },
            NOW
        )
        .is_err()
    );
    for field in ["audience", "nonce", "action", "mode", "domain"] {
        let mut altered = proof.clone();
        match field {
            "audience" => altered.body.audience = "other-service".into(),
            "nonce" => altered.body.challenge_nonce = encode_base64url([22; 32]),
            "action" => altered.body.action_hash = encode_base64url([23; 32]),
            "mode" => altered.body.binding_mode = BindingMode::NoChannelBinding,
            _ => {}
        }
        let domain = if field == "domain" {
            domain::CUSTODY_BRANCH_CERTIFICATE
        } else {
            domain::BRANCH_PROOF_V3
        };
        altered.signature =
            encode_base64url(key(3).sign(&signing_bytes(domain, &altered.body)?).to_bytes());
        assert!(
            verify_branch_proof_v3(
                &authority,
                &altered,
                &challenge(BindingMode::DirectExporter),
                "register",
                ProofChannel::DirectExporter { observed_hash: &binding, receiving_node: &node },
                NOW
            )
            .is_err(),
            "{field}"
        );
    }
    Ok(())
}
#[test]
fn proxy_receipt_requires_independent_observation_exact_proof_and_correct_signer_role() -> TestResult
{
    let node = node(node_body())?;
    let proof = proof(BindingMode::HomeRelayReceipt)?;
    let binding = branch_exporter_hash(&[20; 32]);
    assert!(
        sign_proxy_acceptance(
            &key(7),
            &node,
            &proof,
            &branch_exporter_hash(&[21; 32]),
            encode_base64url([23; 32]),
            NOW
        )
        .is_err()
    );
    let receipt =
        sign_proxy_acceptance(&key(7), &node, &proof, &binding, encode_base64url([23; 32]), NOW)?;
    check_proxy(&proof, &receipt, &node, &node)?;
    for field in ["hash", "source", "audience", "observation", "role", "relay_key"] {
        let mut altered = receipt.clone();
        match field {
            "hash" => altered.body.message_hash = encode_base64url([24; 32]),
            "source" => {
                altered.body.source_device_ref.as_mut().ok_or("source")?.device_id = "other".into();
            }
            "audience" => altered.body.audience = "other-service".into(),
            "observation" => {
                altered.body.client_exporter_hash = Some(branch_exporter_hash(&[21; 32]));
            }
            "role" => altered.body.issuer_kind = AcceptanceIssuer::HomeRelay,
            _ => altered.body.relay_key_id = encode_base64url([12; 32]),
        }
        resign_receipt(&mut altered, if field == "relay_key" { 6 } else { 7 })?;
        assert!(check_proxy(&proof, &altered, &node, &node).is_err(), "{field}");
    }
    assert!(
        sign_proxy_acceptance(&key(6), &node, &proof, &binding, encode_base64url([23; 32]), NOW)
            .is_err()
    );
    Ok(())
}
#[test]
fn current_proxy_revocation_dominates_valid_historical_receipts() -> TestResult {
    let old = node(node_body())?;
    let proof = proof(BindingMode::HomeRelayReceipt)?;
    let receipt = sign_proxy_acceptance(
        &key(7),
        &old,
        &proof,
        &proof.body.transport_binding,
        encode_base64url([23; 32]),
        NOW,
    )?;
    let mut next = node_body();
    next.epoch = 2;
    next.previous_record_hash = Some(old.hash().into());
    next.revoked_proxy_key_ids.push(encode_base64url([11; 32]));
    let current = node(next)?;
    assert!(check_proxy(&proof, &receipt, &old, &current).is_err());
    Ok(())
}
#[test]
fn node_discovery_requires_an_independent_pin_and_monotonic_head() -> TestResult {
    let first = node(node_body())?;
    assert!(
        verify_node_identity_record(
            first.envelope(),
            "node",
            &encode_base64url(key(30).verifying_key().to_bytes()),
            NOW
        )
        .is_err()
    );
    let mut second_body = node_body();
    second_body.epoch = 2;
    second_body.previous_record_hash = Some(first.hash().into());
    second_body.issued_at += 1;
    let second = node(second_body)?;
    first.verify_successor(&second, |_| None, |_| None)?;
    assert!(second.verify_successor(&first, |_| None, |_| None).is_err());
    let mut conflict = second.envelope().body.clone();
    conflict.channel_binding_modes.push(BindingMode::NoChannelBinding);
    assert!(second.verify_successor(&node(conflict)?, |_| None, |_| None).is_err());
    Ok(())
}
#[test]
fn no_channel_binding_requires_signed_advertisement_and_explicit_operator_policy() -> TestResult {
    let proof = proof(BindingMode::NoChannelBinding)?;
    let authority = authority()?;
    let default = node(node_body())?;
    assert!(
        verify_branch_proof_v3(
            &authority,
            &proof,
            &challenge(BindingMode::NoChannelBinding),
            "register",
            ProofChannel::NoChannelBinding { operator_opt_in: true, receiving_node: &default },
            NOW
        )
        .is_err()
    );
    let mut opted_body = node_body();
    opted_body.channel_binding_modes.push(BindingMode::NoChannelBinding);
    let opted = node(opted_body)?;
    assert!(
        verify_branch_proof_v3(
            &authority,
            &proof,
            &challenge(BindingMode::NoChannelBinding),
            "register",
            ProofChannel::NoChannelBinding { operator_opt_in: false, receiving_node: &opted },
            NOW
        )
        .is_err()
    );
    verify_branch_proof_v3(
        &authority,
        &proof,
        &challenge(BindingMode::NoChannelBinding),
        "register",
        ProofChannel::NoChannelBinding { operator_opt_in: true, receiving_node: &opted },
        NOW,
    )?;
    Ok(())
}

#[test]
fn node_rotation_keeps_old_receipt_valid_but_cannot_rebind_its_key_identity() -> TestResult {
    let old = node(node_body())?;
    let proof = proof(BindingMode::HomeRelayReceipt)?;
    let receipt = sign_proxy_acceptance(
        &key(7),
        &old,
        &proof,
        &proof.body.transport_binding,
        encode_base64url([23; 32]),
        NOW,
    )?;
    let mut next = node_body();
    next.epoch = 2;
    next.previous_record_hash = Some(old.hash().into());
    next.proxy_keys[0].status = ReceiptKeyStatus::Retiring;
    let mut replacement = next.proxy_keys[0].clone();
    replacement.key_id = encode_base64url([18; 32]);
    replacement.public_key = encode_base64url(key(17).verifying_key().to_bytes());
    replacement.not_before = NOW;
    replacement.sign_until = NOW + 2_592_000;
    replacement.overlap_until = replacement.sign_until + 605_400;
    replacement.status = ReceiptKeyStatus::Active;
    next.proxy_keys.push(replacement);
    let current = node(next.clone())?;
    let old_id = old.envelope().body.proxy_keys[0].key_id.clone();
    let old_public = old.envelope().body.proxy_keys[0].public_key.clone();
    let binding = old.key_bindings().find(|(id, _)| *id == old_id).ok_or("key binding")?.1;
    old.verify_successor(
        &current,
        |id| (id == old_id).then(|| binding.clone()),
        |public| (public == old_public).then(|| old_id.clone()),
    )?;
    check_proxy(&proof, &receipt, &old, &current)?;
    next.proxy_keys[0].public_key = encode_base64url(key(19).verifying_key().to_bytes());
    assert!(
        old.verify_successor(&node(next)?, |id| (id == old_id).then(|| binding.clone()), |_| None)
            .is_err()
    );
    Ok(())
}

#[test]
fn proof_decoder_rejects_unknown_fields_null_binding_and_noncanonical_binary() -> TestResult {
    let proof = proof(BindingMode::DirectExporter)?;
    let value = serde_json::to_value(&proof)?;
    for field in ["unknown", "null", "binary", "version"] {
        let mut altered = value.clone();
        match field {
            "unknown" => {
                altered["body"]["extra"] = serde_json::json!(true);
            }
            "null" => {
                altered["body"]["transport_binding"] = serde_json::Value::Null;
            }
            "binary" => {
                altered["body"]["transport_binding"] =
                    serde_json::json!(format!("{}=", proof.body.transport_binding));
            }
            _ => {
                altered["body"]["version"] = serde_json::json!(2);
            }
        }
        let parsed = ramflux_protocol::custody::decode::<Envelope<BranchProofV3>>(
            &serde_json::to_vec(&altered)?,
            8192,
        );
        if let Ok(parsed) = parsed {
            let node = node(node_body())?;
            assert!(
                verify_branch_proof_v3(
                    &authority()?,
                    &parsed,
                    &challenge(BindingMode::DirectExporter),
                    "register",
                    ProofChannel::DirectExporter {
                        observed_hash: &proof.body.transport_binding,
                        receiving_node: &node
                    },
                    NOW
                )
                .is_err(),
                "{field}"
            );
        }
    }
    Ok(())
}

const WEB_URL: &str = "wss://gw.example.org/v1/session";
const WEB_ORIGIN: &str = "https://app.example.org";

fn web_node_body() -> NodeIdentityRecord {
    let mut body = node_body();
    body.channel_binding_modes.push(BindingMode::WebOriginBound);
    body.web_listeners =
        vec![WebListener { url: WEB_URL.into(), origins: vec![WEB_ORIGIN.into()] }];
    body
}
fn web_context() -> WebOriginBindingV1 {
    WebOriginBindingV1 {
        schema: WEB_ORIGIN_BINDING_SCHEMA.into(),
        version: 1,
        node_id: "node".into(),
        listener_url: WEB_URL.into(),
        origin: WEB_ORIGIN.into(),
        transport_kind: TRANSPORT_KIND_WEBSOCKET.into(),
        gateway_nonce: encode_base64url([31; 32]),
        issued_at: NOW,
        expires_at: NOW + 300,
    }
}
/// The fixture's native device signing a `web_origin_bound` proof for `context`.
fn web_proof(context: &WebOriginBindingV1) -> TestResult<Envelope<BranchProofV3>> {
    let mut body = proof(BindingMode::WebOriginBound)?.body;
    body.transport_binding = web_origin_binding_hash(context)?;
    Ok(sign_branch_proof_v3(&crate::create_device_branch("vector.example", "primary", 1, [3; 32]), body)?)
}
fn reason(result: Result<(), crate::CryptoError>) -> Option<&'static str> {
    match result {
        Err(crate::CryptoError::IdentityAuthority(reason)) => Some(reason),
        _ => None,
    }
}

#[test]
fn native_device_key_is_refused_through_the_web_channel_even_with_a_valid_receipt() -> TestResult {
    let node = node(web_node_body())?;
    let context = web_context();
    let proof = web_proof(&context)?;
    let hash = web_origin_binding_hash(&context)?;
    // The proxy signs for the web mode exactly as it does for the relay mode.
    let receipt =
        sign_proxy_acceptance(&key(7), &node, &proof, &hash, encode_base64url([23; 32]), NOW)?;
    let result = verify_branch_proof_v3(
        &authority()?,
        &proof,
        &challenge(BindingMode::WebOriginBound),
        "message",
        ProofChannel::WebOriginBound {
            receipt: &receipt,
            context: &context,
            historical_node: &node,
            current_node: &node,
        },
        NOW,
    );
    assert_eq!(reason(result), Some("device is not a web device linked to this origin"));
    Ok(())
}

#[test]
fn web_origin_bound_proof_is_refused_on_every_native_channel() -> TestResult {
    let node = node(web_node_body())?;
    let context = web_context();
    let proof = web_proof(&context)?;
    let hash = web_origin_binding_hash(&context)?;
    let receipt =
        sign_proxy_acceptance(&key(7), &node, &proof, &hash, encode_base64url([23; 32]), NOW)?;
    let challenge = challenge(BindingMode::WebOriginBound);
    let channels = [
        ProofChannel::DirectExporter { observed_hash: &hash, receiving_node: &node },
        ProofChannel::HomeRelayReceipt {
            receipt: &receipt,
            historical_node: &node,
            current_node: &node,
        },
        ProofChannel::NoChannelBinding { operator_opt_in: true, receiving_node: &node },
    ];
    for channel in channels {
        assert!(
            verify_branch_proof_v3(&authority()?, &proof, &challenge, "message", channel, NOW)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn proxy_does_not_vouch_for_a_web_binding_the_node_record_does_not_advertise() -> TestResult {
    let plain = node(node_body())?;
    let context = web_context();
    let proof = web_proof(&context)?;
    let hash = web_origin_binding_hash(&context)?;
    assert!(
        sign_proxy_acceptance(&key(7), &plain, &proof, &hash, encode_base64url([23; 32]), NOW)
            .is_err()
    );
    // A binding for another origin is not what the proof signed.
    let mut other = context.clone();
    other.origin = "https://other.example.org".into();
    let advertised = node(web_node_body())?;
    assert!(
        sign_proxy_acceptance(
            &key(7),
            &advertised,
            &proof,
            &web_origin_binding_hash(&other)?,
            encode_base64url([23; 32]),
            NOW
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn node_record_advertises_the_web_mode_and_its_listeners_together_or_not_at_all() -> TestResult {
    assert!(node(web_node_body()).is_ok());
    let mut mode_only = web_node_body();
    mode_only.web_listeners.clear();
    assert!(node(mode_only).is_err());
    let mut listeners_only = web_node_body();
    listeners_only.channel_binding_modes.pop();
    assert!(node(listeners_only).is_err());
    for bad in ["https://app.example.org/", "http://app.example.org", "null", "*"] {
        let mut body = web_node_body();
        body.web_listeners[0].origins = vec![bad.into()];
        assert!(node(body).is_err(), "{bad}");
    }
    let mut bad_url = web_node_body();
    bad_url.web_listeners[0].url = "wss://gw.example.org:443/v1/session".into();
    assert!(node(bad_url).is_err());
    Ok(())
}
