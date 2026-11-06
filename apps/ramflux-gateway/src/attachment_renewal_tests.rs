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
        source_peer: "source".into(),
        authority_generation: 3,
        home_key: ed25519_dalek::SigningKey::from_bytes(
            &bytes(&r["source_home_seed_hex"])?.try_into().map_err(|_| "seed")?,
        ),
    };
    let attempt = HomeRenewalAttempt {
        request: &request,
        grant: &grant,
        challenge: [0xc1; 32],
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
    mesh_round_trip(&forwarded, &bytes(&r["token"]["bytes_hex"])?).await?;
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
    Ok(())
}

async fn mesh_round_trip(forwarded: &ForwardedRenewal, token: &[u8]) -> Result {
    use crate::clients::tests::{issue_test_ca_and_service_cert, temp_cert_root};
    let root = temp_cert_root("attachment-renewal")?;
    let home = issue_test_ca_and_service_cert(&root, "mesh", "ramflux-gateway")?;
    let source = issue_test_ca_and_service_cert(&root, "mesh", "ramflux-source")?;
    let client_tls = home.tls.clone();
    let trusted_source = source.ca_pem.clone();
    let roots = std::sync::Arc::new(move || Ok(vec![home.ca_pem.clone()]));
    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &source.tls,
        roots,
    )?;
    let endpoint = server.local_addr()?.to_string();
    let expected = forwarded.clone();
    let response = token.to_vec();
    let mut task = tokio::spawn(async move {
        let connection = server.accept_connection().await?;
        let accepted =
            ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(
                &connection,
            )
            .await?;
        let ramflux_transport::MeshQuicAcceptedWireRequest::Json(accepted) = accepted else {
            return Err(anyhow::anyhow!("native renewal transport framing"));
        };
        anyhow::ensure!(
            accepted.request.method == "POST" && accepted.request.path == "/s9/attachments/renew",
            "renewal path"
        );
        let actual: ForwardedRenewal = serde_json::from_value(accepted.request.body.clone())?;
        anyhow::ensure!(actual == expected, "forwarded native bytes changed");
        accepted.write_json_response(200, &response).await?;
        // Keep the authenticated connection owner alive until the client has read.
        Ok::<_, anyhow::Error>((server, connection))
    });
    let round_trip = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let received =
            post_forwarded(&endpoint, &client_tls, "ramflux-source", &[trusted_source], forwarded)
                .await?;
        anyhow::ensure!(received == token, "renewal token response changed");
        let owners = (&mut task).await??;
        drop(owners);
        Ok::<_, anyhow::Error>(())
    })
    .await;
    match round_trip {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            task.abort();
            let _ = task.await;
            let _ = std::fs::remove_dir_all(&root);
            return Err(error.into());
        }
        Err(elapsed) => {
            task.abort();
            let _ = task.await;
            let _ = std::fs::remove_dir_all(&root);
            return Err(anyhow::anyhow!("renewal mesh round trip exceeded 15s: {elapsed}").into());
        }
    }
    std::fs::remove_dir_all(root)?;
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
