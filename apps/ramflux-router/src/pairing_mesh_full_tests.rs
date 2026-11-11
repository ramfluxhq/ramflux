// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Raw DTOs through the router's real header admission, native loan and dispatch owners.
use super::*;
use crate::pairing_full::{ReadContext, Reply};
use ramflux_protocol::custody::{
    Envelope,
    pairing::full_transfer::{
        PROFILE, SecretBase64,
        lease::{BranchKeys, DataGrant, DataLease},
        relay::{FullClaim, FullDiscovery, FullProofReply, HelloFull, ProveFull, ResumeTokenFull},
    },
};

fn lease(
    handle: &RouterHandle,
) -> anyhow::Result<(Envelope<DataLease>, ramflux_node_core::CustodyPublication)> {
    use ramflux_crypto::custody::{
        GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
    };
    let now = wall()?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[61; 32])?)?;
    let management = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([62; 32]));
    let branch = ramflux_crypto::create_device_branch("raw-pairing", "primary", 1, [63; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([64; 32]);
    let record = create_genesis(
        &master,
        &management,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "Raw pairing".into(),
            issued_at: now,
            master_cert_id: id(65),
            branch_cert_id: id(66),
            external_human_primary: None,
        },
    )?;
    handle.state().publish_custody_record(
        &ramflux_node_core::CustodyPublication { record: record.clone(), compacted_ids: None },
        now,
        handle.store(),
    )?;
    let source_ref = record.body.master_certificate.body.primary_device_ref.clone();
    let destination_ref = DeviceRef { device_id: "new-b".into(), ..source_ref.clone() };
    let mut destination_branch = record.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("source branch"))?
        .body
        .clone();
    destination_branch.device_id = destination_ref.device_id.clone();
    destination_branch.branch_signing_public_key =
        ramflux_crypto::public_key_base64url_from_seed([69; 32]);
    destination_branch.agreement_identity_public_key =
        encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([79; 32]).public);
    destination_branch.cert_id = id(80);
    let candidate = ramflux_crypto::custody::cooperative_transfer_preserving_devices(
        &master,
        &SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([81; 32])),
        &ramflux_crypto::custody::verify_record(&record, now, None, None)?,
        ramflux_crypto::custody::CooperativeTransferInput {
            destination: destination_ref.clone(),
            fresh_destination: Some(destination_branch),
            highest_observed_range: 0,
            issued_at: now,
            master_cert_id: id(82),
        },
    )?;
    let body = DataLease {
        schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
        version: 1,
        lease_id: id(67),
        issued_at: now,
        expires_at: now + 604_800,
        grant: DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: id(68),
            node_id: "node".into(),
            source_ref,
            destination_ref,
            branch_keys: BranchKeys {
                source: ramflux_crypto::public_key_base64url_from_seed([63; 32]),
                destination: ramflux_crypto::public_key_base64url_from_seed([69; 32]),
            },
            opaque_commitment: id(70),
            expires_at: now + 604_800,
        },
    };
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &body.signing_bytes()?,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    Ok((
        Envelope { body, signature },
        ramflux_node_core::CustodyPublication { record: candidate, compacted_ids: None },
    ))
}
fn raw(ctx: &ReadContext<'_>, path: &str, headers: &str, body: &[u8]) -> anyhow::Result<Reply> {
    let header = format!(
        "POST {path} HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    );
    let mut bytes = header.into_bytes();
    bytes.extend_from_slice(body);
    let request = ramflux_transport::read_bounded_mesh_http_request_with_admission(
        &mut std::io::Cursor::new(bytes),
        &crate::pairing_full::cap,
        |method, path, original, bytes| {
            crate::pairing_full::admit(ctx, method, path, original, bytes)
        },
    )?
    .ok_or_else(|| anyhow::anyhow!("request absent"))?;
    let (mut request, mut ingress) = request.into_parts();
    let ingress = ingress.as_mut().ok_or_else(|| anyhow::anyhow!("full ingress absent"))?;
    Ok(crate::pairing_full::handle(ctx, ingress, &mut request))
}
fn claim(ctx: &ReadContext<'_>, value: &FullClaim) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let reply = raw(
        ctx,
        PAIRING_CLAIM_PATH,
        "X-Ramflux-Pairing-Source: 203.0.113.10\r\n",
        &value.encode_secret()?,
    )?;
    match reply {
        Reply::Bytes(bytes) => Ok(bytes),
        Reply::Data(_) => anyhow::bail!("wrong claim reply"),
    }
}
fn prove(
    ctx: &ReadContext<'_>,
    template: &ramflux_protocol::custody::pairing::full_transfer::lease::ResumeProof,
    who: &str,
    seed: u8,
) -> anyhow::Result<FullProofReply> {
    let mut body = template.clone();
    body.role = who.into();
    let proof = Envelope {
        signature: ramflux_crypto::sign_canonical_bytes_with_seed(
            &body.signing_bytes()?,
            [seed; 32],
        ),
        body,
    };
    Ok(FullProofReply::from_wire_bytes(&claim(
        ctx,
        &FullClaim::Proof(Box::new(ProveFull {
            kind: "prove_full".into(),
            profile: PROFILE.into(),
            proof,
        })),
    )?)?)
}
fn tokens(
    ctx: &ReadContext<'_>,
    lease: Envelope<DataLease>,
) -> anyhow::Result<(ResumeTokenFull, ResumeTokenFull)> {
    let mut hello = HelloFull {
        epoch: id(71),
        hpke_key: encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([72; 32]).public),
        kind: "hello_full".into(),
        lease,
        profile: PROFILE.into(),
        role: "initiator".into(),
    };
    let first =
        FullDiscovery::from_wire_bytes(&claim(ctx, &FullClaim::Hello(Box::new(hello.clone())))?)?;
    assert!(first.template.is_none());
    hello.role = "responder".into();
    hello.hpke_key = encode_base64url(ramflux_crypto::X25519KeyPair::from_seed([73; 32]).public);
    let both = FullDiscovery::from_wire_bytes(&claim(ctx, &FullClaim::Hello(Box::new(hello)))?)?;
    let template = both.template.ok_or_else(|| anyhow::anyhow!("proof template"))?;
    assert!(matches!(prove(ctx, &template, "initiator", 63)?, FullProofReply::Pending(_)));
    let FullProofReply::Ready(b) = prove(ctx, &template, "responder", 69)? else {
        anyhow::bail!("B not ready")
    };
    let FullProofReply::Ready(a) = prove(ctx, &template, "initiator", 63)? else {
        anyhow::bail!("A not ready")
    };
    assert_eq!(a.peer_proof.body.role, "responder");
    assert_eq!(b.peer_proof.body.role, "initiator");
    Ok((*a, *b))
}
fn authorization(token: &ResumeTokenFull) -> anyhow::Result<String> {
    let raw = token.token.decode(32)?;
    Ok(format!(
        "PairingFull {}.{}.{}.{}",
        token.lease_id,
        token.epoch,
        token.role,
        encode_base64url(raw.as_slice())
    ))
}
#[test]
fn pairing_mesh_full_raw_claim_proof_and_atomic_prebody_forward_are_wired() -> TestResult {
    use ramflux_node_core::pairing_relay::{
        FULL_MESH_ADMIT_PATH, FullArm, FullMeshAdmit, FullMeshPermit, SecretAuthorization,
    };
    let (handle, _env, _redb, _record, _) = wired_handle("pairing-mesh-full-raw")?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let socket = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (_remote, _) = listener.accept()?;
    let peer = ramflux_node_core::parse_mesh_spiffe_uri("spiffe://node/ramflux-federation")?;
    let ctx =
        ReadContext { router: &handle, peer: &peer, socket, accepted: std::time::Instant::now() };
    let (lease, candidate) = lease(&handle)?;
    let (a, _b) = tokens(&ctx, lease)?;
    let body = ramflux_protocol::custody::pairing::full_transfer::relay::CloseFull {
        epoch: a.epoch.clone(),
        kind: "close_full".into(),
        lease_id: a.lease_id.clone(),
        profile: PROFILE.into(),
        role: a.role.clone(),
        token: a.token.clone(),
    }
    .encode_secret()?;
    let auth = authorization(&a)?;
    let admit = FullMeshAdmit {
        arm: FullArm::Close,
        authorization: SecretAuthorization::new(auth.clone()),
        content_length: body.len() as u64,
        request_nonce: SecretBase64::from_bytes(&[74; 32]),
    };
    let Reply::Bytes(reply) = raw(&ctx, FULL_MESH_ADMIT_PATH, "", &admit.encode_secret()?)? else {
        anyhow::bail!("missing permit reply")
    };
    let permit = FullMeshPermit::from_wire_bytes(&reply)?;
    // Native publication races the outstanding prepublication permit. Claim must derive
    // Tail from its own newly installed head; no caller-provided admission arm exists.
    let before = handle
        .state()
        .custody_record(&candidate.record.body.account_anchor, wall()?)?
        .ok_or_else(|| anyhow::anyhow!("current head"))?;
    handle.state().publish_custody_record(&candidate, wall()?, handle.store())?;
    assert!(
        handle.state().publish_custody_record(&before, wall()?, handle.store()).is_err(),
        "stale prepublication native head reopened the old arm"
    );
    let headers = format!(
        "Authorization: {auth}\r\nX-Ramflux-Pairing-Arm: close\r\nX-Ramflux-Pairing-Nonce: {}\r\nX-Ramflux-Pairing-Permit: {}\r\n",
        encode_base64url([74; 32]),
        encode_base64url(permit.permit.decode(32)?.as_slice())
    );
    assert!(matches!(
        raw(&ctx, FullArm::Close.mesh_path(), &headers, &body)?,
        Reply::Data(ramflux_node_core::pairing_relay::FullAdmittedReply::Closed)
    ));
    assert!(
        raw(&ctx, FullArm::Close.mesh_path(), &headers, &body).is_err(),
        "claimed permit replayed"
    );
    Ok(())
}
