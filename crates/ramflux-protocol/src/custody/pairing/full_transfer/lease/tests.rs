// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{canonical_json_bytes, encode_base64url};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fixture() -> TestResult<(LeaseRequest, TranscriptV3)> {
    let value = crate::custody::pairing::context_v3::tests::fixture()?;
    let transcript = TranscriptV3::from_wire_bytes(&canonical_json_bytes(&value)?)?;
    let a = &transcript.initiator;
    let b = &transcript.responder;
    let request = LeaseRequest {
        schema: "ramflux.pairing.full_transfer.lease_request.v1".into(),
        version: 1,
        invitation_id: a.common.invitation_id.clone(),
        issuer_seq: a.common.issuer_seq,
        transcript_hash: encode_base64url([44; 32]),
        grant: DataGrant {
            schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
            version: 1,
            transfer_id: a.common.transfer_id.clone().ok_or("transfer id")?,
            node_id: "trusted-node".into(),
            source_ref: a.device_ref.clone(),
            destination_ref: b.device_ref.clone(),
            branch_keys: BranchKeys {
                source: a.branch_key.clone(),
                destination: b.branch_key.clone(),
            },
            opaque_commitment: encode_base64url(opaque_commitment(&[31; 32], &[32; 32])),
            expires_at: 100 + 604_800,
        },
        source_signature: encode_base64url([1; 64]),
        destination_signature: encode_base64url([2; 64]),
    };
    Ok((request, transcript))
}
#[test]
fn full_data_lease_is_closed_bounded_and_binds_both_frozen_roles() -> TestResult {
    let (request, transcript) = fixture()?;
    request.bind_transcript(&transcript, &encode_base64url([44; 32]))?;
    let encoded = request.to_wire_bytes()?;
    assert!(encoded.len() < 8192);
    assert!(LeaseRequest::from_wire_bytes(&encoded).is_ok());
    assert!(!String::from_utf8(encoded)?.contains("manifest_hash"));
    assert_ne!(request.signing_bytes("initiator")?, request.signing_bytes("responder")?);
    assert!(request.signing_bytes("primary").is_err());
    let mut changed = request.clone();
    changed.grant.branch_keys.destination = encode_base64url([99; 32]);
    assert!(changed.bind_transcript(&transcript, &encode_base64url([44; 32])).is_err());
    assert!(request.bind_transcript(&transcript, &encode_base64url([45; 32])).is_err());
    let mut changed = request;
    changed.grant.destination_ref.device_id = "another-device".into();
    assert!(changed.bind_transcript(&transcript, &encode_base64url([44; 32])).is_err());
    Ok(())
}
#[test]
fn full_data_lease_expiry_and_seven_day_boundary_do_not_revive_old_authority() -> TestResult {
    let (request, _) = fixture()?;
    let mut lease = DataLease {
        schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
        version: 1,
        lease_id: encode_base64url([7; 32]),
        grant: request.grant,
        issued_at: 100,
        expires_at: 100 + 604_800,
    };
    lease.require_live(100)?;
    lease.require_live(lease.expires_at - 1)?;
    assert_eq!(lease.require_live(lease.expires_at), Err(WireError::Field("LeaseExpired")));
    lease.expires_at += 1;
    assert!(lease.validate().is_err());
    Ok(())
}
#[test]
fn full_data_resume_requires_matching_original_pair_and_fresh_common_operands() -> TestResult {
    let proof = ResumeProof {
        schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
        version: 1,
        lease_id: encode_base64url([1; 32]),
        boot_id: encode_base64url([2; 32]),
        nonce: encode_base64url([3; 32]),
        role: "initiator".into(),
        hpke_keys: BranchKeys {
            source: encode_base64url([4; 32]),
            destination: encode_base64url([5; 32]),
        },
        epoch: encode_base64url([6; 32]),
    };
    let mut peer = proof.clone();
    peer.role = "responder".into();
    proof.require_peer(&peer)?;
    assert_ne!(proof.signing_bytes()?, peer.signing_bytes()?);
    assert!(proof.require_peer(&proof).is_err());
    peer.epoch = encode_base64url([7; 32]);
    assert!(proof.require_peer(&peer).is_err());
    peer.epoch = proof.epoch.clone();
    peer.nonce = encode_base64url([7; 32]);
    assert!(proof.require_peer(&peer).is_err());
    Ok(())
}
#[test]
fn full_data_private_opening_binds_the_hidden_manifest_without_a_public_root() -> TestResult {
    let (request, _) = fixture()?;
    let binding = DataBinding {
        profile: "primary_transfer_full_v1".into(),
        transfer_id: request.grant.transfer_id.clone(),
        manifest_hash: encode_base64url([31; 32]),
        epoch: encode_base64url([8; 32]),
        source_ref: request.grant.source_ref.clone(),
        destination_ref: request.grant.destination_ref.clone(),
        base_record_hash: encode_base64url([9; 32]),
    };
    bind_channel(&request.grant, &binding, &[32; 32])?;
    assert!(bind_channel(&request.grant, &binding, &[33; 32]).is_err());
    let mut independent = 29_u32.to_be_bytes().to_vec();
    independent.extend_from_slice(b"ramflux.pairing.full.lease.v1");
    independent.extend_from_slice(&[31; 32]);
    independent.extend_from_slice(&[32; 32]);
    assert_eq!(opaque_commitment(&[31; 32], &[32; 32]), *blake3::hash(&independent).as_bytes());
    Ok(())
}
