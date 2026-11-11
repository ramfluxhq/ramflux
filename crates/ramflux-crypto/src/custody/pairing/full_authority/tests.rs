// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::{
    custody::{SelfSigningKey, verify_record},
    public_key_base64url_from_seed, sign_canonical_bytes_with_seed,
};
use ramflux_protocol::{
    custody::pairing::full_transfer::lease::BranchKeys,
    custody::{DeviceRef, DeviceSet},
    encode_base64url,
};
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn b(byte: u8) -> String {
    encode_base64url([byte; 32])
}
fn fixture() -> TestResult<(SelfSigningKey, Envelope<DeviceSet>, DataGrant)> {
    let (_, primary, genesis) = crate::custody::tests::fixture()?;
    let grant = DataGrant {
        schema: "ramflux.pairing.full_transfer.data_grant.v1".into(),
        version: 1,
        transfer_id: b(1),
        node_id: "node.example".into(),
        source_ref: genesis.body.master_certificate.body.primary_device_ref.clone(),
        destination_ref: DeviceRef {
            account_anchor: genesis.body.account_anchor.clone(),
            device_id: "device-b".into(),
            device_epoch: 1,
        },
        branch_keys: BranchKeys {
            source: genesis.body.devices[0]
                .branch_certificate
                .as_ref()
                .ok_or("branch")?
                .body
                .branch_signing_public_key
                .clone(),
            destination: public_key_base64url_from_seed([10; 32]),
        },
        opaque_commitment: b(2),
        expires_at: genesis.body.issued_at + 604_800,
    };
    Ok((primary, genesis, grant))
}
fn enroll(
    primary: &SelfSigningKey,
    record: &Envelope<DeviceSet>,
    name: &str,
    seed: u8,
) -> TestResult<Envelope<DeviceSet>> {
    let mut branch =
        record.body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
    branch.device_id = name.into();
    branch.cert_id = b(seed);
    branch.branch_signing_public_key = public_key_base64url_from_seed([seed; 32]);
    branch.agreement_identity_public_key =
        encode_base64url(crate::X25519KeyPair::from_seed([seed + 1; 32]).public);
    Ok(primary.enroll_device(
        &verify_record(record, record.body.issued_at, None, None)?,
        primary.certify_branch(branch)?,
        record.body.issued_at,
    )?)
}
#[test]
fn full_lease_authority_allows_head_updates_but_refuses_revocation_and_reused_destination()
-> TestResult {
    let (primary, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    verify_full_prepublication_authority(&grant, &verify_record(&genesis, now, None, None)?, now)?;
    let linked = enroll(&primary, &genesis, "device-b", 10)?;
    let with_c = enroll(&primary, &linked, "device-c", 20)?;
    verify_full_prepublication_authority(&grant, &verify_record(&with_c, now, None, None)?, now)?;
    let revoked =
        primary.revoke_device(&verify_record(&with_c, now, None, None)?, "device-b", now)?;
    assert!(matches!(
        verify_full_prepublication_authority(
            &grant,
            &verify_record(&revoked, now, None, None)?,
            now
        ),
        Err(CryptoError::Pairing("HeadChanged"))
    ));
    let mut reused = grant.clone();
    reused.destination_ref.device_epoch = 2;
    assert!(
        verify_full_prepublication_authority(
            &reused,
            &verify_record(&linked, now, None, None)?,
            now
        )
        .is_err()
    );
    let mut changed = grant.clone();
    changed.branch_keys.destination = public_key_base64url_from_seed([21; 32]);
    assert!(
        verify_full_prepublication_authority(
            &changed,
            &verify_record(&linked, now, None, None)?,
            now
        )
        .is_err()
    );
    let revoked_a =
        primary.revoke_device(&verify_record(&linked, now, None, None)?, "primary", now)?;
    assert!(
        verify_full_prepublication_authority(
            &grant,
            &verify_record(&revoked_a, now, None, None)?,
            now
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn full_lease_request_requires_both_original_signatures_and_exact_role_scope() -> TestResult {
    let (_, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    let mut request = LeaseRequest {
        schema: "ramflux.pairing.full_transfer.lease_request.v1".into(),
        version: 1,
        invitation_id: b(5),
        issuer_seq: 1,
        transcript_hash: b(6),
        grant,
        source_signature: encode_base64url([0; 64]),
        destination_signature: encode_base64url([0; 64]),
    };
    request.source_signature =
        sign_canonical_bytes_with_seed(&request.signing_bytes("initiator")?, [3; 32]);
    request.destination_signature =
        sign_canonical_bytes_with_seed(&request.signing_bytes("responder")?, [10; 32]);
    let authority = verify_record(&genesis, now, None, None)?;
    verify_full_lease_request(&request, &authority, now)?;
    let mut reflected = request.clone();
    reflected.destination_signature = reflected.source_signature.clone();
    assert!(verify_full_lease_request(&reflected, &authority, now).is_err());
    let mut changed = request.clone();
    changed.transcript_hash = b(7);
    assert!(verify_full_lease_request(&changed, &authority, now).is_err());
    request.grant.expires_at = now;
    assert!(matches!(
        verify_full_lease_request(&request, &authority, now),
        Err(CryptoError::Pairing("LeaseExpired"))
    ));
    Ok(())
}
#[test]
fn full_resume_requires_both_original_branch_proofs_and_fresh_boot_challenge() -> TestResult {
    let (_, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    let lease = DataLease {
        schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
        version: 1,
        lease_id: b(4),
        grant,
        issued_at: now,
        expires_at: now + 604_800,
    };
    let proof = ResumeProof {
        schema: "ramflux.pairing.full_transfer.resume_proof.v1".into(),
        version: 1,
        lease_id: lease.lease_id.clone(),
        boot_id: b(5),
        nonce: b(6),
        role: "initiator".into(),
        hpke_keys: BranchKeys { source: b(7), destination: b(8) },
        epoch: b(9),
    };
    let source = Envelope {
        signature: sign_canonical_bytes_with_seed(&proof.signing_bytes()?, [3; 32]),
        body: proof,
    };
    let mut responder = source.body.clone();
    responder.role = "responder".into();
    let destination = Envelope {
        signature: sign_canonical_bytes_with_seed(&responder.signing_bytes()?, [10; 32]),
        body: responder,
    };
    verify_full_resume_pair(&lease, &source, &destination, &b(5), &b(6), now)?;
    assert!(verify_full_resume_pair(&lease, &source, &destination, &b(11), &b(6), now).is_err());
    assert!(verify_full_resume_pair(&lease, &source, &destination, &b(5), &b(11), now).is_err());
    let mut replaced = destination.clone();
    replaced.signature = sign_canonical_bytes_with_seed(&replaced.body.signing_bytes()?, [12; 32]);
    assert!(verify_full_resume_pair(&lease, &source, &replaced, &b(5), &b(6), now).is_err());
    assert!(verify_full_resume_pair(&lease, &source, &source, &b(5), &b(6), now).is_err());
    assert!(
        verify_full_resume_pair(&lease, &source, &destination, &b(5), &b(6), lease.expires_at)
            .is_err()
    );
    Ok(())
}
#[test]
fn full_tail_admission_accepts_expected_demotion_and_rejects_other_publication_or_removed_branch()
-> TestResult {
    let (primary, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    let linked = enroll(&primary, &genesis, "device-b", 10)?;
    let master = crate::custody::MasterKey::from_phrase(
        &crate::custody::RecoveryPhrase::from_entropy(&[0; 32])?,
    )?;
    let new_primary = SelfSigningKey::generate()?;
    let candidate = crate::custody::cooperative_transfer_preserving_devices(
        &master,
        &new_primary,
        &verify_record(&linked, now, None, None)?,
        crate::custody::CooperativeTransferInput {
            destination: grant.destination_ref.clone(),
            fresh_destination: None,
            highest_observed_range: 0,
            issued_at: now + 1,
            master_cert_id: b(40),
        },
    )?;
    let published = verify_record(&candidate, now + 1, None, None)?;
    verify_full_tail_authority(&grant, &published, now + 1)?;
    assert!(verify_full_prepublication_authority(&grant, &published, now + 1).is_err());
    let revoked = new_primary.revoke_device(&published, "primary", now + 2)?;
    assert!(
        verify_full_tail_authority(&grant, &verify_record(&revoked, now + 2, None, None)?, now + 2)
            .is_err()
    );
    Ok(())
}

#[test]
fn full_data_lease_uses_independently_trusted_node_and_original_grant() -> TestResult {
    use ramflux_protocol::custody::{
        BindingMode, NodeIdentityRecord, ReceiptKey, ReceiptKeyStatus,
    };
    let (_, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    let node_key = ed25519_dalek::SigningKey::from_bytes(&[50; 32]);
    let body = NodeIdentityRecord {
        schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
        version: 1,
        node_id: grant.node_id.clone(),
        node_signing_public_key: public_key_base64url_from_seed([50; 32]),
        client_tls_certificate_sha256: Some(b(51)),
        epoch: 1,
        previous_record_hash: None,
        issued_at: now,
        receipt_keys: vec![ReceiptKey {
            key_id: b(52),
            public_key: public_key_base64url_from_seed([53; 32]),
            not_before: now,
            sign_until: now + 2_591_900,
            overlap_until: now + 2_591_900 + 605_400,
            status: ReceiptKeyStatus::Active,
        }],
        revoked_receipt_key_ids: vec![],
        proxy_keys: vec![],
        revoked_proxy_key_ids: vec![],
        channel_binding_modes: vec![BindingMode::DirectExporter],
    };
    let record = crate::custody::sign_node_identity_record(&node_key, body)?;
    let node = crate::custody::verify_node_identity_record(
        &record,
        &grant.node_id,
        &public_key_base64url_from_seed([50; 32]),
        now,
    )?;
    let lease = DataLease {
        schema: "ramflux.pairing.full_transfer.data_lease.v1".into(),
        version: 1,
        lease_id: b(54),
        grant: grant.clone(),
        issued_at: now,
        expires_at: now + 604_800,
    };
    let signed = Envelope {
        signature: sign_canonical_bytes_with_seed(&lease.signing_bytes()?, [50; 32]),
        body: lease,
    };
    verify_full_data_lease(&signed, &grant, &node, now)?;
    let mut changed = grant.clone();
    changed.opaque_commitment = b(55);
    assert!(verify_full_data_lease(&signed, &changed, &node, now).is_err());
    let mut replaced = signed.clone();
    replaced.signature = sign_canonical_bytes_with_seed(&replaced.body.signing_bytes()?, [56; 32]);
    assert!(verify_full_data_lease(&replaced, &grant, &node, now).is_err());
    assert!(verify_full_data_lease(&signed, &grant, &node, signed.body.expires_at).is_err());
    Ok(())
}

#[test]
fn pairing_full_tail_relay_admission_is_data_only() -> TestResult {
    tail_admission_predicate()
}

#[test]
fn pairing_full_tail_admission_predicate() -> TestResult {
    tail_admission_predicate()
}

fn tail_admission_predicate() -> TestResult {
    let (primary, genesis, grant) = fixture()?;
    let now = genesis.body.issued_at;
    let linked = enroll(&primary, &genesis, "device-b", 10)?;
    let old = verify_record(&linked, now, None, None)?;
    assert!(
        matches!(
            verify_full_tail_authority(&grant, &old, now),
            Err(CryptoError::Pairing("HeadChanged"))
        ),
        "A-primary is not tail state"
    );
    let master = crate::custody::MasterKey::from_phrase(
        &crate::custody::RecoveryPhrase::from_entropy(&[0; 32])?,
    )?;
    let management = SelfSigningKey::generate()?;
    let candidate = crate::custody::cooperative_transfer_preserving_devices(
        &master,
        &management,
        &old,
        crate::custody::CooperativeTransferInput {
            destination: grant.destination_ref.clone(),
            fresh_destination: None,
            highest_observed_range: 0,
            issued_at: now + 1,
            master_cert_id: b(50),
        },
    )?;
    let current = verify_record(&candidate, now + 1, None, None)?;
    verify_full_tail_authority(&grant, &current, now + 1)?;
    // Passing the data-only predicate grants no prepublication/source-primary permission.
    assert!(verify_full_prepublication_authority(&grant, &current, now + 1).is_err());
    for changed in 0..5 {
        let mut wrong = grant.clone();
        match changed {
            0 => wrong.branch_keys.source = public_key_base64url_from_seed([90; 32]),
            1 => wrong.branch_keys.destination = public_key_base64url_from_seed([91; 32]),
            2 => wrong.source_ref.device_epoch += 1,
            3 => wrong.destination_ref.device_epoch += 1,
            _ => {
                wrong.source_ref.account_anchor = b(92);
                wrong.destination_ref.account_anchor = b(92);
            }
        }
        assert!(matches!(
            verify_full_tail_authority(&wrong, &current, now + 1),
            Err(CryptoError::Pairing("HeadChanged"))
        ));
    }
    let demoted = crate::custody::cooperative_transfer_preserving_devices(
        &master,
        &SelfSigningKey::generate()?,
        &current,
        crate::custody::CooperativeTransferInput {
            destination: grant.source_ref.clone(),
            fresh_destination: None,
            highest_observed_range: ramflux_protocol::custody::decode_epoch(
                current.envelope().body.device_set_epoch,
            )?
            .0,
            issued_at: now + 2,
            master_cert_id: b(51),
        },
    )?;
    let demoted = verify_record(&demoted, now + 2, None, None)?;
    assert!(matches!(
        verify_full_tail_authority(&grant, &demoted, now + 2),
        Err(CryptoError::Pairing("HeadChanged"))
    ));
    let revoked = management.revoke_device(&current, &grant.source_ref.device_id, now + 2)?;
    let revoked = verify_record(&revoked, now + 2, None, None)?;
    assert!(matches!(
        verify_full_tail_authority(&grant, &revoked, now + 2),
        Err(CryptoError::Pairing("HeadChanged"))
    ));
    let mut absent = candidate.body.clone();
    absent.devices.retain(|device| device.device_id != grant.source_ref.device_id);
    let absent = management.sign_record(absent)?;
    let absent = verify_record(&absent, now + 1, None, None)?;
    assert!(matches!(
        verify_full_tail_authority(&grant, &absent, now + 1),
        Err(CryptoError::Pairing("HeadChanged"))
    ));
    assert!(matches!(
        verify_full_tail_authority(&grant, &current, grant.expires_at),
        Err(CryptoError::Pairing("LeaseExpired"))
    ));
    Ok(())
}

#[test]
fn pairing_full_j3_lease_margin_is_checked_before_candidate() -> TestResult {
    let (_, _, mut grant) = fixture()?;
    let now = grant.expires_at - 604_800;
    for hours in [23, 24, 25] {
        grant.expires_at = now + hours * 3600;
        let result = verify_full_j3_lease_margin(&grant, now);
        if hours < 24 {
            assert!(matches!(result, Err(CryptoError::Pairing("LeaseExpired"))));
        } else {
            result?;
        }
    }
    for expiry in [now - 1, now, u64::MAX] {
        grant.expires_at = expiry;
        assert!(verify_full_j3_lease_margin(&grant, now).is_err());
    }
    Ok(())
}
