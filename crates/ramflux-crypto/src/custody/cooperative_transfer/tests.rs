// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::custody::{RecoveryPhrase, verify_record};
use ramflux_protocol::{canonical_json_bytes, encode_base64url};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn cooperative_transfer_keeps_all_branch_keys_and_denials() -> TestResult {
    let (_, old, genesis) = crate::custody::tests::fixture()?;
    let now = genesis.body.issued_at;
    let base_certificate =
        genesis.body.devices[0].branch_certificate.as_ref().ok_or("certificate")?;
    let template = base_certificate.body.clone();
    let mut source = genesis;
    for (index, name) in ["device-b", "device-c", "retired"].into_iter().enumerate() {
        let mut branch = template.clone();
        branch.device_id = name.into();
        let seed = u8::try_from(index)? + 10;
        let signing = crate::create_device_branch(&source.body.principal_id, name, 1, [seed; 32]);
        branch.branch_signing_public_key =
            encode_base64url(signing.signing_key.verifying_key().to_bytes());
        branch.agreement_identity_public_key =
            encode_base64url(crate::X25519KeyPair::from_seed([seed + 1; 32]).public);
        branch.cert_id = encode_base64url([seed; 32]);
        source = old.enroll_device(
            &verify_record(&source, now, None, None)?,
            old.certify_branch(branch)?,
            now,
        )?;
    }
    source = old.revoke_device(&verify_record(&source, now, None, None)?, "retired", now)?;
    let verified = verify_record(&source, now, None, None)?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    for fresh in [false, true] {
        let destination = DeviceRef {
            account_anchor: source.body.account_anchor.clone(),
            device_id: if fresh { "fresh-target" } else { "device-b" }.into(),
            device_epoch: 1,
        };
        let new_branch = if fresh {
            let mut branch = template.clone();
            branch.device_id.clone_from(&destination.device_id);
            let signing = crate::create_device_branch(
                &source.body.principal_id,
                &branch.device_id,
                1,
                [77; 32],
            );
            branch.branch_signing_public_key =
                encode_base64url(signing.signing_key.verifying_key().to_bytes());
            branch.agreement_identity_public_key =
                encode_base64url(crate::X25519KeyPair::from_seed([78; 32]).public);
            Some(branch)
        } else {
            None
        };
        let primary = SelfSigningKey::generate()?;
        let next = cooperative_transfer_preserving_devices(
            &master,
            &primary,
            &verified,
            CooperativeTransferInput {
                destination: destination.clone(),
                fresh_destination: new_branch,
                highest_observed_range: 7,
                issued_at: now + 1,
                master_cert_id: encode_base64url([88; 32]),
            },
        )?;
        let accepted = verify_record(&next, now + 1, None, None)?;
        verify_cooperative_preservation(&verified, &accepted, &destination, fresh)?;
        assert_rejects_changed_lease(&verified, &next, &primary, &destination, fresh, now + 1)?;
        assert_eq!(next.body.devices.len(), source.body.devices.len() + usize::from(fresh));
        assert_eq!(next.body.master_certificate.body.primary_device_ref, destination);
        assert_eq!(decode_epoch(next.body.device_set_epoch)?.0, 8);
        assert_ne!(next.body.master_certificate.body.self_signing_public_key, old.public_key());
        assert_eq!(next.body.account_anchor, source.body.account_anchor);
        assert_eq!(next.body.delegations, source.body.delegations);
        assert_eq!(next.body.revoked_delegation_ids, source.body.revoked_delegation_ids);
        assert_retained(&source, &next, &accepted, now + 1)?;
        assert!(accepted.revoked_ids().contains("retired"));
        assert!(old.sign_record(next.body.clone()).is_err());
    }
    Ok(())
}

fn assert_retained(
    source: &Envelope<DeviceSet>,
    next: &Envelope<DeviceSet>,
    accepted: &VerifiedRecord,
    now: u64,
) -> TestResult {
    for before in &source.body.devices {
        let after = next
            .body
            .devices
            .iter()
            .find(|device| device.device_id == before.device_id)
            .ok_or("missing retained peer")?;
        assert_eq!(after.device_epoch, before.device_epoch);
        assert_eq!(after.signing_key_commitment, before.signing_key_commitment);
        assert_eq!(after.agreement_key_commitment, before.agreement_key_commitment);
        assert_eq!(after.status, before.status);
        assert_eq!(after.revoked_at, before.revoked_at);
        assert_eq!(after.message_layer, before.message_layer);
        match (&before.branch_certificate, &after.branch_certificate) {
            (Some(before), Some(after)) => {
                assert_eq!(before.body.capabilities, after.body.capabilities);
                assert_eq!(before.body.not_before, after.body.not_before);
                assert_eq!(before.body.expires_at, after.body.expires_at);
                assert_eq!(
                    before.body.branch_signing_public_key,
                    after.body.branch_signing_public_key
                );
                assert_eq!(
                    before.body.agreement_identity_public_key,
                    after.body.agreement_identity_public_key
                );
                let reference = DeviceRef {
                    account_anchor: source.body.account_anchor.clone(),
                    device_id: before.body.device_id.clone(),
                    device_epoch: before.body.device_epoch,
                };
                accepted.authorize(&reference, "register", now)?;
            }
            (None, None) => {
                assert_eq!(canonical_json_bytes(before)?, canonical_json_bytes(after)?);
            }
            _ => return Err("retained branch certificate disappeared".into()),
        }
    }
    Ok(())
}

fn assert_rejects_changed_lease(
    source: &VerifiedRecord,
    candidate: &Envelope<DeviceSet>,
    primary: &SelfSigningKey,
    destination: &DeviceRef,
    fresh: bool,
    now: u64,
) -> TestResult {
    let mut body = candidate.body.clone();
    let device = body
        .devices
        .iter_mut()
        .find(|device| device.device_id == "device-c")
        .ok_or("retained C")?;
    let mut cert = device.branch_certificate.as_ref().ok_or("branch certificate")?.body.clone();
    cert.expires_at -= 1;
    device.branch_certificate = Some(primary.certify_branch(cert)?);
    let signed = primary.sign_record(body)?;
    let verified = verify_record(&signed, now, None, None)?;
    assert!(verify_cooperative_preservation(source, &verified, destination, fresh).is_err());
    Ok(())
}
