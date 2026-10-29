// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replacement cannot revive old management authority or discard compacted denials.
use super::*;
use ramflux_protocol::custody::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn master_recovery_skips_observed_ranges_revokes_old_devices_and_keeps_checkpoint_denials()
-> TestResult {
    let (_, old, genesis) = super::super::tests::fixture()?;
    let now = genesis.body.issued_at;
    let names = vec!["previously-compacted".to_owned()];
    let mut prior = genesis.body.clone();
    let checkpoint = RevokedCheckpoint {
        schema: ramflux_protocol::domain::CUSTODY_REVOKED_CHECKPOINT.into(),
        version: 1,
        account_anchor: prior.account_anchor.clone(),
        master_certificate_hash: object_hash(&prior.master_certificate)?,
        device_set_epoch: prior.device_set_epoch,
        previous_checkpoint_hash: None,
        list_hash: framed_hash(ramflux_protocol::domain::CUSTODY_REVOKED_LIST, &names)?,
        count: 1,
        compacted_before: now - 7_776_000,
        issued_at: now,
    };
    let signature = crate::sign_canonical_bytes_with_seed(
        &signing_bytes(ramflux_protocol::domain::CUSTODY_REVOKED_CHECKPOINT, &checkpoint)?,
        *old.vault_seed(),
    );
    prior.revoked_device_checkpoint = Some(Envelope { body: checkpoint, signature });
    let prior = old.sign_record(prior)?;
    let verified = super::super::verify_record(&prior, now, Some(&names), None)?;
    let master = MasterKey::from_phrase(&super::super::RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let primary = SelfSigningKey::generate()?;
    let branch = crate::create_device_branch(&prior.body.principal_id, "replacement", 1, [19; 32]);
    let next = recover_primary(
        &master,
        &primary,
        &branch,
        &crate::X25519KeyPair::from_seed([20; 32]),
        &verified,
        RecoveryInput {
            highest_observed_range: 8,
            issued_at: now + 1,
            master_cert_id: ramflux_protocol::encode_base64url([21; 32]),
            branch_cert_id: ramflux_protocol::encode_base64url([22; 32]),
        },
    )?;
    let recovered = super::super::verify_record(&next, now + 1, Some(&names), None)?;
    let mut pins = super::super::AuthorityPins::default();
    pins.observe(&verified)?;
    pins.observe(&recovered)?;
    assert_eq!(decode_epoch(next.body.device_set_epoch)?.0, 9);
    assert_eq!(next.body.account_anchor, prior.body.account_anchor);
    assert!(recovered.revoked_ids().contains("previously-compacted"));
    assert!(
        recovered
            .authorize(&prior.body.master_certificate.body.primary_device_ref, "register", now + 1)
            .is_err()
    );
    assert!(pins.require_current(&verified).is_err());
    let mut attacker = prior.body.clone();
    attacker.device_set_epoch = encode_epoch(1, MAX_REVISION)?;
    assert!(
        pins.observe(&super::super::verify_record(
            &old.sign_record(attacker)?,
            now + 1,
            Some(&names),
            None
        )?)
        .is_err()
    );
    recovered.authorize(
        &next.body.master_certificate.body.primary_device_ref,
        "register",
        now + 1,
    )?;
    Ok(())
}

#[test]
fn different_master_cannot_recover_the_same_anchor() -> TestResult {
    let (_, _, record) = super::super::tests::fixture()?;
    let now = record.body.issued_at;
    let verified = super::super::verify_record(&record, now, None, None)?;
    let wrong = MasterKey::from_phrase(&super::super::RecoveryPhrase::from_entropy(&[1; 32])?)?;
    let branch = crate::create_device_branch(&record.body.principal_id, "replacement", 1, [19; 32]);
    assert!(
        recover_primary(
            &wrong,
            &SelfSigningKey::generate()?,
            &branch,
            &crate::X25519KeyPair::from_seed([20; 32]),
            &verified,
            RecoveryInput {
                highest_observed_range: 1,
                issued_at: now,
                master_cert_id: ramflux_protocol::encode_base64url([21; 32]),
                branch_cert_id: ramflux_protocol::encode_base64url([22; 32])
            }
        )
        .is_err()
    );
    Ok(())
}
