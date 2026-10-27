// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conflict ordering and retention regressions across authenticated range advances.
use super::*;
use crate::custody::{MasterKey, RecoveryPhrase, SelfSigningKey, verify_record};
use ramflux_protocol::{custody::encode_epoch, encode_base64url};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn lower_revision_master_certificate_fork_in_current_range_is_fenced() -> Result {
    let (_, primary, genesis) = super::super::tests::fixture()?;
    let now = genesis.body.issued_at;
    let mut pins = AuthorityPins::default();
    let first = verify_record(&genesis, now, None, None)?;
    pins.observe(&first)?;
    let second = primary.revoke_device(&first, "primary", now + 1)?;
    pins.observe(&verify_record(&second, now + 1, None, None)?)?;
    let mut third = second.body.clone();
    third.device_set_epoch = encode_epoch(1, 3)?;
    third.previous_record_hash = Some(object_hash(&second)?);
    let third = primary.sign_record(third)?;
    let third = verify_record(&third, now + 2, None, None)?;
    pins.observe(&third)?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let mut cert = second.body.master_certificate.body.clone();
    cert.cert_id = encode_base64url([91; 32]);
    let mut fork = second.body.clone();
    fork.master_certificate = master.certify(cert)?;
    let fork = primary.sign_record(fork)?;
    let fork = verify_record(&fork, now + 2, None, None)?;
    let PinOutcome::Fenced(alert) = pins.observe(&fork)? else {
        return Err("fork was not fenced".into());
    };
    assert_eq!(alert.kind, CustodyConflictKind::MasterCertificate);
    let evidence = pins.conflict_evidence(&genesis.body.account_anchor, 1).ok_or("evidence")?;
    assert_eq!(&evidence.accepted, third.envelope());
    assert_eq!(&evidence.conflicting, fork.envelope());
    assert!(pins.require_current(&third).is_err());
    Ok(())
}

fn next_range(
    primary: &SelfSigningKey,
    master: &MasterKey,
    previous: &Envelope<DeviceSet>,
    range: u64,
) -> Result<Envelope<DeviceSet>> {
    let mut body = previous.body.clone();
    let mut cert = body.master_certificate.body.clone();
    cert.range_index = range;
    cert.cert_id = encode_base64url([u8::try_from(range)?; 32]);
    cert.previous_certificate_hash = Some(object_hash(&body.master_certificate)?);
    body.master_certificate = master.certify(cert)?;
    for device in &mut body.devices {
        if let Some(cert) = &device.branch_certificate {
            let mut cert = cert.body.clone();
            cert.master_certificate_hash = object_hash(&body.master_certificate)?;
            device.branch_certificate = Some(primary.certify_branch(cert)?);
        }
    }
    body.previous_record_hash = Some(object_hash(previous)?);
    body.device_set_epoch = encode_epoch(range, 1)?;
    primary.sign_record(body).map_err(Into::into)
}

#[test]
fn normal_range_advances_retain_recent_conflicts_instead_of_stale_accepted_copies() -> Result {
    let (_, primary, mut current) = super::super::tests::fixture()?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let now = current.body.issued_at;
    let anchor = current.body.account_anchor.clone();
    let mut pins = AuthorityPins::default();
    pins.observe(&verify_record(&current, now, None, None)?)?;
    for range in 2..=18 {
        current = next_range(&primary, &master, &current, range)?;
        pins.observe(&verify_record(&current, now, None, None)?)?;
        if range == 8 || range >= 11 {
            let mut fork = current.body.clone();
            fork.profile.display_name = "Conflicting profile".into();
            let fork = primary.sign_record(fork)?;
            assert!(matches!(
                pins.observe(&verify_record(&fork, now, None, None)?)?,
                PinOutcome::Fenced(_)
            ));
        }
        if range == 9 || range == 10 {
            assert!(pins.conflict_evidence(&anchor, 8).is_some());
        }
    }
    assert!(pins.conflict_evidence(&anchor, 8).is_none());
    for range in 11..=18 {
        assert!(pins.conflict_evidence(&anchor, range).is_some());
    }
    assert_eq!(pins.accounts[&anchor].conflicts.len(), 8);
    assert!(pins.accounts[&anchor].range_records.len() <= 1);
    Ok(())
}
