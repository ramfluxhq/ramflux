// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed controls for custody name, transition and compacted-revocation guards.
use super::*;
use crate::CryptoError;
use ramflux_protocol::{DeviceSetStatus, ProtocolError};

const UNSAFE_NAMES: [&str; 5] = ["   ", "a\u{200b}b", "a\u{202e}b", "root~x", "legacy~x"];

fn assert_authority_error<T: std::fmt::Debug>(
    result: &std::result::Result<T, CryptoError>,
    expected: &'static str,
) {
    assert!(
        matches!(result, Err(CryptoError::IdentityAuthority(reason)) if *reason == expected),
        "expected {expected:?}, got {result:?}"
    );
}

fn tombstone(record: &Envelope<DeviceSet>, id: &str) -> Device {
    let mut device = record.body.devices[0].clone();
    device.device_id = id.into();
    device.status = DeviceSetStatus::Revoked;
    device.revoked_at = Some(record.body.issued_at);
    device.branch_certificate = None;
    device.migration_state = MigrationState::Revoked;
    device
}

fn with_checkpoint(mut body: DeviceSet, ids: &[String]) -> Result<DeviceSet> {
    let checkpoint = RevokedCheckpoint {
        schema: domain::CUSTODY_REVOKED_CHECKPOINT.into(),
        version: 1,
        account_anchor: body.account_anchor.clone(),
        master_certificate_hash: object_hash(&body.master_certificate)?,
        device_set_epoch: body.device_set_epoch,
        previous_checkpoint_hash: None,
        list_hash: framed_hash(domain::CUSTODY_REVOKED_LIST, &ids)?,
        count: u64::try_from(ids.len())?,
        compacted_before: body.issued_at - 7_776_000,
        issued_at: body.issued_at,
    };
    // The fixture's primary seed signs the checkpoint under its real wire domain.
    let signature = crate::sign_canonical_bytes_with_seed(
        &signing_bytes(domain::CUSTODY_REVOKED_CHECKPOINT, &checkpoint)?,
        [2; 32],
    );
    body.revoked_device_checkpoint = Some(Envelope { body: checkpoint, signature });
    Ok(body)
}

fn enroll_secondary(
    primary: &SelfSigningKey,
    genesis: &Envelope<DeviceSet>,
) -> Result<Envelope<DeviceSet>> {
    let now = genesis.body.issued_at;
    let current = verify_record(genesis, now, None, None)?;
    let mut branch =
        genesis.body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
    branch.device_id = "secondary".into();
    branch.cert_id = encode_base64url([27; 32]);
    primary.enroll_device(&current, primary.certify_branch(branch)?, now + 1).map_err(Into::into)
}

#[test]
fn roster_names_reject_blank_invisible_bidi_and_reserved_prefixes() -> Result {
    let (_, primary, genesis) = fixture()?;
    let now = genesis.body.issued_at;
    let mut accepted = Vec::new();
    for name in UNSAFE_NAMES.into_iter().chain(["retired-device"]) {
        let mut body = genesis.body.clone();
        body.devices.push(tombstone(&genesis, name));
        body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        // Signing and section validation succeed: only shared name validation rejects it.
        let signed = primary.sign_record(body)?;
        let result = verify_record(&signed, now, None, None);
        if name == "retired-device" {
            result?;
        } else if !matches!(
            result,
            Err(CryptoError::Protocol(ProtocolError::InvalidIdentityRecord(
                "invalid or reserved live device name"
            )))
        ) {
            accepted.push(format!("{name:?}: {result:?}"));
        }
    }
    assert!(accepted.is_empty(), "name guard did not reject: {accepted:?}");
    Ok(())
}

#[test]
fn compacted_names_reject_blank_invisible_bidi_and_reserved_prefixes() -> Result {
    let (_, primary, genesis) = fixture()?;
    let now = genesis.body.issued_at;
    let mut accepted = Vec::new();
    for name in UNSAFE_NAMES.into_iter().chain(["retired-device"]) {
        let ids = vec![name.to_owned()];
        let signed = primary.sign_record(with_checkpoint(genesis.body.clone(), &ids)?)?;
        let result = verify_record(&signed, now, Some(&ids), None);
        if name == "retired-device" {
            assert!(result?.revoked_ids().contains(name));
        } else if !matches!(
            result,
            Err(CryptoError::Protocol(ProtocolError::InvalidIdentityRecord(
                "invalid or reserved live device name"
            )))
        ) {
            accepted.push(format!("{name:?}: {result:?}"));
        }
    }
    assert!(accepted.is_empty(), "compacted name guard did not reject: {accepted:?}");
    Ok(())
}

#[test]
fn compacted_device_cannot_reactivate_in_a_signed_roster() -> Result {
    let (_, primary, genesis) = fixture()?;
    let now = genesis.body.issued_at;
    let ids = vec!["primary".to_owned()];
    let current = verify_record(&genesis, now, None, None)?;
    let revoked = primary.revoke_device(&current, "primary", now + 1)?;
    let revoked = primary.sign_record(with_checkpoint(revoked.body, &ids)?)?;
    let verified = verify_record(&revoked, now + 1, Some(&ids), None)?;
    assert!(verified.revoked_ids().contains("primary"));

    let mut resurrection = revoked.body.clone();
    resurrection.device_set_epoch += 1;
    resurrection.previous_record_hash = Some(object_hash(&revoked)?);
    resurrection.devices = genesis.body.devices;
    let resurrection = primary.sign_record(resurrection)?;
    assert_authority_error(
        &verify_record(&resurrection, now + 1, Some(&ids), None),
        "compacted device cannot reactivate",
    );
    Ok(())
}

#[test]
fn pinned_enrollment_reserve_rejects_a_new_active_device_but_allows_denials() -> Result {
    let (_, primary, genesis) = fixture()?;
    let now = genesis.body.issued_at;
    let secondary = enroll_secondary(&primary, &genesis)?;
    let mut body = genesis.body.clone();
    for i in 1..MAX_ENROLLMENT_ROSTER {
        body.devices.push(tombstone(&genesis, &format!("retired-{i:04}")));
    }
    let full = primary.sign_record(body)?;
    let mut pins = AuthorityPins::default();
    pins.observe(&verify_record(&full, now, None, None)?)?;
    let before = serde_json::to_vec(&pins)?;
    let mut next = full.body.clone();
    next.device_set_epoch += 1;
    next.previous_record_hash = Some(object_hash(&full)?);
    let mut denial = next.clone();
    denial.devices.push(tombstone(&genesis, "retired-extra"));
    let denial = primary.sign_record(denial)?;
    let mut control = pins.clone();
    assert_eq!(control.observe(&verify_record(&denial, now, None, None)?)?, PinOutcome::Advanced);

    next.devices.push(secondary.body.devices[1].clone());
    let next = primary.sign_record(next)?;
    let verified = verify_record(&next, now + 1, None, None)?;
    assert_authority_error(
        &pins.observe(&verified),
        "custody enrollment reserve exhausted; prioritize revocation",
    );
    assert_eq!(serde_json::to_vec(&pins)?, before);
    Ok(())
}

#[test]
fn pinned_device_cannot_disappear_without_revocation() -> Result {
    let (_, primary, genesis) = fixture()?;
    let enrolled = enroll_secondary(&primary, &genesis)?;
    let now = enrolled.body.issued_at;
    let current = verify_record(&enrolled, now, None, None)?;
    let mut pins = AuthorityPins::default();
    pins.observe(&current)?;
    let before = serde_json::to_vec(&pins)?;
    let revoked = primary.revoke_device(&current, "secondary", now + 1)?;
    let mut control = pins.clone();
    assert_eq!(
        control.observe(&verify_record(&revoked, now + 1, None, None)?)?,
        PinOutcome::Advanced
    );

    let mut missing = enrolled.body.clone();
    missing.device_set_epoch += 1;
    missing.previous_record_hash = Some(object_hash(&enrolled)?);
    missing.devices.retain(|device| device.device_id != "secondary");
    let missing = primary.sign_record(missing)?;
    assert_authority_error(
        &pins.observe(&verify_record(&missing, now + 1, None, None)?),
        "custody roster entry disappeared without revocation",
    );
    assert_eq!(serde_json::to_vec(&pins)?, before);
    Ok(())
}

#[test]
fn compacted_checkpoint_preserves_removed_device_denial_and_pins() -> Result {
    let (_, primary, genesis) = fixture()?;
    let enrolled = enroll_secondary(&primary, &genesis)?;
    let now = enrolled.body.issued_at;
    let current = verify_record(&enrolled, now, None, None)?;
    let reference = DeviceRef {
        account_anchor: enrolled.body.account_anchor.clone(),
        device_id: "secondary".into(),
        device_epoch: 1,
    };
    current.authorize(&reference, "register", now)?;
    let revoked = primary.revoke_device(&current, "secondary", now + 1)?;
    let mut pins = AuthorityPins::default();
    pins.observe(&current)?;
    pins.observe(&verify_record(&revoked, now + 1, None, None)?)?;

    let ids = vec!["secondary".to_owned()];
    let mut compacted = revoked.body.clone();
    compacted.device_set_epoch += 1;
    compacted.previous_record_hash = Some(object_hash(&revoked)?);
    compacted.devices.retain(|device| device.device_id != "secondary");
    let compacted = primary.sign_record(with_checkpoint(compacted, &ids)?)?;
    let compacted = verify_record(&compacted, now + 1, Some(&ids), None)?;
    assert_eq!(compacted.revoked_ids(), &std::collections::BTreeSet::from(["secondary".into()]));
    assert_authority_error(
        &compacted.authorize(&reference, "register", now + 1),
        "custody device anchor or revocation mismatch",
    );
    assert_eq!(pins.observe(&compacted)?, PinOutcome::Advanced);
    pins.require_current(&compacted)?;
    Ok(())
}
