// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use ramflux_protocol::{PrincipalKind, custody::*, domain, encode_base64url};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fixture() -> Result<(serde_json::Value, SelfSigningKey, Envelope<DeviceSet>)> {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/custody_v3.json"))?;
    let phrase = RecoveryPhrase::from_entropy(&[0; 32])?;
    let master = MasterKey::from_phrase(&phrase)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let branch = crate::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let agreement = crate::X25519KeyPair::from_seed([4; 32]);
    let record = create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: PrincipalKind::Human,
            display_name: "Vector Human".into(),
            issued_at: 1_700_000_000,
            master_cert_id: encode_base64url([5; 32]),
            branch_cert_id: encode_base64url([6; 32]),
            external_human_primary: None,
        },
    )?;
    Ok((v, primary, record))
}
#[test]
fn independent_python_vector_matches_every_canonical_byte_signature_and_hash() -> Result {
    let (vector, _, record) = fixture()?;
    assert_eq!(serde_json::to_value(&record)?, vector["record"]);
    assert_eq!(
        hex::encode(ramflux_protocol::canonical_json_bytes(&record)?),
        vector["record_canonical_hex"]
    );
    assert_eq!(
        hex::encode(signing_bytes(domain::SIGNED_DEVICE_SET_V3, &record.body)?),
        vector["record_signing_bytes_hex"]
    );
    assert_eq!(object_hash(&record)?, vector["record_hash"]);
    assert_eq!(object_hash(&record.body.master_certificate)?, vector["master_certificate_hash"]);
    let cert = record.body.devices[0].branch_certificate.as_ref().ok_or("branch")?;
    assert_eq!(object_hash(cert)?, vector["branch_certificate_hash"]);
    let wire = ramflux_protocol::canonical_json_bytes(&record)?;
    let decoded = Envelope::<DeviceSet>::from_wire_bytes(&wire)?;
    let verified = verify_record(&decoded, 1_700_000_000, None, None)?;
    verified.authorize(
        &record.body.master_certificate.body.primary_device_ref,
        "register",
        1_700_000_000,
    )?;
    assert!(!verified.capacity_pressure().any());
    Ok(())
}
#[test]
fn phrase_normalization_prefixes_checksum_and_word_count_are_enforced() -> Result {
    let original = RecoveryPhrase::from_entropy(&[0; 32])?;
    let master = MasterKey::from_phrase(&original)?;
    let text = original.display_words();
    assert_eq!(text.split_whitespace().count(), 24);
    let prefixed = text.replace("abandon", "ABAN").replace(' ', "\u{2003}");
    assert_eq!(
        MasterKey::from_phrase(&RecoveryPhrase::parse(&prefixed)?)?.public_key(),
        master.public_key()
    );
    let nfkd = text.replace("abandon", "ＡＢＡＮＤＯＮ");
    assert_eq!(
        MasterKey::from_phrase(&RecoveryPhrase::parse(&nfkd)?)?.public_key(),
        master.public_key()
    );
    for input in [
        "abandon ".repeat(24),
        "abandon ".repeat(23),
        text.replace("art", "not-a-word"),
        text.replace("abandon", "ab"),
    ] {
        assert!(RecoveryPhrase::parse(&input).is_err());
    }
    assert!(original.matches_word(1, "ＡＢＡＮ")?);
    assert!(!original.matches_word(1, "ability")?);
    assert!(original.matches_word(0, "abandon").is_err());
    assert!(original.matches_word(1, "abandon art").is_err());
    assert!(!format!("{original:?} {master:?}").contains("abandon"));
    Ok(())
}
#[test]
fn mandatory_nulls_duplicate_keys_and_float_versions_never_reach_authority() -> Result {
    let (_, _, record) = fixture()?;
    let raw = serde_json::to_value(record)?;
    let mut missing = raw.clone();
    missing["body"].as_object_mut().ok_or("body")?.remove("previous_record_hash");
    assert!(Envelope::<DeviceSet>::from_wire_bytes(&serde_json::to_vec(&missing)?).is_err());
    let mut nested = raw.clone();
    nested["body"]["master_certificate"]["body"]
        .as_object_mut()
        .ok_or("cert")?
        .remove("legacy_binding_hash");
    assert!(Envelope::<DeviceSet>::from_wire_bytes(&serde_json::to_vec(&nested)?).is_err());
    let mut fractional = raw.clone();
    fractional["body"]["version"] = serde_json::json!(3.0);
    assert!(Envelope::<DeviceSet>::from_wire_bytes(&serde_json::to_vec(&fractional)?).is_err());
    let canonical = ramflux_protocol::canonical_json_string(&raw)?;
    let duplicate = canonical.replacen("\"version\":3", "\"version\":3,\"version\":3", 1);
    assert!(Envelope::<DeviceSet>::from_wire_bytes(duplicate.as_bytes()).is_err());
    Ok(())
}
#[test]
fn tampering_wrong_signers_reused_keys_and_unsupported_modes_fail_closed() -> Result {
    let (vector, primary, record) = fixture()?;
    let mut wrong = record.clone();
    wrong.signature = encode_base64url([0; 64]);
    assert!(verify_record(&wrong, 1_700_000_000, None, None).is_err());
    let master_seed: [u8; 32] = hex::decode(vector["master_seed_hex"].as_str().ok_or("seed")?)?
        .try_into()
        .map_err(|_| "seed length")?;
    wrong.signature = crate::sign_canonical_bytes_with_seed(
        &signing_bytes(domain::SIGNED_DEVICE_SET_V3, &wrong.body)?,
        master_seed,
    );
    assert!(verify_record(&wrong, 1_700_000_000, None, None).is_err());
    let mut body = record.body.clone();
    body.profile.display_name = "tampered".into();
    assert!(
        verify_record(
            &Envelope { body, signature: record.signature.clone() },
            1_700_000_000,
            None,
            None
        )
        .is_err()
    );
    for version in [1, 2, 4] {
        let mut body = record.body.clone();
        body.version = version;
        assert!(primary.sign_record(body).is_err());
    }
    let mut body = record.body.clone();
    body.origin = "migrated".into();
    assert!(primary.sign_record(body).is_err());
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let reused = SelfSigningKey::from_vault_seed(&Zeroizing::new(master_seed));
    let mut cert = record.body.master_certificate.body.clone();
    cert.self_signing_public_key = reused.public_key();
    assert!(master.certify(cert).is_err());
    Ok(())
}
#[test]
fn record_readability_does_not_extend_branch_leases_or_poison_time_with_endpoints() -> Result {
    let (_, _, record) = fixture()?;
    let reference = &record.body.master_certificate.body.primary_device_ref;
    let verified = verify_record(&record, 1_702_592_301, None, None)?;
    assert!(verified.authorize(reference, "register", 1_702_592_301).is_err());
    assert!(verify_record(&record, 1_699_999_699, None, None).is_err());
    verify_record(&record, 1_699_999_700, None, None)?.authorize(
        reference,
        "message",
        1_699_999_700,
    )?;
    Ok(())
}
#[test]
fn authenticated_capacity_pressure_warns_at_eighty_percent_of_roster() -> Result {
    let (_, primary, record) = fixture()?;
    let mut body = record.body;
    body.device_set_epoch = encode_epoch(1, 2)?;
    let prototype = body.devices[0].clone();
    for n in 0..818 {
        let mut device = prototype.clone();
        device.device_id = format!("revoked-{n:04}");
        device.status = ramflux_protocol::DeviceSetStatus::Revoked;
        device.revoked_at = Some(1_700_000_000);
        device.branch_certificate = None;
        device.migration_state = MigrationState::Revoked;
        body.devices.push(device);
    }
    let below = primary.sign_record(body.clone())?;
    assert!(!verify_record(&below, 1_700_000_000, None, None)?.capacity_pressure().roster);
    let mut last = body.devices.last().ok_or("device")?.clone();
    last.device_id = "revoked-0818".into();
    body.devices.push(last);
    let at = primary.sign_record(body)?;
    assert!(verify_record(&at, 1_700_000_000, None, None)?.capacity_pressure().roster);
    Ok(())
}

#[test]
fn durable_mode_head_conflict_and_revocation_pins_survive_reload() -> Result {
    let (_, primary, record) = fixture()?;
    let now = record.body.issued_at;
    let verified = verify_record(&record, now, None, None)?;
    let mut pins = AuthorityPins::default();
    assert!(pins.permits_legacy(&record.body.account_anchor));
    assert_eq!(pins.observe(&verified)?, PinOutcome::Advanced);
    assert!(!pins.permits_legacy(&record.body.account_anchor));
    pins.require_current(&verified)?;
    assert_eq!(pins.observe(&verified)?, PinOutcome::Unchanged);
    let revoked = primary.revoke_device(&verified, "primary", now + 1)?;
    assert_eq!(revoked.body.devices.len(), record.body.devices.len());
    assert!(
        ramflux_protocol::canonical_json_bytes(&revoked)?.len()
            < ramflux_protocol::canonical_json_bytes(&record)?.len()
    );
    let revoked = verify_record(&revoked, now + 1, None, None)?;
    pins.observe(&revoked)?;
    let encoded = serde_json::to_vec(&pins)?;
    let mut pins: AuthorityPins = serde_json::from_slice(&encoded)?;
    assert!(!pins.permits_legacy(&record.body.account_anchor));
    assert!(pins.require_current(&verified).is_err());
    assert!(pins.observe(&verified).is_err());
    let mut resurrection = record.body.clone();
    resurrection.device_set_epoch += 2;
    let resurrection = primary.sign_record(resurrection)?;
    assert!(pins.observe(&verify_record(&resurrection, now + 1, None, None)?).is_err());
    let mut conflict = revoked.envelope().body.clone();
    conflict.profile.display_name = "Another name".into();
    let conflict = primary.sign_record(conflict)?;
    let conflict = verify_record(&conflict, now + 1, None, None)?;
    assert_eq!(pins.observe(&conflict)?, PinOutcome::Fenced);
    let pins: AuthorityPins = serde_json::from_slice(&serde_json::to_vec(&pins)?)?;
    assert!(pins.require_current(&revoked).is_err());
    assert!(!pins.permits_legacy(&record.body.account_anchor));
    Ok(())
}

#[test]
fn full_roster_and_reserved_enrollment_space_do_not_block_in_place_revocation() -> Result {
    let (_, primary, mut record) = fixture()?;
    let mut tombstone = record.body.devices[0].clone();
    tombstone.status = ramflux_protocol::DeviceSetStatus::Revoked;
    tombstone.revoked_at = Some(record.body.issued_at);
    tombstone.branch_certificate = None;
    tombstone.migration_state = MigrationState::Revoked;
    for i in 1..MAX_ROSTER {
        tombstone.device_id = format!("revoked-{i:04}");
        record.body.devices.push(tombstone.clone());
    }
    record.body.devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let record = primary.sign_record(record.body)?;
    let now = record.body.issued_at;
    let verified = verify_record(&record, now, None, None)?;
    let mut branch = record.body.devices[0].branch_certificate.clone().ok_or("branch")?;
    branch.body.device_id = "new-device".into();
    let branch = primary.certify_branch(branch.body)?;
    assert!(primary.enroll_device(&verified, branch, now + 1).is_err());
    let revoked = primary.revoke_device(&verified, "primary", now + 1)?;
    assert_eq!(revoked.body.devices.len(), MAX_ROSTER);
    verify_record(&revoked, now + 1, None, None)?;
    Ok(())
}
