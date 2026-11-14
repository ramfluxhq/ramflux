// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use crate::X25519KeyPair;
use ramflux_protocol::{custody::DeviceRef, encode_base64url};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn full_auth_hpke_export_matches_independent_rfc9180_hmac_vector() -> TestResult {
    fn hex(bytes: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..bytes.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&bytes[index..index + 2], 16))
            .collect()
    }
    let kem: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/hpke_rfc9180_auth_x25519_sha256_aes256gcm.json"
    ))?;
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/pairing_full_export_v1.json"
    ))?;
    let case = &kem["cases"][0];
    let secret = super::super::KemSk::from_bytes(&hex(case["skRm"].as_str().ok_or("skRm")?)?)?;
    let public = super::super::KemPk::from_bytes(&hex(case["pkSm"].as_str().ok_or("pkSm")?)?)?;
    let enc = KemEnc::from_bytes(&hex(case["enc"].as_str().ok_or("enc")?)?)?;
    let binding = binding();
    let context = setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
        &auth_receiver_mode(public),
        &secret,
        &enc,
        &info(&[9; 32], &binding)?,
    )?;
    let keys = export_keys(
        |label, output| {
            context.export(label, output).map_err(|_| CryptoError::Pairing("hpke_export"))
        },
        &[9; 32],
        &binding,
    )?;
    assert_eq!(
        keys.initiator.as_slice(),
        hex(expected["initiator_key_hex"].as_str().ok_or("initiator key")?)?
    );
    assert_eq!(
        keys.responder.as_slice(),
        hex(expected["responder_key_hex"].as_str().ok_or("responder key")?)?
    );
    Ok(())
}
fn binding() -> DataBinding {
    let anchor = encode_base64url([1; 32]);
    DataBinding {
        profile: "primary_transfer_full_v1".into(),
        transfer_id: encode_base64url([2; 32]),
        manifest_hash: encode_base64url([3; 32]),
        epoch: encode_base64url([4; 32]),
        base_record_hash: encode_base64url([5; 32]),
        source_ref: DeviceRef {
            account_anchor: anchor.clone(),
            device_id: "source".into(),
            device_epoch: 1,
        },
        destination_ref: DeviceRef {
            account_anchor: anchor,
            device_id: "destination".into(),
            device_epoch: 1,
        },
    }
}
#[test]
fn full_auth_hpke_exports_direction_keys_and_exact_packet_context() -> TestResult {
    let binding = binding();
    let sender = X25519KeyPair::from_seed([21; 32]);
    let receiver = X25519KeyPair::from_seed([22; 32]);
    let setup = setup_full_sender(
        HpkeSecrets::from_seed(&mut [21; 32]),
        &receiver.public,
        &[9; 32],
        &binding,
    )?;
    let exported = open_full_receiver(
        HpkeSecrets::from_seed(&mut [22; 32]),
        &sender.public,
        &setup.enc,
        &setup.confirmation,
        &[9; 32],
        &binding,
    )?;
    assert_eq!(setup.keys.initiator.as_slice(), exported.initiator.as_slice());
    assert_eq!(setup.keys.responder.as_slice(), exported.responder.as_slice());
    assert_ne!(exported.initiator.as_slice(), exported.responder.as_slice());
    let mut expected = 30_u32.to_be_bytes().to_vec();
    expected.extend_from_slice(b"ramflux.pairing.full.packet.v1");
    for bytes in [[9; 32], [2; 32], [3; 32], [4; 32]] {
        expected.extend_from_slice(&bytes);
    }
    assert_eq!(exported.packet_context.as_slice(), expected);
    let another = setup_full_sender(
        HpkeSecrets::from_seed(&mut [21; 32]),
        &receiver.public,
        &[9; 32],
        &binding,
    )?;
    assert_ne!(setup.enc, another.enc);
    assert_ne!(setup.keys.initiator.as_slice(), another.keys.initiator.as_slice());
    Ok(())
}
#[test]
fn full_auth_hpke_rejects_changed_transcript_epoch_base_branch_and_confirmation() -> TestResult {
    let binding = binding();
    let sender = X25519KeyPair::from_seed([21; 32]);
    let receiver = X25519KeyPair::from_seed([22; 32]);
    let setup = setup_full_sender(
        HpkeSecrets::from_seed(&mut [21; 32]),
        &receiver.public,
        &[9; 32],
        &binding,
    )?;
    for which in 0..5 {
        let mut changed = binding.clone();
        match which {
            0 => changed.epoch = encode_base64url([77; 32]),
            1 => changed.base_record_hash = encode_base64url([77; 32]),
            2 => changed.destination_ref.device_id = "foreign".into(),
            3 => changed.manifest_hash = encode_base64url([77; 32]),
            _ => changed.transfer_id = encode_base64url([77; 32]),
        }
        assert!(
            open_full_receiver(
                HpkeSecrets::from_seed(&mut [22; 32]),
                &sender.public,
                &setup.enc,
                &setup.confirmation,
                &[9; 32],
                &changed
            )
            .is_err()
        );
    }
    assert!(
        open_full_receiver(
            HpkeSecrets::from_seed(&mut [22; 32]),
            &sender.public,
            &setup.enc,
            &setup.confirmation,
            &[8; 32],
            &binding
        )
        .is_err()
    );
    let mut tampered = setup.confirmation;
    tampered[0] ^= 1;
    assert!(
        open_full_receiver(
            HpkeSecrets::from_seed(&mut [22; 32]),
            &sender.public,
            &setup.enc,
            &tampered,
            &[9; 32],
            &binding
        )
        .is_err()
    );
    Ok(())
}
