// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn keys(epoch: u8) -> FullDataKeys {
    let mut context = 30_u32.to_be_bytes().to_vec();
    context.extend_from_slice(b"ramflux.pairing.full.packet.v1");
    for bytes in [[9; 32], [2; 32], [3; 32], [epoch; 32]] {
        context.extend_from_slice(&bytes);
    }
    FullDataKeys {
        initiator: Zeroizing::new([6; 32]),
        responder: Zeroizing::new([7; 32]),
        packet_context: Zeroizing::new(context),
    }
}
fn pair() -> (FullDataCipher, FullDataCipher) {
    (
        FullDataCipher::new(PairingRole::Initiator, keys(4)),
        FullDataCipher::new(PairingRole::Responder, keys(4)),
    )
}
#[test]
fn full_channel_caches_only_two_exact_retries_and_reacks_duplicates_once() -> TestResult {
    let (mut a, mut b) = pair();
    let (first, bytes) = a.seal(b"first")?;
    assert_eq!(a.retry(first)?, bytes);
    let FullOpened::New(opened) = b.open(first, &bytes)? else {
        return Err("first packet was duplicate".into());
    };
    assert_eq!(opened.as_slice(), b"first");
    assert!(matches!(b.open(first, &bytes)?, FullOpened::Duplicate));
    let (second, bytes2) = a.seal(b"second")?;
    assert!(matches!(a.seal(b"third"), Err(CryptoError::Pairing("Busy"))));
    assert!(matches!(b.open(second, &bytes2)?, FullOpened::New(_)));
    assert!(matches!(b.open(first, &bytes)?, FullOpened::Duplicate));
    a.acknowledge_packet(first)?;
    let (third, bytes3) = a.seal(b"third")?;
    assert!(a.retry(first).is_err());
    assert!(matches!(b.open(third, &bytes3)?, FullOpened::New(_)));
    assert!(matches!(b.open(first, &bytes), Err(CryptoError::Pairing("Replay"))));
    Ok(())
}
#[test]
fn full_channel_rejects_counter_epoch_reflection_and_altered_duplicate() -> TestResult {
    let (mut a, mut b) = pair();
    let (counter, bytes) = a.seal(b"secret packet")?;
    assert!(matches!(b.open(counter, &bytes)?, FullOpened::New(_)));
    let mut altered = bytes.clone();
    altered[0] ^= 1;
    assert!(b.open(counter, &altered).is_err());
    let (_, mut skipped) = pair();
    assert!(skipped.open(counter + 1, &bytes).is_err());
    let (mut reflected, _) = pair();
    assert!(reflected.open(counter, &bytes).is_err());
    let mut resumed = FullDataCipher::new(PairingRole::Responder, keys(5));
    assert!(resumed.open(counter, &bytes).is_err());
    Ok(())
}
#[test]
fn full_channel_key_limit_and_maximum_packet_are_checked_before_effect() -> TestResult {
    let (mut a, mut b) = pair();
    a.sent = PACKETS_PER_KEY - 1;
    b.received = PACKETS_PER_KEY - 1;
    assert_eq!(a.remaining_send_packets(), 1);
    let (counter, bytes) = a.seal(&vec![3; FULL_PACKET_PLAINTEXT_BYTES])?;
    assert!(matches!(b.open(counter, &bytes)?, FullOpened::New(_)));
    assert_eq!(a.remaining_send_packets(), 0);
    assert!(matches!(a.seal(b"rekey"), Err(CryptoError::Pairing("ResumeRequired"))));
    let (mut a, _) = pair();
    assert!(a.seal(&vec![3; FULL_PACKET_PLAINTEXT_BYTES + 1]).is_err());
    Ok(())
}

fn manifest() -> ramflux_protocol::custody::pairing::full_transfer::DataPacket {
    use ramflux_protocol::custody::pairing::full_transfer::{DataPacket, SecretBase64};
    DataPacket::Manifest {
        manifest_hash: ramflux_protocol::encode_base64url([3; 32]),
        offset: ramflux_protocol::custody::pairing::full_transfer::U64(0),
        total: ramflux_protocol::custody::pairing::full_transfer::U64(1),
        bytes: SecretBase64::from_bytes(b"m"),
    }
}
#[test]
fn full_ready_consumes_responder_zero_and_first_source_manifest_stays_zero() -> TestResult {
    use ramflux_protocol::custody::pairing::{PairingWire, full_transfer::DataPacket};
    let hash = ramflux_protocol::encode_base64url([3; 32]);
    let mut a = FullConfirmedChannel::new(PairingRole::Initiator, keys(4), hash.clone())?;
    let mut b = FullConfirmedChannel::new(PairingRole::Responder, keys(4), hash.clone())?;
    assert!(matches!(a.seal_packet(&manifest()), Err(CryptoError::Pairing("PublicationPending"))));
    let (counter, ready) = b.seal_ready()?;
    assert_eq!(counter, 0);
    assert_eq!(b.retry(0)?, ready);
    // Independent plaintext expectation: required null is present and credit is exactly zero.
    let (mut observer, _) = pair();
    let FullOpened::New(plaintext) = observer.open(0, &ready)? else {
        return Err("Ready unexpectedly duplicate".into());
    };
    assert_eq!(plaintext.as_slice(), format!(
        "{{\"credit\":0,\"durable_through\":null,\"kind\":\"receipt\",\"manifest_hash\":\"{hash}\"}}"
    ).as_bytes());
    DataPacket::from_wire_bytes(&plaintext)?;
    a.open_ready(counter, &ready)?;
    assert!(b.seal_ready().is_err());
    let receipt = DataPacket::Receipt { manifest_hash: hash, durable_through: None, credit: 1 };
    assert!(matches!(a.seal_packet(&receipt), Err(CryptoError::Pairing("ManifestMismatch"))));
    let (counter, data) = a.seal_packet(&manifest())?;
    assert_eq!(counter, 0);
    assert!(matches!(b.open_packet(counter, &data)?, Some(DataPacket::Manifest { .. })));
    assert!(b.open_packet(counter, &data)?.is_none());
    let (counter, receipt) = b.seal_packet(&receipt)?;
    assert_eq!(counter, 1);
    assert!(matches!(
        a.open_packet(counter, &receipt)?,
        Some(DataPacket::Receipt { credit: 1, .. })
    ));
    Ok(())
}
#[test]
fn full_ready_wrong_base_manifest_hash_refused_after_valid_aead() -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::DataPacket;
    let mut a = FullConfirmedChannel::new(
        PairingRole::Initiator,
        keys(4),
        ramflux_protocol::encode_base64url([3; 32]),
    )?;
    // Same direction key/context: this is an authenticated wrong hash, not an AEAD failure.
    let (_, mut malicious_b) = pair();
    let wrong = DataPacket::Receipt {
        manifest_hash: ramflux_protocol::encode_base64url([99; 32]),
        durable_through: None,
        credit: 0,
    };
    let (counter, bytes) = malicious_b.seal(&wrong.encode_secret()?)?;
    assert!(matches!(a.open_ready(counter, &bytes), Err(CryptoError::Pairing("ManifestMismatch"))));
    assert!(matches!(a.seal_packet(&manifest()), Err(CryptoError::Pairing("Retired"))));
    Ok(())
}
#[test]
fn full_ready_requires_closed_zero_credit_null_receipt_at_counter_zero() -> TestResult {
    use ramflux_protocol::custody::pairing::full_transfer::DataPacket;
    for (durable_through, credit) in
        [(None, 1), (Some(ramflux_protocol::custody::pairing::full_transfer::U64(0)), 0)]
    {
        let hash = ramflux_protocol::encode_base64url([3; 32]);
        let mut a = FullConfirmedChannel::new(PairingRole::Initiator, keys(4), hash.clone())?;
        let (_, mut b) = pair();
        let packet = DataPacket::Receipt { manifest_hash: hash, durable_through, credit };
        let (counter, bytes) = b.seal(&packet.encode_secret()?)?;
        assert!(matches!(a.open_ready(counter, &bytes), Err(CryptoError::Pairing("WrongContext"))));
    }
    Ok(())
}
