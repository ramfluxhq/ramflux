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
