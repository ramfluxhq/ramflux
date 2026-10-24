// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! RFC 9605 published suite-5 known answers and adversarial replay/header cases.
use super::*;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn rfc9605_appendix_c3_suite5_derivation_and_ciphertext() -> TestResult {
    // Factual vector data: https://www.rfc-editor.org/rfc/rfc9605.html#appendix-C.3
    let base = hex::decode("000102030405060708090a0b0c0d0e0f")?;
    let metadata = hex::decode("4945544620534672616d65205747")?;
    let plaintext = hex::decode("64726166742d696574662d736672616d652d656e63")?;
    let expected = hex::decode(
        "990123456794f509d36e9beacb0e261d99c7d1e972f1fed787d4049f17ca21353c1cc24d56ceabced279",
    )?;
    let mut sender = SFrameSender::new(&base, 0x123)?;
    sender.next = Some(0x4567);
    assert_eq!(
        hex::encode(sender.key.key.as_ref()),
        "d3e27b0d4a5ae9e55df01a70e6d4d28d969b246e2936f4b7a5d9b494da6b9633"
    );
    assert_eq!(hex::encode(sender.key.salt.as_ref()), "84991c167b8cd23c93708ec7");
    assert_eq!(sender.seal(&metadata, &plaintext)?, expected);
    let mut receiver = SFrameReceiver::new(&base, 0x123)?;
    assert_eq!(receiver.open(&metadata, &expected)?, plaintext);
    assert!(receiver.open(&metadata, &expected).is_err());
    Ok(())
}
#[test]
fn rfc_minimal_headers_cover_inline_extended_and_u64_boundaries() -> TestResult {
    for (kid, counter, hex) in [
        (0, 0, "00"),
        (7, 7, "77"),
        (8, 8, "880808"),
        (0x123, 0x4567, "9901234567"),
        (u64::MAX, u64::MAX, "ffffffffffffffffffffffffffffffffff"),
    ] {
        let header = SFrameHeader { kid, counter };
        let bytes = hex::decode(hex)?;
        assert_eq!(header.encode(), bytes);
        assert_eq!(SFrameHeader::decode(&bytes)?, (header, bytes.len()));
    }
    for bytes in [vec![], vec![0x80], vec![0x80, 7], vec![0x90, 0, 8], vec![0x08, 0]] {
        assert!(SFrameHeader::decode(&bytes).is_err());
    }
    Ok(())
}
#[test]
fn altered_metadata_ciphertext_and_counter_do_not_advance_replay_state() -> TestResult {
    let mut sender = SFrameSender::new(&[9; 32], 0)?;
    let frames = (0..140).map(|_| sender.seal(b"rtp", b"opus")).collect::<Result<Vec<_>, _>>()?;
    let mut receiver = SFrameReceiver::new(&[9; 32], 0)?;
    assert!(receiver.open(b"wrong-rtp", &frames[139]).is_err());
    let mut forged = frames[139].clone();
    let end = forged.len() - 1;
    forged[end] ^= 1;
    assert!(receiver.open(b"rtp", &forged).is_err());
    assert_eq!(receiver.open(b"rtp", &frames[0])?, b"opus");
    assert_eq!(receiver.open(b"rtp", &frames[139])?, b"opus");
    assert!(receiver.open(b"rtp", &frames[0]).is_err());
    assert_eq!(receiver.open(b"rtp", &frames[138])?, b"opus");
    assert!(receiver.open(b"rtp", &frames[138]).is_err());
    sender.next = Some(u64::MAX);
    sender.seal(b"rtp", b"last")?;
    assert!(sender.seal(b"rtp", b"wrapped").is_err());
    assert!(SFrameReceiver::new(&[9; 32], 1)?.open(b"rtp", &frames[1]).is_err());
    Ok(())
}
