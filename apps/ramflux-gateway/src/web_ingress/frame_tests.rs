// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Incoming, MAX_FRAGMENTS_PER_MESSAGE, MessageReader, ReadEnd, encode, write_binary};
use crate::web_ingress::close::CloseCode;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A masked client frame with explicit header bits.
fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [0x11_u8, 0x22, 0x33, 0x44];
    let mut frame = vec![first];
    if payload.len() < 126 {
        frame.push(0x80 | u8::try_from(payload.len()).unwrap_or(0));
    } else if let Ok(len) = u16::try_from(payload.len()) {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&len.to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(byte, key)| byte ^ key));
    frame
}

async fn read_all(bytes: Vec<u8>, cap: usize) -> Result<Incoming, ReadEnd> {
    let mut reader = MessageReader::new(std::io::Cursor::new(bytes));
    reader.next(&move || cap).await
}

fn violation(result: Result<Incoming, ReadEnd>) -> Option<CloseCode> {
    match result {
        Err(ReadEnd::Violation(code)) => Some(code),
        _ => None,
    }
}

#[tokio::test]
async fn one_binary_message_is_one_frame_body() -> TestResult {
    let body = br#"{"frame_type":"heartbeat"}"#;
    let incoming = read_all(client_frame(0x82, body), 1024).await.map_err(|e| format!("{e:?}"))?;
    assert_eq!(incoming, Incoming::Binary(body.to_vec()));
    Ok(())
}

#[tokio::test]
async fn fragmented_binary_message_is_reassembled() -> TestResult {
    let mut bytes = client_frame(0x02, b"ab");
    bytes.extend(client_frame(0x00, b"cd"));
    bytes.extend(client_frame(0x80, b"ef"));
    let incoming = read_all(bytes, 1024).await.map_err(|e| format!("{e:?}"))?;
    assert_eq!(incoming, Incoming::Binary(b"abcdef".to_vec()));
    Ok(())
}

#[tokio::test]
async fn text_message_closes_with_unsupported_data() {
    assert_eq!(
        violation(read_all(client_frame(0x81, b"hello"), 1024).await),
        Some(CloseCode::UnsupportedData)
    );
}

#[tokio::test]
async fn any_rsv_bit_is_a_protocol_error_so_compression_cannot_be_used() {
    for rsv in [0x40_u8, 0x20, 0x10] {
        assert_eq!(
            violation(read_all(client_frame(0x82 | rsv, b"x"), 1024).await),
            Some(CloseCode::ProtocolError)
        );
    }
}

#[tokio::test]
async fn unmasked_client_frame_is_a_protocol_error() {
    // 0x82 0x01 'x': a binary frame without the mask bit.
    assert_eq!(
        violation(read_all(vec![0x82, 0x01, b'x'], 1024).await),
        Some(CloseCode::ProtocolError)
    );
}

#[tokio::test]
async fn unknown_opcode_and_oversized_control_frame_are_protocol_errors() {
    assert_eq!(
        violation(read_all(client_frame(0x83, b"x"), 1024).await),
        Some(CloseCode::ProtocolError)
    );
    assert_eq!(
        violation(read_all(client_frame(0x89, &[0_u8; 126]), 1024).await),
        Some(CloseCode::ProtocolError)
    );
    // A fragmented control frame (FIN clear) is refused as well.
    assert_eq!(
        violation(read_all(client_frame(0x09, b"x"), 1024).await),
        Some(CloseCode::ProtocolError)
    );
}

#[tokio::test]
async fn oversize_is_rejected_from_the_header_before_the_payload_is_read() {
    // Only the header and mask are supplied: a reader that buffered first would hit
    // end-of-stream (`Transport`) instead of the size violation.
    let mut header = vec![0x82, 0x80 | 127];
    header.extend_from_slice(&(2_000_000_u64).to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(violation(read_all(header, 1_048_576).await), Some(CloseCode::MessageTooBig));
}

#[tokio::test]
async fn oversize_is_rejected_on_the_running_fragment_total() {
    let mut bytes = client_frame(0x02, &[0_u8; 600]);
    // The second fragment's header alone crosses the cap; its payload is absent.
    bytes.extend_from_slice(&[0x80, 0x80 | 126]);
    bytes.extend_from_slice(&600_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(violation(read_all(bytes, 1000).await), Some(CloseCode::MessageTooBig));
}

#[tokio::test]
async fn continuation_without_a_message_and_interleaved_data_are_protocol_errors() {
    assert_eq!(
        violation(read_all(client_frame(0x80, b"x"), 1024).await),
        Some(CloseCode::ProtocolError)
    );
    let mut bytes = client_frame(0x02, b"a");
    bytes.extend(client_frame(0x82, b"b"));
    assert_eq!(violation(read_all(bytes, 1024).await), Some(CloseCode::ProtocolError));
}

#[tokio::test]
async fn too_many_fragments_is_a_policy_violation() {
    let mut bytes = client_frame(0x02, b"a");
    for _ in 0..MAX_FRAGMENTS_PER_MESSAGE {
        bytes.extend(client_frame(0x00, b"a"));
    }
    assert_eq!(violation(read_all(bytes, 1_048_576).await), Some(CloseCode::Policy));
}

#[tokio::test]
async fn non_minimal_length_encoding_is_a_protocol_error() {
    let mut bytes = vec![0x82, 0x80 | 126];
    bytes.extend_from_slice(&5_u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(b"hello");
    assert_eq!(violation(read_all(bytes, 1024).await), Some(CloseCode::ProtocolError));
}

#[tokio::test(start_paused = true)]
async fn partial_message_must_complete_within_the_fragment_deadline() -> TestResult {
    let (mut client, server) = tokio::io::duplex(4096);
    tokio::io::AsyncWriteExt::write_all(&mut client, &client_frame(0x02, b"a")).await?;
    let mut reader = MessageReader::new(server);
    let result = reader.next(&|| 1024).await;
    assert_eq!(violation(result), Some(CloseCode::Timeout));
    drop(client);
    Ok(())
}

#[tokio::test]
async fn control_frames_between_fragments_are_delivered_and_the_message_survives() -> TestResult {
    let mut bytes = client_frame(0x02, b"a");
    bytes.extend(client_frame(0x89, b"p"));
    bytes.extend(client_frame(0x80, b"b"));
    let mut reader = MessageReader::new(std::io::Cursor::new(bytes));
    let first = reader.next(&|| 1024).await.map_err(|e| format!("{e:?}"))?;
    assert_eq!(first, Incoming::Ping(b"p".to_vec()));
    let second = reader.next(&|| 1024).await.map_err(|e| format!("{e:?}"))?;
    assert_eq!(second, Incoming::Binary(b"ab".to_vec()));
    Ok(())
}

#[tokio::test]
async fn server_frames_are_unmasked_unfragmented_and_carry_no_rsv_bits() -> TestResult {
    let mut wire = Vec::new();
    write_binary(&mut wire, b"abc").await?;
    assert_eq!(wire, vec![0x82, 0x03, b'a', b'b', b'c']);
    let medium = encode(0x2, &[0_u8; 300]);
    assert_eq!(medium.get(..4), Some(&[0x82, 126, 0x01, 0x2C][..]));
    let large = encode(0x2, &vec![0_u8; 70_000]);
    assert_eq!(large.get(..2), Some(&[0x82, 127][..]));
    assert_eq!(large.len(), 70_000 + 10);
    Ok(())
}
