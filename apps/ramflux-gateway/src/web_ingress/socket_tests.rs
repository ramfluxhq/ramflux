// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Outbound, Outgoing, Shared, Socket, WebFrameSink, WebFrameSource, classify};
use crate::web_ingress::close::CloseCode;
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn masked(first: u8, payload: &[u8]) -> Vec<u8> {
    let mask = [9_u8, 8, 7, 6];
    let mut frame = vec![first];
    if payload.len() < 126 {
        frame.push(0x80 | u8::try_from(payload.len()).unwrap_or(0));
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(byte, key)| byte ^ key));
    frame
}

/// Read one unmasked server frame: (opcode, payload).
async fn server_frame<R: tokio::io::AsyncRead + Unpin>(io: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0_u8; 2];
    io.read_exact(&mut head).await?;
    let len = match head[1] {
        126 => {
            let mut extended = [0_u8; 2];
            io.read_exact(&mut extended).await?;
            usize::from(u16::from_be_bytes(extended))
        }
        short => usize::from(short),
    };
    let mut payload = vec![0_u8; len];
    io.read_exact(&mut payload).await?;
    Ok((head[0] & 0x0F, payload))
}

#[test]
fn session_established_gains_the_carrier_name_in_both_forms() -> TestResult {
    let plain = br#"{"frame_type":"session_established","session":{"session_id":"s"}}"#;
    let Outbound::Established(body) = classify(plain) else {
        return Err("plain form must be recognised".into());
    };
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(value["session"]["carrier"], "websocket");

    let push = br#"{"frame_type":"session_established","session":{"session":{"session_id":"s"},"capabilities":[],"inbox_incarnation_id":"i"}}"#;
    let Outbound::Established(body) = classify(push) else {
        return Err("session-push form must be recognised".into());
    };
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(value["session"]["session"]["carrier"], "websocket");
    assert!(value["session"].get("carrier").is_none());

    assert_eq!(classify(br#"{"frame_type":"nack","reason":"x"}"#), Outbound::Other);
    assert_eq!(classify(b"not json"), Outbound::Other);
    Ok(())
}

#[tokio::test]
async fn no_error_frame_leaves_the_listener_before_establishment() -> TestResult {
    let (out, mut queued) = tokio::sync::mpsc::channel(4);
    let shared = Arc::new(Shared::default());
    let notified = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&notified);
    let mut sink = WebFrameSink {
        out,
        shared: Arc::clone(&shared),
        on_established: Some(Box::new(move || flag.store(true, Ordering::Release))),
    };
    let nack = br#"{"frame_type":"nack","reason":"auth rejected: detail"}"#;
    assert!(sink.send_frame(nack).await.is_err());
    assert!(shared.refused());
    assert!(!shared.established());
    assert!(queued.try_recv().is_err());

    let established = br#"{"frame_type":"session_established","session":{"session_id":"s"}}"#;
    sink.send_frame(established).await.map_err(|error| error.to_string())?;
    assert!(shared.established());
    assert!(notified.load(Ordering::Acquire));
    assert!(matches!(queued.try_recv(), Ok(Outgoing::Binary(_))));

    // After establishment every frame passes through unchanged.
    sink.send_frame(nack).await.map_err(|error| error.to_string())?;
    let Ok(Outgoing::Binary(body)) = queued.try_recv() else {
        return Err("frame must be queued".into());
    };
    assert_eq!(body, nack);
    Ok(())
}

#[tokio::test]
async fn binary_messages_reach_the_session_source_and_frames_go_out_unmasked() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (read, write) = tokio::io::split(server);
    let (socket, frames) = Socket::start(read, write);
    let mut source = WebFrameSource { frames };

    client.write_all(&masked(0x82, br#"{"frame_type":"custody_open"}"#)).await?;
    let body = source.recv_frame().await.map_err(|error| error.to_string())?;
    assert_eq!(body, br#"{"frame_type":"custody_open"}"#);

    socket.out.send(Outgoing::Binary(b"reply".to_vec())).await.map_err(|e| e.to_string())?;
    assert_eq!(server_frame(&mut client).await?, (0x2, b"reply".to_vec()));

    socket.close(Some(CloseCode::AuthRefused)).await;
    let (opcode, payload) = server_frame(&mut client).await?;
    assert_eq!(opcode, 0x8);
    assert_eq!(payload, CloseCode::AuthRefused.payload());
    Ok(())
}

#[tokio::test]
async fn text_message_and_pre_session_oversize_close_the_connection() -> TestResult {
    for (bytes, code) in [
        (masked(0x81, b"text"), CloseCode::UnsupportedData),
        (
            {
                // Header only: 70 000 bytes announced while the pre-session cap is 65 536.
                let mut header = vec![0x82, 0x80 | 127];
                header.extend_from_slice(&70_000_u64.to_be_bytes());
                header.extend_from_slice(&[1, 2, 3, 4]);
                header
            },
            CloseCode::MessageTooBig,
        ),
        (masked(0xC2, b"x"), CloseCode::ProtocolError),
    ] {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(server);
        let (socket, mut frames) = Socket::start(read, write);
        client.write_all(&bytes).await?;
        let (opcode, payload) = server_frame(&mut client).await?;
        assert_eq!(opcode, 0x8);
        assert_eq!(payload, code.payload());
        // The session side sees the end of the stream, never the offending bytes.
        assert_eq!(frames.recv().await, None);
        socket.close(None).await;
    }
    Ok(())
}

#[tokio::test]
async fn client_ping_is_answered_and_ping_flood_is_a_policy_close() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (read, write) = tokio::io::split(server);
    let (socket, _frames) = Socket::start(read, write);
    for _ in 0..4 {
        client.write_all(&masked(0x89, b"hi")).await?;
        assert_eq!(server_frame(&mut client).await?, (0xA, b"hi".to_vec()));
    }
    client.write_all(&masked(0x89, b"hi")).await?;
    let (opcode, payload) = server_frame(&mut client).await?;
    assert_eq!((opcode, payload), (0x8, CloseCode::Policy.payload()));
    socket.close(None).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn server_pings_and_closes_when_no_pong_arrives() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (read, write) = tokio::io::split(server);
    let (socket, _frames) = Socket::start(read, write);
    // First the ping (empty payload) after the interval, then the timeout close.
    assert_eq!(server_frame(&mut client).await?, (0x9, Vec::new()));
    let (opcode, payload) = server_frame(&mut client).await?;
    assert_eq!((opcode, payload), (0x8, CloseCode::Timeout.payload()));
    socket.close(None).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn idle_connection_is_closed_with_timeout() -> TestResult {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let (read, write) = tokio::io::split(server);
    let (socket, _frames) = Socket::start(read, write);
    // Answer pings so that only the application-idle rule can end the connection.
    loop {
        let (opcode, payload) = server_frame(&mut client).await?;
        if opcode == 0x9 {
            client.write_all(&masked(0x8A, &[])).await?;
            continue;
        }
        assert_eq!((opcode, payload), (0x8, CloseCode::Timeout.payload()));
        break;
    }
    socket.close(None).await;
    Ok(())
}
