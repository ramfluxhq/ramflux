// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An aborted fixture relay step closes the held socket before its response is released.

use super::post;
use std::time::{Duration, Instant};
use tokio::{io::AsyncReadExt, sync::oneshot};

#[tokio::test]
async fn local_relay_cancellation_closes_a_held_request_without_a_blocking_worker()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_secs(30), case()).await?
}
async fn case() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let (entered, waiting) = oneshot::channel();
    let (release, released) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 1024];
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Err("request ended before its body".into());
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(boundary) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..boundary])?;
                let length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .ok_or("missing content length")?
                    .1
                    .trim()
                    .parse::<usize>()?;
                if request.len() >= boundary + 4 + length {
                    break;
                }
            }
        }
        let _ = entered.send(());
        let mut byte = [0_u8; 1];
        tokio::select! {
            count = stream.read(&mut byte) => assert_eq!(count?, 0, "cancel must close the transport"),
            _ = released => return Err("response released before cancellation closed the request".into()),
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let client = tokio::spawn(async move {
        post::<_, serde_json::Value>(
            &endpoint,
            "/relay/v1/object/put_chunk",
            &serde_json::json!({"held": true}),
            Duration::from_secs(600),
        )
        .await
    });
    waiting.await?;
    let started = Instant::now();
    client.abort();
    assert!(client.await.is_err());
    server.await??;
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(release);
    Ok(())
}
