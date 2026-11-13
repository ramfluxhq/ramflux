// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(unix)]

//! The CLI surfaces a terminal attachment receipt and uses the usual failure exit status.
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn attachment_fetch_prints_deleted_receipt_and_exits_one()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!("rf-fetch-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let socket = root.join("bus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(async move {
        // handle_object opens its connection once; only one body request is necessary.
        let (mut stream, _) = listener.accept().await?;
        let len = stream.read_u32().await?;
        let mut bytes = vec![0; usize::try_from(len)?];
        stream.read_exact(&mut bytes).await?;
        let mut frame: ramflux_sdk::LocalBusFrame = serde_json::from_slice(&bytes)?;
        assert_eq!(frame.method, "object.fetch");
        assert_eq!(frame.body, json!({"object_id":"object","operation_id":"fetch-op"}));
        frame.kind = ramflux_sdk::LocalBusFrameKind::Response;
        frame.ok = Some(true);
        frame.body = json!({"object_id":"object","operation_id":"fetch-op",
            "transfer_state":"failed","last_error":"attachment deleted","retryable":false});
        let bytes = serde_json::to_vec(&frame)?;
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_rf"))
            .arg("--socket")
            .arg(&socket)
            .args([
                "object",
                "fetch",
                "--account",
                "account",
                "--object",
                "object",
                "--operation-id",
                "fetch-op",
            ])
            .output()
    })
    .await??;
    tokio::time::timeout(std::time::Duration::from_secs(10), server).await???;
    assert_eq!(output.status.code(), Some(1));
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["last_error"], "attachment deleted");
    assert_eq!(receipt["retryable"], false);
    assert!(String::from_utf8(output.stderr)?.contains("attachment deleted"));
    Ok(())
}
