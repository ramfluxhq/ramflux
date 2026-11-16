// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

//! Thumbnail metadata stays off the raw image, and revoke surfaces a typed refusal.
use base64::Engine as _;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(10), future).await.expect("deadline")
}

fn thumbnail_body(encoded: &str) -> Value {
    json!({
        "message": {
            "media": [{
                "objectId": "object-1",
                "inlineThumbnail": {
                    "mimeType": "image/jpeg",
                    "width": 8,
                    "height": 4,
                    "encodedImage": encoded
                }
            }]
        }
    })
}

fn serve(
    socket: &std::path::Path,
    respond: impl FnOnce(&ramflux_sdk::LocalBusFrame) -> ramflux_sdk::LocalBusFrame + Send + 'static,
) -> tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
    let listener = tokio::net::UnixListener::bind(socket).expect("bind");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let len = stream.read_u32().await?;
        let mut bytes = vec![0; usize::try_from(len)?];
        stream.read_exact(&mut bytes).await?;
        let request: ramflux_sdk::LocalBusFrame = serde_json::from_slice(&bytes)?;
        let response = respond(&request);
        let bytes = serde_json::to_vec(&response)?;
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        Ok(())
    })
}

fn response(request: &ramflux_sdk::LocalBusFrame, body: Value) -> ramflux_sdk::LocalBusFrame {
    let mut frame = request.clone();
    frame.kind = ramflux_sdk::LocalBusFrameKind::Response;
    frame.ok = Some(true);
    frame.body = body;
    frame
}

fn run(socket: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rf"))
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("rf")
}

#[tokio::test]
async fn thumbnail_prints_metadata_without_image_bytes() {
    within(async {
        let root = ramflux_test_support::TestPath::new().expect("root").child("thumb");
        std::fs::create_dir_all(&root).expect("dir");
        let socket = root.join("bus.sock");
        let image = b"thumb-bytes";
        let encoded = base64::engine::general_purpose::STANDARD.encode(image);
        let encoded_probe = encoded.clone();
        let server = serve(&socket, move |request| {
            assert_eq!(request.method, "message.read");
            assert_eq!(request.body["conversation_id"], "conversation");
            assert_eq!(request.body["message_id"], "message");
            response(request, thumbnail_body(&encoded_probe))
        });
        let output = tokio::task::spawn_blocking({
            let socket = socket.clone();
            move || {
                run(
                    &socket,
                    &[
                        "object",
                        "thumbnail",
                        "--account",
                        "account",
                        "--conversation",
                        "conversation",
                        "--message",
                        "message",
                    ],
                )
            }
        })
        .await
        .expect("join");
        server.await.expect("server").expect("exchange");
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(!stdout.contains("encodedImage"), "{stdout}");
        assert!(!stdout.contains(&encoded), "{stdout}");
        assert!(!stdout.contains("thumb-bytes"), "{stdout}");
        let receipt: Value = serde_json::from_str(&stdout).expect("json");
        assert_eq!(receipt["thumbnails"][0]["object_id"], "object-1");
        assert_eq!(receipt["thumbnails"][0]["mime"], "image/jpeg");
        assert_eq!(receipt["thumbnails"][0]["size"], image.len());
        assert_eq!(receipt["thumbnails"][0]["width"], 8);
        assert_eq!(receipt["thumbnails"][0]["height"], 4);
    })
    .await;
}

#[tokio::test]
async fn thumbnail_out_writes_one_private_file_and_refuses_other_counts() {
    within(async {
        let root = ramflux_test_support::TestPath::new().expect("root").child("thumb-out");
        std::fs::create_dir_all(&root).expect("dir");
        let image = b"thumb-bytes";
        let encoded = base64::engine::general_purpose::STANDARD.encode(image);
        let socket = root.join("one.sock");
        let out = root.join("thumb.bin");
        let encoded_probe = encoded.clone();
        let server =
            serve(&socket, move |request| response(request, thumbnail_body(&encoded_probe)));
        let output = tokio::task::spawn_blocking({
            let socket = socket.clone();
            let out = out.clone();
            move || {
                run(
                    &socket,
                    &[
                        "object",
                        "thumbnail",
                        "--account",
                        "account",
                        "--conversation",
                        "conversation",
                        "--message",
                        "message",
                        "--out",
                        out.to_str().expect("path"),
                    ],
                )
            }
        })
        .await
        .expect("join");
        server.await.expect("server").expect("exchange");
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(std::fs::read(&out).expect("out"), image);
        let mode = std::fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let empty_socket = root.join("empty.sock");
        let empty_out = root.join("empty.bin");
        let server = serve(&empty_socket, |request| response(request, json!({"message":{}})));
        let output = tokio::task::spawn_blocking({
            let socket = empty_socket.clone();
            let out = empty_out.clone();
            move || {
                run(
                    &socket,
                    &[
                        "object",
                        "thumbnail",
                        "--account",
                        "account",
                        "--conversation",
                        "conversation",
                        "--message",
                        "message",
                        "--out",
                        out.to_str().expect("path"),
                    ],
                )
            }
        })
        .await
        .expect("join");
        server.await.expect("server").expect("exchange");
        assert_eq!(output.status.code(), Some(1));
        assert!(!empty_out.exists());
        let stderr = String::from_utf8(output.stderr).expect("utf8");
        assert!(stderr.contains("exactly one"), "{stderr}");
    })
    .await;
}

#[tokio::test]
async fn revoke_sends_object_revoke_and_attachment_deleted_exits_one() {
    within(async {
        let root = ramflux_test_support::TestPath::new().expect("root").child("revoke");
        std::fs::create_dir_all(&root).expect("dir");
        let socket = root.join("bus.sock");
        let server = serve(&socket, |request| {
            assert_eq!(request.method, "object.revoke");
            assert_eq!(request.body["object_id"], "object");
            assert_eq!(request.body["conversation_id"], "conversation");
            assert_eq!(request.body["recipient_principal_id"], "recipient");
            assert_eq!(request.body["link_id"], "link");
            assert_eq!(request.body["effective_at"], 5);
            assert_eq!(request.body["recipient_device_id"], "device");
            assert_eq!(request.body["target_delivery_id"], "target");
            let mut frame = request.clone();
            frame.kind = ramflux_sdk::LocalBusFrameKind::Error;
            frame.ok = Some(false);
            frame.error = Some(ramflux_sdk::LocalBusErrorBody {
                details: None,
                reason_code: None,
                code: "AttachmentDeleted".to_owned(),
                message: "attachment deleted".to_owned(),
                retry_after_ms: None,
                cause: None,
            });
            frame
        });
        let output = tokio::task::spawn_blocking({
            let socket = socket.clone();
            move || {
                run(
                    &socket,
                    &[
                        "object",
                        "revoke",
                        "--account",
                        "account",
                        "--object",
                        "object",
                        "--conversation",
                        "conversation",
                        "--recipient",
                        "recipient",
                        "--link",
                        "link",
                        "--effective-at",
                        "5",
                        "--recipient-device",
                        "device",
                        "--target",
                        "target",
                    ],
                )
            }
        })
        .await
        .expect("join");
        server.await.expect("server").expect("exchange");
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).expect("utf8");
        assert!(stderr.contains("AttachmentDeleted"), "{stderr}");
    })
    .await;
}
