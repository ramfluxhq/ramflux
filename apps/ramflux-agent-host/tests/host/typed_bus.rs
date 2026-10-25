// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The actual SDK/RfdBus exchange classifies error codes, never words inside error messages.
use super::support::{Fixture, TestResult};
use ramflux_agent_host::{AgentBus, Error, RfdBus};
use ramflux_sdk::{
    LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind, SurfaceRefusalCode as Code,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
async fn typed_refusal_code_survives_sdk_transport_without_leaking_or_parsing_diagnostics()
-> TestResult {
    let f = Fixture::new()?;
    let listener = tokio::net::UnixListener::bind(&f.config.socket)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        for code in ["not_author", "too_large", "stale_hash", "unknown_failure", "resync_required"]
        {
            let length = socket.read_u32().await?;
            let mut bytes = vec![0; usize::try_from(length)?];
            socket.read_exact(&mut bytes).await?;
            let request: LocalBusFrame = serde_json::from_slice(&bytes)?;
            let mut response = request.clone();
            response.kind = LocalBusFrameKind::Error;
            response.ok = Some(false);
            response.body = json!(null);
            response.error = Some(LocalBusErrorBody {
                details: None,
                reason_code: Some("stale_version".into()),
                code: code.into(),
                message: "secret diagnostic contains stale_version and not_author".into(),
                retry_after_ms: None,
                cause: None,
            });
            let bytes = serde_json::to_vec(&response)?;
            socket.write_u32(u32::try_from(bytes.len())?).await?;
            socket.write_all(&bytes).await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut bus = RfdBus::connect(&f.config.socket, "agent").await?;
    for (index, expected) in
        [Some(Code::NotAuthor), Some(Code::TooLarge), Some(Code::StaleHash), None, None]
            .into_iter()
            .enumerate()
    {
        let error = bus.request("surface.send", json!({}), None).await.err().ok_or("refusal")?;
        assert!(!error.to_string().contains("secret"));
        if let Some(expected) = expected {
            assert!(matches!(error,Error::SurfaceRefused(actual) if actual==expected));
        } else if index == 3 {
            assert!(matches!(error, Error::SurfaceRefused(Code::NotPermitted)));
        } else {
            assert!(matches!(error, Error::Resync));
        }
    }
    server.await?.map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
async fn r5_authentication_loss_on_receive_and_surface_reads_stops_the_host() -> TestResult {
    let f = Fixture::new()?;
    let listener = tokio::net::UnixListener::bind(&f.config.socket)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        for (method, code) in [
            ("message.receive", "Unauthenticated"),
            ("account.status", "AccountLocked"),
            ("surface.get", "AccountLocked"),
        ] {
            let length = socket.read_u32().await?;
            let mut bytes = vec![0; usize::try_from(length)?];
            socket.read_exact(&mut bytes).await?;
            let mut frame: LocalBusFrame = serde_json::from_slice(&bytes)?;
            assert_eq!(frame.method, method);
            frame.kind = LocalBusFrameKind::Error;
            frame.ok = Some(false);
            frame.body = json!(null);
            frame.error = Some(LocalBusErrorBody {
                code: code.into(),
                message: "redacted".into(),
                details: None,
                reason_code: None,
                retry_after_ms: None,
                cause: None,
            });
            let wire = serde_json::to_vec(&frame)?;
            socket.write_u32(u32::try_from(wire.len())?).await?;
            socket.write_all(&wire).await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut bus = RfdBus::connect(&f.config.socket, "agent").await?;
    for method in ["message.receive", "surface.get"] {
        assert!(matches!(bus.request(method, json!({}), None).await, Err(Error::IdentityLost)));
    }
    server.await?.map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
async fn gateway_authentication_races_revalidate_identity_without_resending_the_operation()
-> TestResult {
    for failed_identity in
        [None, Some("account.status"), Some("device.list"), Some("identity.directory")]
    {
        let f = Fixture::new()?;
        let listener = tokio::net::UnixListener::bind(&f.config.socket)?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            for method in [
                "message.receive",
                "account.status",
                "device.list",
                "identity.directory",
                "message.receive",
            ] {
                let length = socket.read_u32().await?;
                let mut bytes = vec![0; usize::try_from(length)?];
                socket.read_exact(&mut bytes).await?;
                let mut frame: LocalBusFrame = serde_json::from_slice(&bytes)?;
                assert_eq!(frame.method, method);
                let first = frame.request_id == "agent-1";
                let rejected = first || failed_identity == Some(method);
                frame.kind =
                    if rejected { LocalBusFrameKind::Error } else { LocalBusFrameKind::Response };
                frame.ok = Some(!rejected);
                frame.body = match method {
                    "account.status" => {
                        json!({"client_mode":"headless_ai","local_device_authorized":true,"principal_id":"agent"})
                    }
                    "device.list" => {
                        json!({"principal_id":"agent","local_device_id":"device","devices":[{"device_id":"device"}]})
                    }
                    "identity.directory" => {
                        json!({"identities":[{"principal_id":"agent","is_self":true,"kind":"headless_ai"}],"next_cursor":null})
                    }
                    _ => json!({"received":[]}),
                };
                if rejected {
                    frame.error = Some(LocalBusErrorBody {
                        code: "Unauthenticated".into(),
                        message: "redacted".into(),
                        details: None,
                        reason_code: None,
                        retry_after_ms: None,
                        cause: None,
                    });
                }
                let wire = serde_json::to_vec(&frame)?;
                socket.write_u32(u32::try_from(wire.len())?).await?;
                socket.write_all(&wire).await?;
                if failed_identity == Some(method) {
                    break;
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut bus = RfdBus::connect(&f.config.socket, "agent").await?;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bus.request("message.receive", json!({}), None),
        )
        .await?;
        if failed_identity.is_some() {
            assert!(matches!(outcome, Err(Error::IdentityLost)));
        } else {
            assert!(matches!(outcome, Err(Error::Bus)));
            assert_eq!(
                bus.request("message.receive", json!({}), None).await?["received"],
                json!([])
            );
        }
        server.await?.map_err(|e| e.to_string())?;
    }
    Ok(())
}
