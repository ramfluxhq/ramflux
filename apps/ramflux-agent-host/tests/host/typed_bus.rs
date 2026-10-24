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
