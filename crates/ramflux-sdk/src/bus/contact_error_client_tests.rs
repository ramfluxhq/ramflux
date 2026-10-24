// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Structured contact refusals must survive the public SDK socket boundary.
use super::*;
#[tokio::test]
async fn contact_confirmation_details_and_retry_hints_survive_the_sdk_client_round_trip()
-> Result<(), SdkError> {
    let path = std::env::temp_dir().join(format!(
        "ramflux-contact-errors-{}-{}.sock",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_nanos())
    ));
    let listener = tokio::net::UnixListener::bind(&path)?;
    let expected = LocalBusErrorBody {
        code: "ValidationFailed".into(),
        message: "confirmation required".into(),
        reason_code: Some("root_replacement_confirmation_required".into()),
        details: Some(Box::new(
            serde_json::json!({"principal_id":"bob","previous_root_commitment":"old","proposed_root_commitment":"new"}),
        )),
        retry_after_ms: None,
        cause: None,
    };
    let rate = crate::bus::io::local_bus_error_body(&SdkError::ContactInput(
        crate::ContactReason::LookupRateLimited,
    ));
    let replies = [expected.clone(), rate.clone(), expected.clone()];
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let (read, mut write) = socket.into_split();
        let mut reader = tokio::io::BufReader::new(read);
        for reply in replies {
            let mut frame = crate::bus::io::read_local_bus_frame(&mut reader).await?;
            frame.body = serde_json::json!({});
            frame.kind = LocalBusFrameKind::Error;
            frame.ok = Some(false);
            frame.error = Some(reply);
            crate::bus::io::write_local_bus_frame(&mut write, &frame).await?;
        }
        Ok::<_, SdkError>(())
    });
    let mut client = LocalBusClient::connect(&path).await?;
    let frame = LocalBusFrame::request(
        "compare",
        Some("alice".into()),
        "contact",
        "contact.add",
        serde_json::json!({"card":"public-card"}),
    );
    let response = client.request_frame_response(frame).await?;
    assert_eq!(response.kind, LocalBusFrameKind::Error);
    assert_eq!(response.error, Some(expected));
    let frame = LocalBusFrame::request(
        "rate",
        Some("alice".into()),
        "contact",
        "contact.add",
        serde_json::json!({"principal_id":"bob"}),
    );
    let response = client.request_frame_response(frame).await?;
    assert_eq!(response.error, Some(rate.clone()));
    assert_eq!(rate.code, "Unavailable");
    assert_eq!(rate.reason_code.as_deref(), Some("rate_limited"));
    assert_eq!(rate.retry_after_ms, Some(60000));
    let old_api = client
        .request(
            Some("alice".into()),
            "contact",
            "contact.add",
            serde_json::json!({"card":"public-card"}),
        )
        .await;
    assert!(
        matches!(old_api,Err(SdkError::LocalBus(message)) if message=="ValidationFailed: confirmation required")
    );
    server.await.map_err(|e| SdkError::LocalBus(e.to_string()))??;
    std::fs::remove_file(path)?;
    Ok(())
}
