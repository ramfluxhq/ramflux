// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Error metadata survives the actual client socket and response demultiplexer.
use super::*;

#[tokio::test]
async fn subscription_refusals_preserve_replay_bounds_in_the_sdk_error() -> Result<(), SdkError> {
    let root = PathBuf::from("/tmp").join(format!(
        "ramflux-stream-error-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |t| t.as_nanos())
    ));
    std::fs::create_dir_all(&root)?;
    let socket = root.join("bus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let request = read_local_bus_frame(&mut socket).await?;
        let mut response = local_bus_error(&request, &SdkError::LocalBus("resync_required".into()));
        response.body = serde_json::json!({"floor_seq":10,"head_seq":42});
        if let Some(error) = &mut response.error {
            error.code = "resync_required".into();
        }
        write_local_bus_frame(&mut socket, &response).await
    });
    let mut client = LocalBusClient::connect(&socket).await?;
    let result = client
        .request(
            Some("a".into()),
            "stream",
            "bus.subscribe",
            serde_json::json!({"since_seq":0,"topics":["*"]}),
        )
        .await;
    let refusal = result.err().ok_or_else(closed)?;
    let details = format!("{refusal:?}");
    assert!(details.contains("floor_seq"), "structured refusal lost replay floor: {details}");
    assert!(details.contains("head_seq"), "structured refusal lost replay head: {details}");
    assert!(details.contains("42"));
    assert!(details.contains("10"));
    server.await.map_err(|e| SdkError::LocalBus(e.to_string()))??;
    drop(client);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
