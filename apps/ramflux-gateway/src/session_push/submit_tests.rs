// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual self-recipient frames distinguish compact capability replies from legacy replies.
use super::*;
#[tokio::test]
async fn compact_reply_and_self_target_delivery() -> anyhow::Result<()> {
    self_submit(true).await
}
#[tokio::test]
async fn legacy_wire_unchanged_self_delivery_once() -> anyhow::Result<()> {
    self_submit(false).await
}
async fn self_submit(capable: bool) -> anyhow::Result<()> {
    let mut fixture = Fixture::new(if capable { "push-capable-self" } else { "push-legacy-self" })?;
    let mut runtime = crate::session::submit_ack_tests::test_runtime()?;
    runtime.target_delivery_id = "alice-target".into();
    runtime.session_push = capable.then(|| ID.into());
    let submit = crate::session::submit_ack_tests::signed_submit(
        &runtime,
        i64::try_from(ramflux_node_core::now_unix_seconds())?,
    )?;
    let envelope_id = submit.envelope.envelope_id.clone();
    let (send, frames) = sink();
    fixture
        .context
        .hub
        .register_session(
            runtime.target_delivery_id.clone(),
            runtime.session_id.clone(),
            send.clone(),
            runtime.session_push.clone(),
        )
        .await?;
    let context = fixture.context.clone();
    let task = tokio::spawn(async move {
        crate::session::handle_gateway_submit(&send, &context, &runtime, &submit).await
    });
    let req = fixture.next().await?;
    assert_eq!(req.path, "/mvp0/envelope");
    req.respond.send((200,json!({"outcome":"online","target_delivery_id":"alice-target","inbox_seq":1,"cursor":null,"incarnation_id":ID,"retain_until":123_456}))).map_err(|_|Retired)?;
    tokio::time::timeout(Duration::from_secs(10), task).await???;
    fixture.context.hub.flushed("alice-target").await?;
    let rows = frames.lock().map_err(|_| Retired)?.clone();
    if capable {
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            json!({"frame_type":"submit_accepted","incarnation_id":ID,"envelope_id":envelope_id,"target_delivery_id":"alice-target","inbox_seq":1})
        );
        assert_eq!(rows[1]["frame_type"], "deliver");
        assert_eq!(rows[1]["incarnation_id"], ID);
        assert_eq!(rows[1]["retain_until"], 123_456);
        assert_eq!(rows[1]["entry"]["envelope"]["envelope_id"], envelope_id);
    } else {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["frame_type"], "deliver");
        assert!(rows[0].get("incarnation_id").is_none());
        assert!(rows[0].get("retain_until").is_none());
        assert_eq!(rows[0]["entry"]["envelope"]["envelope_id"], envelope_id);
        assert_eq!(rows[0].as_object().map(serde_json::Map::len), Some(2));
    }
    Ok(())
}
