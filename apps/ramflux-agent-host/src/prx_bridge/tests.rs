// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Socket-driven host-loop contract tests.
use super::test_support::*;

use serde_json::{Value, json};
use std::sync::Arc;

#[tokio::test]
async fn bridge_dm_turn_sends_one_signed_text_reply() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    assert_eq!(input["params"]["attachments"], json!([]));
    assert_eq!(input["params"]["sender"]["device_id"], "human-device");
    assert_eq!(input["params"]["chat"]["kind"], "dm");
    let mut first = params(&input, "first-final");
    first["final"] = json!(true);
    first["text"] = json!("expected reply");
    server.call("reply.text", first).await?;
    assert_eq!(
        texts(&*host.data.lock().map_err(|_| "data")?)?,
        vec!["expected reply"],
        "reply.text must render before terminal fallback"
    );
    finish(&server, &input, "expected reply").await?;
    let data = Arc::clone(&host.data);
    assert_eq!(texts(&*data.lock().map_err(|_| "data")?)?, vec!["expected reply"]);
    assert!(
        data.lock().map_err(|_| "data")?.replies.iter().all(|r| r["sender_id"] == "agent-device")
    );
    let saved: Value = serde_json::from_slice(&std::fs::read(&host.config.state_file)?)?;
    assert_eq!(saved["engine"]["kind"], "ramflux.agent.prx_bridge.v1");
    assert!(
        saved["engine"]["turns"]
            .as_object()
            .ok_or("turns")?
            .values()
            .any(|t| t["terminal_at"].is_u64()),
        "terminal RPC ack must follow durable terminal state"
    );
    let stopped = host.stop().await?;
    assert_eq!(stopped.host.engine.stats()["inbound_sent"], 1);
    Ok(())
}
#[tokio::test]
async fn bridge_non_streamed_turn_uses_final_surface_fallback_text() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut p = params(&input, "fallback");
    p["op"] = json!("create");
    p["surface_id"] =
        json!(format!("final-{}", input["params"]["turn_id"].as_str().ok_or("turn")?));
    p["fallback_text"] = json!("nonstreamed");
    p["version"] = json!(1);
    assert_eq!(server.call("reply.surface", p).await?["result"]["ok"], true);
    let mut p = params(&input, "done");
    p["state"] = json!("done");
    server.call("turn.status", p).await?;
    assert_eq!(texts(&*host.data.lock().map_err(|_| "data")?)?, vec!["nonstreamed"]);
    assert_eq!(
        host.data.lock().map_err(|_| "data")?.surfaces,
        [] as [ramflux_protocol::A2uiConversationEvent; 0]
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_replayed_reply_frame_is_acked_without_second_rfd_write() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut p = params(&input, "generic");
    p["op"] = json!("create");
    p["surface_id"] = json!("generic");
    p["fallback_text"] = json!("fallback");
    server.call("reply.surface", p.clone()).await?;
    let before = host
        .data
        .lock()
        .map_err(|_| "data")?
        .requests
        .iter()
        .filter(|(m, _, _)| m == "message.submit")
        .count();
    server.call("reply.surface", p).await?;
    let after = host
        .data
        .lock()
        .map_err(|_| "data")?
        .requests
        .iter()
        .filter(|(m, _, _)| m == "message.submit")
        .count();
    assert_eq!(before, after);
    let stopped = host.stop().await?;
    assert_eq!(stopped.host.engine.stats()["dup_frames"], 1);
    Ok(())
}

#[tokio::test]
async fn bridge_generic_surface_create_is_rendered_as_fallback_text() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut p = params(&input, "generic");
    p["op"] = json!("create");
    p["surface_id"] = json!("notice");
    p["fallback_text"] = json!("generic text");
    assert_eq!(server.call("reply.surface", p).await?["result"]["ok"], true);
    assert_eq!(texts(&*host.data.lock().map_err(|_| "data")?)?, vec!["generic text"]);
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_stream_creates_surface_then_ordered_appends_then_close_then_text() -> TestResult {
    use ramflux_protocol::A2uiConversationCommand as C;
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    for (version, delta) in [(1, "a"), (2, "b")] {
        let mut p = params(&input, &format!("delta-{version}"));
        p["op"] = json!("stream_append");
        p["version"] = json!(version);
        p["text_delta"] = json!(delta);
        p["surface_id"] = json!("stream");
        server.call("reply.surface", p).await?;
    }
    let mut p = params(&input, "close");
    p["op"] = json!("close");
    p["version"] = json!(3);
    p["fallback_text"] = json!("ab");
    server.call("reply.surface", p).await?;
    finish(&server, &input, "ab").await?;
    {
        let data = host.data.lock().map_err(|_| "data")?;
        assert!(matches!(
            data.surfaces.first().map(ramflux_protocol::A2uiConversationEvent::command),
            Some(C::CreateSurface(_))
        ));
        assert!(matches!(
            data.surfaces.last().map(ramflux_protocol::A2uiConversationEvent::command),
            Some(C::DeleteSurface(_))
        ));
        let appended = data
            .surfaces
            .iter()
            .filter_map(|s| {
                if let C::StreamAppend(a) = s.command() {
                    Some(a.text_delta.as_str())
                } else {
                    None
                }
            })
            .collect::<String>();
        assert_eq!(appended, "ab");
        assert!(data.surfaces.iter().any(|s| matches!(s.command(),C::StreamAppend(a) if a.final_)));
        assert!(data.surfaces.iter().any(|s|matches!(s.command(),C::PatchSurface(p) if p.ops.iter().any(|o|matches!(o,ramflux_protocol::SurfacePatchOp::SetFallbackText{fallback_text} if fallback_text=="ab")))));
        assert_eq!(texts(&data)?, vec!["ab"]);
    }
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_stream_version_gap_is_not_rendered() -> TestResult {
    use ramflux_protocol::A2uiConversationCommand as C;
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    for (version, delta) in [(1, "safe"), (3, "gap-marker")] {
        let mut p = params(&input, &format!("delta-{version}"));
        p["op"] = json!("stream_append");
        p["version"] = json!(version);
        p["text_delta"] = json!(delta);
        server.call("reply.surface", p).await?;
    }
    finish(&server, &input, "safe").await?;
    assert!(
        !host.data.lock().map_err(|_| "data")?.surfaces.iter().any(
            |s| matches!(s.command(),C::StreamAppend(a) if a.text_delta.contains("gap-marker"))
        )
    );
    let stopped = host.stop().await?;
    assert_eq!(stopped.host.engine.stats()["stream_gap"], 1);
    Ok(())
}
#[tokio::test]
async fn bridge_stream_deltas_are_coalesced_and_capped() -> TestResult {
    use ramflux_protocol::A2uiConversationCommand as C;
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut bytes = Vec::new();
    for i in 1..=200 {
        let mut p = params(&input, &format!("delta-{i}"));
        p["op"] = json!("stream_append");
        p["version"] = json!(i);
        p["text_delta"] = json!("x".repeat(100));
        bytes.extend(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":format!("prx-{}",1000+i),"method":"reply.surface","params":p}))?);
        bytes.push(b'\n');
    }
    server.raw(bytes).await?;
    let calls = Arc::clone(&server.calls);
    let data = Arc::clone(&host.data);
    let coalesced = wait(&server.changed, move || {
        let appends = data
            .lock()
            .ok()?
            .surfaces
            .iter()
            .filter(|s| matches!(s.command(), C::StreamAppend(_)))
            .count();
        if appends > 11 {
            return Some(false);
        }
        calls
            .lock()
            .ok()?
            .iter()
            .any(|f| f["id"] == "prx-1200" && f["result"]["ok"] == true)
            .then_some(true)
    })
    .await?;
    assert!(coalesced, "200 deltas must not cause per-delta writes");
    let mut p = params(&input, "close");
    p["op"] = json!("close");
    p["version"] = json!(201);
    p["fallback_text"] = json!("x".repeat(20_000));
    server.call("reply.surface", p).await?;
    finish(&server, &input, &"x".repeat(20_000)).await?;
    {
        let data = host.data.lock().map_err(|_| "data")?;
        let appends =
            data.surfaces.iter().filter(|s| matches!(s.command(), C::StreamAppend(_))).count();
        assert!(appends <= 11, "200 deltas must not cause per-delta writes");
        let creates =
            data.surfaces.iter().filter(|s| matches!(s.command(), C::CreateSurface(_))).count();
        assert_eq!(creates, 2, "roll over after the 15 KiB block");
        let mut sizes = std::collections::HashMap::<String, usize>::new();
        for event in &data.surfaces {
            if let C::StreamAppend(a) = event.command() {
                *sizes.entry(a.surface_id.clone()).or_default() += a.text_delta.len();
            }
        }
        assert!(sizes.values().all(|size| *size <= 15_360));
        assert_eq!(sizes.values().sum::<usize>(), 20_000);
    }
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_reconnect_resends_unacked_inbound_with_same_key_and_turn_id() -> TestResult {
    use std::sync::atomic::Ordering;
    let (_root, server, mut host) = fixture().await?;
    server.ack_inbound.store(false, Ordering::SeqCst);
    let first = host.input(&server, "message-1").await?;
    let after = server.calls.lock().map_err(|_| "calls")?.len();
    server.disconnect().await?;
    let retry = server.wait_method("inbound.message", after).await?;
    assert_eq!(first["params"], retry["params"]);
    let stopped = host.stop().await?;
    assert!(stopped.host.engine.stats()["inbound_resent"].as_u64().unwrap_or(0) >= 1);
    Ok(())
}
#[tokio::test]
async fn bridge_deleted_message_sends_erase_and_retries_until_erased_true() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    host.input(&server, "message-1").await?;
    server.erase_errors.lock().map_err(|_| "errors")?.extend([Some(-32603), Some(-32005), None]);
    host.event(
        "message.updated",
        json!({"message":{"conversation_id":"thread","message_id":"message-1","deleted":true}}),
    )
    .await?;
    host.applied().await?;
    let state_path = host.config.state_file.clone();
    wait(&host.changed, move || {
        let s: Value = serde_json::from_slice(&std::fs::read(&state_path).ok()?).ok()?;
        s["engine"]["erases"].as_object()?.is_empty().then_some(())
    })
    .await?;
    let stopped = host.stop().await?;
    let stats = stopped.host.engine.stats();
    assert_eq!(stats["erases"]["acked"], 1);
    assert_eq!(stats["erases"]["retried"], 2);
    Ok(())
}
#[tokio::test]
async fn bridge_receipt_updates_cause_no_bus_reads() -> TestResult {
    let (_root, _server, mut host) = fixture().await?;
    let before = host.data.lock().map_err(|_| "data")?.requests.len();
    host.event("message.updated",json!({"message":{"conversation_id":"thread","message_id":"message-1","deleted":false,"receipt":"delivered"}})).await?;
    host.applied().await?;
    assert!(
        host.data.lock().map_err(|_| "data")?.requests[before..]
            .iter()
            .all(|(method, _, _)| method == "message.receive")
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_conversation_removal_sends_agent_revoked_and_cancels_turns() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    host.data.lock().map_err(|_| "data")?.removed = true;
    host.event("conversation.changed", json!({"conversation_id":"thread","removed":true})).await?;
    host.applied().await?;
    let mut barrier = params(&input, "removal-barrier");
    barrier["on"] = json!(false);
    server.call("reply.typing", barrier).await?;
    assert!(
        server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .any(|r| r["method"] == "inbound.control" && r["params"]["kind"] == "agent_revoked"),
        "removal must forward agent_revoked"
    );
    assert!(
        server.calls.lock().map_err(|_| "calls")?.iter().any(|r| r["method"] == "turn.cancel"),
        "removal must cancel the turn"
    );
    finish(&server, &input, "must not deliver").await?;
    assert_eq!(host.data.lock().map_err(|_| "data")?.replies, [] as [serde_json::Value; 0]);
    assert!(
        !host
            .data
            .lock()
            .map_err(|_| "data")?
            .requests
            .iter()
            .any(|(m, _, _)| m == "message.delete")
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_oversize_or_malformed_frame_does_not_stop_host() -> TestResult {
    let (_root, server, host) = fixture().await?;
    server.raw(b"{\"jsonrpc\":\"1.0\",\"id\":\"bad\"}\n".to_vec()).await?;
    let calls = Arc::clone(&server.calls);
    wait(&server.changed, move || {
        calls
            .lock()
            .ok()?
            .iter()
            .any(|f| f["id"] == "bad" && f["error"]["code"] == -32600)
            .then_some(())
    })
    .await?;
    let after = server.calls.lock().map_err(|_| "calls")?.len();
    server.raw(vec![b'x'; 1_048_577]).await?;
    server.wait_method("bridge.hello", after).await?;
    let stopped = host.stop().await?;
    assert_eq!(stopped.host.engine.stats()["frames_rejected"]["oversize"], 1);
    assert_eq!(stopped.host.engine.stats()["frames_rejected"]["parse"], 1);
    assert!(stopped.root.path().exists());
    Ok(())
}

async fn request_approval(server: &Server, input: &Value, deadline: u64) -> TestResult {
    let mut p = params(input, "approval");
    p["approval_id"] = json!("approval-prx");
    p["tool_name"] = json!("file_read");
    p["arguments_redacted"] = json!({"path":"fixture.txt"});
    p["args_hash"] = json!("digest");
    p["risk"] = json!("low");
    p["expires_at_ms"] = json!(deadline);
    assert_eq!(server.call("approval.request", p).await?["result"]["ok"], true);
    Ok(())
}
async fn resolve(host: &mut Host, approved: bool, device: &str) -> TestResult {
    {
        let mut data = host.data.lock().map_err(|_| "data")?;
        data.task["accepted"] = json!(true);
        data.task["state"] = json!("running");
        data.task["version"] = json!(2);
    }
    host.event("task.changed", json!({"conversation_id":"thread","task_id":"unused"})).await?;
    let data = Arc::clone(&host.data);
    wait(&host.changed, move || {
        data.lock().ok().filter(|d| d.task["state"] == "needs_me").map(|_| ())
    })
    .await?;
    {
        let mut data = host.data.lock().map_err(|_| "data")?;
        let task = data.task["task_id"].clone();
        data.task["state"] = json!(if approved { "running" } else { "failed" });
        data.task["version"] = json!(4);
        data.task["steps"] = json!([{"id":"approval","title":"Approval","state":if approved {"running"}else{"failed"}}]);
        data.task["approval_decisions"] = json!([{"grant_id":"grant-human","status":if approved{"approved"}else{"denied"},
            "task_binding":{"task_id":task,"step_id":"approval"},"decided_by":{"principal_id":"human-principal","device_id":device}}]);
    }
    host.event("task.changed", json!({"conversation_id":"thread","task_id":"unused"})).await?;
    host.applied().await
}
#[tokio::test]
async fn bridge_supervised_approval_approved_after_human_grant() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
    assert!(
        !server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .any(|r| r["method"] == "approval.decision")
    );
    assert_eq!(host.data.lock().map_err(|_| "data")?.task["state"], "proposed");
    resolve(&mut host, true, "human-device").await?;
    let decision = server.wait_method("approval.decision", 0).await?;
    assert_eq!(decision["params"]["decision"], "approved");
    assert_eq!(decision["params"]["decided_by"]["device_id"], "human-device");
    assert_eq!(decision["params"]["decided_by"]["trust"], "verified");
    finish(&server, &input, "TOOL_RAN").await?;
    assert_eq!(texts(&*host.data.lock().map_err(|_| "data")?)?, vec!["TOOL_RAN"]);
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_supervised_approval_denied_is_forwarded_denied() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
    resolve(&mut host, false, "human-device").await?;
    assert_eq!(server.wait_method("approval.decision", 0).await?["params"]["decision"], "denied");
    finish(&server, &input, "TOOL_REFUSED").await?;
    assert_eq!(texts(&*host.data.lock().map_err(|_| "data")?)?, vec!["TOOL_REFUSED"]);
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_approval_from_other_device_or_unverified_is_not_forwarded() -> TestResult {
    for unverified in [false, true] {
        let (_root, server, mut host) = fixture().await?;
        let input = host.input(&server, "message-1").await?;
        request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
        if unverified {
            host.data.lock().map_err(|_| "data")?.verified = false;
        }
        resolve(&mut host, true, if unverified { "human-device" } else { "human-other" }).await?;
        {
            let mut data = host.data.lock().map_err(|_| "data")?;
            data.clock = crate::bus::now_ms();
            data.polled_clock = 0;
        }
        host.poll_clock().await?;
        let mut p = params(&input, "decision-barrier");
        p["on"] = json!(false);
        server.call("reply.typing", p).await?;
        assert!(
            !server
                .calls
                .lock()
                .map_err(|_| "calls")?
                .iter()
                .any(|r| r["method"] == "approval.decision")
        );
        assert!(
            texts(&*host.data.lock().map_err(|_| "data")?)?
                .iter()
                .any(|t| t.contains("approval_unavailable"))
        );
        host.stop().await?;
    }
    Ok(())
}
#[tokio::test]
async fn bridge_supervised_approval_timeout_sends_expired_and_typed_reply() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let deadline = crate::bus::now_ms() + 60_000;
    request_approval(&server, &input, deadline).await?;
    assert_eq!(host.data.lock().map_err(|_| "data")?.replies, [] as [serde_json::Value; 0]);
    host.data.lock().map_err(|_| "data")?.clock = deadline;
    host.poll_clock().await?;
    let mut p = params(&input, "clock-gate");
    p["on"] = json!(true);
    server.call("reply.typing", p).await?;
    assert!(
        server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .any(|r| r["method"] == "approval.decision" && r["params"]["decision"] == "expired"),
        "deadline must send expired"
    );
    assert!(
        texts(&*host.data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("approval_timeout"))
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_full_mode_never_opens_a_grant() -> TestResult {
    let root = tempfile::Builder::new().prefix("rf-full-").tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    let mut host = Host::start(&server, crate::PrxAuthorization::Full).await?;
    let input = host.input(&server, "message-1").await?;
    request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
    assert!(
        !host
            .data
            .lock()
            .map_err(|_| "data")?
            .requests
            .iter()
            .any(|(m, _, _)| m == "mcp.tool.started" || m == "task.propose")
    );
    let decision = server.wait_method("approval.decision", 0).await?;
    assert_eq!(decision["params"]["decision"], "expired");
    assert!(
        texts(&*host.data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("authorization_mismatch"))
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_awaiting_approval_status_is_typed_failure() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut p = params(&input, "durable-approval");
    p["state"] = json!("awaiting_approval");
    p["approval_id"] = json!("durable");
    server.call("turn.status", p).await?;
    assert!(
        texts(&*host.data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("prx_internal_approval_unavailable"))
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_turn_without_terminal_status_is_cancelled_at_turn_timeout() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let mut accepted = params(&input, "admission-ack-barrier");
    accepted["on"] = json!(true);
    server.call("reply.typing", accepted).await?;
    let state: Value = serde_json::from_slice(&std::fs::read(&host.config.state_file)?)?;
    let started = state["engine"]["turns"]
        .as_object()
        .ok_or("turns")?
        .values()
        .next()
        .ok_or("turn")?["submitted_at"]
        .as_u64()
        .ok_or("start")?;
    host.data.lock().map_err(|_| "data")?.clock = started + 999_999;
    let mut p = params(&input, "before-timeout");
    p["on"] = json!(true);
    server.call("reply.typing", p).await?;
    assert!(
        !server.calls.lock().map_err(|_| "calls")?.iter().any(|r| r["method"] == "turn.cancel")
    );
    host.data.lock().map_err(|_| "data")?.clock = started + 1_000_000;
    host.poll_clock().await?;
    let mut p = params(&input, "at-timeout");
    p["on"] = json!(true);
    server.call("reply.typing", p).await?;
    assert!(
        server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .any(|r| r["method"] == "turn.cancel" && r["params"]["reason"] == "host_turn_timeout"),
        "deadline must cancel the turn"
    );
    assert!(
        texts(&*host.data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("engine_turn_timeout"))
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_deleted_message_still_queued_is_never_sent_to_prx() -> TestResult {
    use std::sync::atomic::Ordering;
    let root = tempfile::Builder::new().prefix("rf-queued-").tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    server.hello_answer.store(false, Ordering::SeqCst);
    let mut host = Host::start(&server, crate::PrxAuthorization::Supervised).await?;
    server.wait_method("bridge.hello", 0).await?;
    host.enqueue("message-1").await?;
    host.event(
        "message.updated",
        json!({"message":{"conversation_id":"thread","message_id":"message-1","deleted":true}}),
    )
    .await?;
    host.applied().await?;
    server
        .raw(
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"rf-hello","result":{"ok":true}}))?
                .into_iter()
                .chain(*b"\n")
                .collect(),
        )
        .await?;
    server.wait_method("inbound.message_deleted", 0).await?;
    assert!(
        !server.calls.lock().map_err(|_| "calls")?.iter().any(|f| f["method"] == "inbound.message")
    );
    let state: Value = serde_json::from_slice(&std::fs::read(&host.config.state_file)?)?;
    assert!(state["engine"]["inbound"].as_object().ok_or("queue")?.is_empty());
    assert!(state["engine"]["turns"].as_object().ok_or("turns")?.is_empty());
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_pending_erase_survives_host_restart() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    host.input(&server, "message-1").await?;
    server.erase_errors.lock().map_err(|_| "errors")?.extend([Some(-32603); 10]);
    host.event(
        "message.updated",
        json!({"message":{"conversation_id":"thread","message_id":"message-1","deleted":true}}),
    )
    .await?;
    host.applied().await?;
    server.wait_method("inbound.message_deleted", 0).await?;
    let data = Arc::clone(&host.data);
    let stopped = host.stop().await?;
    assert!(
        stopped.host.state.engine.as_ref().ok_or("state")?["erases"].is_object(),
        "erase outbox must be serialized"
    );
    assert_eq!(
        stopped.host.state.engine.as_ref().ok_or("state")?["erases"]
            .as_object()
            .ok_or("erases")?
            .len(),
        1
    );
    server.erase_errors.lock().map_err(|_| "errors")?.clear();
    let host = Host::resume(stopped, data).await?;
    let state_path = host.config.state_file.clone();
    wait(&host.changed, move || {
        let s: Value = serde_json::from_slice(&std::fs::read(&state_path).ok()?).ok()?;
        s["engine"]["erases"].as_object()?.is_empty().then_some(())
    })
    .await?;
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_unreachable_at_start_warns_and_retries_without_stopping_host() -> TestResult {
    let root = tempfile::Builder::new().prefix("rf-unreachable-").tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    server.stop_listener();
    tokio::task::yield_now().await;
    let started = Host::start(&server, crate::PrxAuthorization::Supervised).await;
    assert!(started.is_ok(), "an unreachable PRX socket must not stop host startup");
    let mut host = started?;
    host.enqueue("message-1").await?;
    host.event("message.updated", json!({"message":{"deleted":false}})).await?;
    host.applied().await?;
    let saved: Value = serde_json::from_slice(&std::fs::read(&host.config.state_file)?)?;
    assert_eq!(saved["engine"]["inbound"].as_object().ok_or("queue")?.len(), 1);
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_hello_refusal_backs_off_and_logs_once_per_window() -> TestResult {
    use std::sync::atomic::Ordering;
    let root = tempfile::Builder::new().prefix("rf-refusal-").tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    server.hello_code.store(-32004, Ordering::SeqCst);
    let mut host = Host::start(&server, crate::PrxAuthorization::Supervised).await?;
    server.wait_method("bridge.hello", 0).await?;
    let closed = Arc::clone(&server.disconnects);
    wait(&server.changed, move || (closed.load(Ordering::SeqCst) >= 1).then_some(())).await?;
    host.event("message.updated", json!({"message":{"deleted":false}})).await?;
    host.applied().await?;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(59)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .filter(|f| f["method"] == "bridge.hello")
            .count(),
        1
    );
    let after = server.calls.lock().map_err(|_| "calls")?.len();
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::time::resume();
    server.wait_method("bridge.hello", after).await?;
    let stopped = host.stop().await?;
    assert!(stopped.host.engine.stats()["hello_refused"]["-32004"].as_u64().unwrap_or(0) >= 1);
    Ok(())
}

#[tokio::test]
async fn bridge_tool_events_without_task_render_progress() -> TestResult {
    use ramflux_protocol::A2uiConversationCommand as C;
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    for kind in ["started", "finished"] {
        let mut p = params(&input, kind);
        p["kind"] = json!(kind);
        p["tool_name"] = json!("file_read");
        p["tool_call_id"] = json!("call-1");
        p["iteration"] = json!(1);
        server.call("tool.event", p).await?;
    }
    finish(&server, &input, "TOOL_RAN").await?;
    {
        let data = host.data.lock().map_err(|_| "data")?;
        assert!(!data.requests.iter().any(|(m, _, _)| m == "task.propose"));
        let progress = data
            .surfaces
            .iter()
            .filter_map(|s| {
                if let C::StreamAppend(a) = s.command() {
                    Some(a.text_delta.as_str())
                } else {
                    None
                }
            })
            .collect::<String>();
        assert!(progress.contains("file_read: running") && progress.contains("file_read: done"));
    }
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_tool_events_become_task_steps_for_running_task() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    host.data.lock().map_err(|_| "data")?.task = json!({"conversation_id":"thread","task_id":"human-task","requester":"human-principal","assignee":"agent-principal","accepted":true,"state":"running","version":2,"steps":[]});
    host.event("task.changed", json!({"conversation_id":"thread","task_id":"human-task"})).await?;
    host.applied().await?;
    for kind in ["started", "finished"] {
        let mut p = params(&input, kind);
        p["kind"] = json!(kind);
        p["tool_name"] = json!("file_read");
        p["tool_call_id"] = json!("call-1");
        p["iteration"] = json!(1);
        server.call("tool.event", p).await?;
    }
    {
        let data = host.data.lock().map_err(|_| "data")?;
        assert_eq!(data.task["steps"].as_array().ok_or("steps")?.len(), 1);
        assert_eq!(data.task["steps"][0]["state"], "done");
        assert_eq!(data.task["version"], 4);
        assert!(!data.requests.iter().any(|(m, _, _)| m == "task.propose"));
        assert_eq!(data.surfaces, [] as [ramflux_protocol::A2uiConversationEvent; 0]);
    }
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_socket_with_wrong_mode_owner_or_symlink_fails_closed_at_start() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    let server = Server::new(root.path())?;
    let mut config: crate::PrxBridgeConfig =
        serde_json::from_value(json!({"socket_path":server.path}))?;
    std::fs::set_permissions(&server.path, std::fs::Permissions::from_mode(0o666))?;
    assert!(matches!(crate::PrxBridgeEngine::new(&config, "agent", 1), Err(crate::Error::Config)));
    std::fs::set_permissions(&server.path, std::fs::Permissions::from_mode(0o600))?;
    let link = root.path().join("link.sock");
    symlink(&server.path, &link)?;
    config.socket_path = link;
    assert!(matches!(crate::PrxBridgeEngine::new(&config, "agent", 1), Err(crate::Error::Config)));
    config.socket_path = server.path.clone();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(matches!(crate::PrxBridgeEngine::new(&config, "agent", 1), Err(crate::Error::Config)));
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    // Root can construct an owner-only negative on Linux; unprivileged Mac cannot chown.
    if rustix::process::geteuid().is_root() {
        std::os::unix::fs::chown(&server.path, Some(65534), None)?;
        assert!(matches!(
            crate::PrxBridgeEngine::new(&config, "agent", 1),
            Err(crate::Error::Config)
        ));
        std::os::unix::fs::chown(&server.path, Some(0), None)?;
    }
    Ok(())
}
#[tokio::test]
async fn checkpoint_from_main_without_bridge_fields_loads() -> TestResult {
    use crate::EngineProvider;
    let (_root, server, host) = fixture().await?;
    let mut old = serde_json::to_value(host.config.clone())?;
    old["engine"] = Value::Null;
    old["rules"] = json!([{"pattern":"ping","reply":"pong"}]);
    let () = crate::Config::validate(&serde_json::from_value(old)?)?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let mut config = host.config.clone();
    config.state_file = root.path().join("old.json");
    let old: std::result::Result<crate::Checkpoint, _> = serde_json::from_value(
        json!({"account_id":"agent","principal_id":"agent-principal","device_id":"agent-device","cursor":37,"last_reply_ms":{},"pending":null}),
    );
    assert!(old.is_ok(), "a main checkpoint without new fields must load");
    let old = old?;
    let store = crate::CheckpointStore::new(config.state_file.clone())?;
    store.save(&old)?;
    drop(store);
    let bridge = config.engine.as_ref().and_then(|e| e.prx_bridge.as_ref()).ok_or("config")?;
    let restored =
        crate::AgentHost::new(config.clone(), crate::PrxBridgeEngine::new(bridge, "agent", 128)?)?;
    assert_eq!(restored.checkpoint().cursor, Some(37));
    assert_eq!(
        restored.engine.checkpoint()?.ok_or("state")?["kind"],
        "ramflux.agent.prx_bridge.v1"
    );
    drop(restored);
    drop(server);
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_engine_refuses_http_engine_state() -> TestResult {
    let (_root, _server, host) = fixture().await?;
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let mut config = host.config.clone();
    config.state_file = root.path().join("http.json");
    let old = crate::Checkpoint {
        engine: Some(json!({"sessions":{},"jobs":{},"pending":{},"completed":{}})),
        ..Default::default()
    };
    let store = crate::CheckpointStore::new(config.state_file.clone())?;
    store.save(&old)?;
    drop(store);
    let bridge = config.engine.as_ref().and_then(|e| e.prx_bridge.as_ref()).ok_or("config")?;
    assert!(matches!(
        crate::AgentHost::new(config.clone(), crate::PrxBridgeEngine::new(bridge, "agent", 128)?),
        Err(crate::Error::State)
    ));
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn config_accepts_exactly_one_engine() -> TestResult {
    let (_root, _server, host) = fixture().await?;
    let mut config = host.config.clone();
    assert!(config.validate().is_ok());
    config.rules.push(crate::Rule { pattern: "ping".into(), reply: "pong".into(), surface: None });
    assert!(matches!(config.validate(), Err(crate::Error::Config)));
    config.rules.clear();
    let serialized = serde_json::to_value(&config)?;
    let mut both = serialized.clone();
    both["engine"]["prx"] = json!({"base_url":"http://example.invalid","token_file":"/tmp/token","session_scope":"per_conversation","request_timeout_s":1,"max_in_flight_per_conversation":1});
    assert!(serde_json::from_value::<crate::Config>(both)?.validate().is_err());
    config.engine = None;
    assert!(config.validate().is_err());
    let mut invalid = serialized;
    invalid["engine"]["prx_bridge"]["stream_flush_ms"] = json!(99);
    assert!(serde_json::from_value::<crate::Config>(invalid)?.validate().is_err());
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_pending_visible_failure_is_sent_after_bus_reconnect() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
    {
        let mut data = host.data.lock().map_err(|_| "data")?;
        data.task["assignee"] = json!("foreign-assignee");
        data.fail_after_task_read = Some(());
    }
    let data = Arc::clone(&host.data);
    let stopped = host.transport_failure().await?;
    assert_eq!(stopped.host.state.visible_failures.len(), 1);
    assert!(stopped.host.state.approvals.is_empty());
    data.lock().map_err(|_| "data")?.bus_down = false;
    let host = Host::resume(stopped, Arc::clone(&data)).await?;
    assert!(
        texts(&*data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("approval_unavailable"))
    );
    host.stop().await?;
    http_visible_failure().await
}
async fn http_visible_failure() -> TestResult {
    use crate::prx_test_support::{FakePrx, approval_steps, step};
    use crate::{
        AgentHost, EngineConfig, EngineProvider, PrxAuthorization, PrxConfig, PrxEngine,
        PrxSessionScope,
    };
    use hyper::{Method, StatusCode};
    use tokio::sync::{Notify, mpsc};
    let mut steps = approval_steps("2099-01-01T00:00:00Z");
    steps.push(step(
        Method::POST,
        "/api/sessions/session-1/approvals/decision-1",
        StatusCode::OK,
        json!({}),
    ));
    let server = FakePrx::start(steps).await.map_err(|_| "HTTP fixture")?;
    let (_root, socket, template) = fixture().await?;
    let mut config = template.config.clone();
    template.stop().await?;
    drop(socket);
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    config.state_file = root.path().join("state.json");
    let token = root.path().join("token");
    std::fs::write(&token, "test-prx-token")?;
    std::fs::set_permissions(&token, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let prx = PrxConfig {
        base_url: server.base_url.clone(),
        token_file: token,
        session_scope: PrxSessionScope::PerConversation,
        request_timeout_s: 2,
        max_in_flight_per_conversation: 1,
        authorization: PrxAuthorization::Supervised,
        turn_timeout_s: 120,
        approval_timeout_s: 600,
    };
    config.engine = Some(EngineConfig { prx: Some(prx.clone()), prx_bridge: None });
    let mut host = AgentHost::new(config.clone(), PrxEngine::new(&prx, 128)?)?;
    let data = Arc::new(std::sync::Mutex::new(Data { verified: true, ..Data::default() }));
    let changed = Arc::new(Notify::new());
    let (events, rx) = mpsc::channel(8);
    data.lock().map_err(|_|"data")?.messages.insert("message-1".into(),json!({"conversation_id":"thread","message_id":"message-1","sender_id":"human-principal","sender_device_id":"human-device","sender_root_commitment":"human-root","body_utf8":"HTTP input","deleted":false}));
    let mut bus = Bus { data: Arc::clone(&data), changed: Arc::clone(&changed), events: rx };
    host.start(&mut bus).await?;
    let task = tokio::spawn(async move {
        let result = host.run(&mut bus).await;
        (host, bus, result)
    });
    let mut event = ramflux_sdk::LocalBusFrame::request(
        "input",
        Some("agent".into()),
        "stream",
        "message.received",
        json!({"message":{"conversation_id":"thread","message_id":"message-1","sender_id":"human-principal"}}),
    );
    event.kind = ramflux_sdk::LocalBusFrameKind::Event;
    event.seq = Some(1);
    events.send(event).await?;
    let observed = Arc::clone(&data);
    wait(&changed, move || {
        observed.lock().ok().filter(|d| d.task["state"] == "proposed").map(|_| ())
    })
    .await?;
    {
        let mut state = data.lock().map_err(|_| "data")?;
        state.task["assignee"] = json!("foreign-assignee");
        state.fail_after_task_read = Some(());
    }
    let (host, mut bus, result) =
        tokio::time::timeout(std::time::Duration::from_secs(5), task).await??;
    assert!(matches!(result, Err(crate::Error::Bus)));
    assert_eq!(host.state.visible_failures.len(), 1);
    assert!(host.state.approvals.is_empty());
    assert!(
        host.engine.checkpoint()?.ok_or("engine")?["completed"]
            .as_object()
            .ok_or("completed")?
            .is_empty()
    );
    drop(host);
    data.lock().map_err(|_| "data")?.bus_down = false;
    let mut restored = AgentHost::new(config, PrxEngine::new(&prx, 128)?)?;
    restored.start(&mut bus).await?;
    assert_eq!(texts(&*data.lock().map_err(|_| "data")?)?.len(), 1);
    assert!(restored.state.visible_failures.is_empty());
    Ok(())
}
#[tokio::test]
async fn bridge_logs_never_contain_bodies() -> TestResult {
    const CHILD: &str = "RAMFLUX_BRIDGE_LOG_TEST_CHILD";
    const MARKER: &str = "bridge-private-body-marker";
    if std::env::var_os(CHILD).is_none() {
        let output = tokio::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "prx_bridge::tests::bridge_logs_never_contain_bodies", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .await?;
        let logs = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "logging child failed");
        assert!(!logs.contains(MARKER));
        return Ok(());
    }
    let (_root, server, mut host) = fixture().await?;
    host.enqueue_text("message-1", MARKER).await?;
    let input = server.wait_method("inbound.message", 0).await?;
    let mut p = params(&input, "delta");
    p["op"] = json!("stream_append");
    p["version"] = json!(1);
    p["text_delta"] = json!(MARKER);
    p["fallback_text"] = json!(MARKER);
    server.call("reply.surface", p).await?;
    let mut p = params(&input, "tool");
    p["kind"] = json!("started");
    p["tool_name"] = json!("file_read");
    p["tool_call_id"] = json!("call");
    p["iteration"] = json!(1);
    p["summary"] = json!(MARKER);
    server.call("tool.event", p).await?;
    let mut p = params(&input, "approval");
    p["approval_id"] = json!("log-approval");
    p["tool_name"] = json!("file_read");
    p["args_hash"] = json!("digest");
    p["risk"] = json!("low");
    p["arguments_redacted"] = json!({"fixture":MARKER});
    p["expires_at_ms"] = json!(crate::bus::now_ms() + 60_000);
    server.call("approval.request", p).await?;
    finish(&server, &input, MARKER).await?;
    host.stop().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_missing_signer_metadata_is_not_forwarded() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    request_approval(&server, &input, crate::bus::now_ms() + 60_000).await?;
    // Hold the receipt read until the rfd-shaped row (without signer fields) is installed.
    {
        let mut data = host.data.lock().map_err(|_| "data")?;
        data.task["accepted"] = json!(true);
        data.task["state"] = json!("running");
        data.task["version"] = json!(2);
    }
    let data = Arc::clone(&host.data);
    wait(&host.changed, move || {
        data.lock().ok().filter(|d| d.task["state"] == "needs_me").map(|_| ())
    })
    .await?;
    {
        let mut data = host.data.lock().map_err(|_| "data")?;
        let task = data.task["task_id"].clone();
        data.task["state"] = json!("running");
        data.task["version"] = json!(4);
        data.task["steps"] = json!([{"id":"approval","state":"running"}]);
        data.task["approval_decisions"] = json!([{"grant_id":"grant-human","status":"approved","task_binding":{"task_id":task,"step_id":"approval"},"delivery_state":"applied"}]);
    }
    let data = Arc::clone(&host.data);
    wait(&host.changed, move || data.lock().ok().filter(|d| !d.replies.is_empty()).map(|_| ()))
        .await?;
    let mut barrier = params(&input, "signer-barrier");
    barrier["on"] = json!(false);
    server.call("reply.typing", barrier).await?;
    assert!(
        !server
            .calls
            .lock()
            .map_err(|_| "calls")?
            .iter()
            .any(|r| r["method"] == "approval.decision")
    );
    assert!(
        texts(&*host.data.lock().map_err(|_| "data")?)?
            .iter()
            .any(|t| t.contains("approval_unavailable"))
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_deleting_an_old_turn_preserves_the_current_turn_index() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let first = host.input(&server, "old-message").await?;
    finish(&server, &first, "old reply").await?;
    // The fake clock releases the ordinary per-conversation rate limit.
    host.data.lock().map_err(|_| "data")?.clock = crate::bus::now_ms() + 200;
    let current = host.input(&server, "current-message").await?;
    host.event(
        "message.updated",
        json!({"message":{"conversation_id":"thread","message_id":"old-message","deleted":true}}),
    )
    .await?;
    host.applied().await?;
    let data = Arc::clone(&host.data);
    let stopped = host.stop().await?;
    let id = current["params"]["turn_id"].as_str().ok_or("turn")?;
    assert_eq!(stopped.host.engine.active.get("thread").map(String::as_str), Some(id));
    assert!(stopped.host.engine.state.turns.values().all(|t| t.message != "old-message"));
    drop(data);
    Ok(())
}
#[tokio::test]
async fn bridge_restored_packet_never_answers_a_previous_connection_rpc() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    host.data.lock().map_err(|_| "data")?.fail_reply = Some(());
    let mut p = params(&input, "held-reply");
    p["final"] = json!(true);
    p["text"] = json!("recovered");
    let mut bytes = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"prx-held-old","method":"reply.text","params":p}),
    )?;
    bytes.push(b'\n');
    server.raw(bytes).await?;
    let data = Arc::clone(&host.data);
    let stopped = host.transport_failure().await?;
    let checkpoint = stopped.host.state.engine.as_ref().ok_or("checkpoint")?;
    assert_eq!(checkpoint["packet"]["rpc_id"], "prx-held-old");
    assert!(checkpoint["packet"].get("rpc_generation").is_none());
    data.lock().map_err(|_| "data")?.bus_down = false;
    data.lock().map_err(|_| "data")?.fail_reply = None;
    let after = server.calls.lock().map_err(|_| "calls")?.len();
    let host = Host::resume(stopped, data).await?;
    server.wait_method("bridge.hello", after).await?;
    let mut p = params(&input, "new-connection-barrier");
    p["on"] = json!(true);
    server.call("reply.typing", p).await?;
    assert!(
        !server.calls.lock().map_err(|_| "calls")?[after..]
            .iter()
            .any(|r| r["id"] == "prx-held-old"),
        "stale RPC id was answered on a new connection"
    );
    host.stop().await?;
    Ok(())
}
#[tokio::test]
async fn bridge_stream_json_escaping_stays_within_canonical_snapshot_limit() -> TestResult {
    let (_root, server, mut host) = fixture().await?;
    let input = host.input(&server, "message-1").await?;
    let text = "\"\n😀".repeat(2500);
    let mut p = params(&input, "escaped");
    p["op"] = json!("stream_append");
    p["version"] = json!(1);
    p["text_delta"] = json!(text);
    server.call("reply.surface", p).await?;
    let mut p = params(&input, "close");
    p["op"] = json!("close");
    p["version"] = json!(2);
    p["fallback_text"] = json!(text);
    server.call("reply.surface", p).await?;
    finish(&server, &input, &text).await?;
    {
        let data = host.data.lock().map_err(|_| "data")?;
        assert!(
            data.surface_states.len() >= 2,
            "escaped data must roll before canonical JSON fills"
        );
        for state in data.surface_states.values() {
            assert!(state.is_closed());
            assert!(
                ramflux_protocol::canonical_json_bytes(state.content().ok_or("snapshot")?)?.len()
                    <= ramflux_protocol::MAX_SURFACE_DATA_BYTES
            );
        }
        let actual = data
            .surface_states
            .values()
            .map(|s| s.content().and_then(|s| s.components[0]["text"].as_str()).map_or(0, str::len))
            .sum::<usize>();
        assert_eq!(actual, text.len());
    }
    host.stop().await?;
    Ok(())
}

#[tokio::test]
async fn bridge_http_pending_visible_failure_is_sent_after_bus_reconnect() -> TestResult {
    http_visible_failure().await
}
