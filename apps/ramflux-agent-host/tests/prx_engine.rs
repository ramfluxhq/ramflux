// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[path = "support/prx.rs"]
mod support;
use hyper::StatusCode;
use ramflux_agent_host::{
    ConversationInput, EngineEvent, EngineFailure, EngineInput, EngineProvider, Error, Intent,
    PrxAuthorization, PrxConfig, PrxEngine, PrxSessionScope,
};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use support::{FakePrx, Step, TestResult, accepted, approval_steps, approval_view, step};

fn engine(server: &FakePrx, timeout_s: u64) -> TestResult<(tempfile::TempDir, PrxEngine)> {
    let root = tempfile::tempdir()?;
    let token_file = root.path().join("prx.token");
    std::fs::write(&token_file, "test-prx-token\n")?;
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))?;
    let config = PrxConfig {
        base_url: server.base_url.clone(),
        token_file,
        session_scope: PrxSessionScope::PerConversation,
        request_timeout_s: timeout_s,
        max_in_flight_per_conversation: 1,
        authorization: PrxAuthorization::Supervised,
        turn_timeout_s: 120,
        approval_timeout_s: 600,
    };
    Ok((root, PrxEngine::new(&config, 8)?))
}

async fn submit(engine: &mut PrxEngine) -> ramflux_agent_host::Result<Vec<EngineEvent>> {
    engine
        .submit(
            EngineInput {
                conversation: ConversationInput {
                    conversation_id: "conversation",
                    message_id: "message",
                    text: "hello",
                },
                sender_display_name: "Human",
                chat_kind: "direct",
                mentioned: true,
            },
            1,
        )
        .await
}

#[tokio::test]
async fn ok_reply_strips_image_markers_and_checkpoint_has_no_token() -> TestResult {
    let server = FakePrx::start(vec![
        step(
            hyper::Method::POST,
            "/api/sessions",
            StatusCode::CREATED,
            json!({"session_id":"session-1"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/message?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-1"),
        ),
        step(
            hyper::Method::GET,
            "/api/jobs/job-1",
            StatusCode::OK,
            json!({
                "status":"succeeded","http_status":200,
                "result":{"status":"ok","reply":"answer [IMAGE:/private/result.png] complete"}
            }),
        ),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    assert!(
        matches!(submit(&mut engine).await?.as_slice(), [EngineEvent::Intents { intents, .. }] if intents.is_empty())
    );
    let events = engine.poll(2).await?;
    assert!(matches!(events.as_slice(), [EngineEvent::Intents { intents, .. }]
        if matches!(intents.as_slice(), [Intent::ReplyText(reply)] if reply == "answer  complete")));
    let checkpoint = serde_json::to_string(&engine.checkpoint()?)?;
    assert!(!checkpoint.contains("test-prx-token"));
    assert!(server.bodies().await.iter().any(|body| body["message"].as_str().is_some_and(|v| {
        v.starts_with("[Ramflux context: sender=Human; chat_kind=direct; mentioned=yes]")
    })));
    Ok(())
}

#[tokio::test]
async fn human_approval_resumes_as_another_detached_job() -> TestResult {
    let server = FakePrx::start(vec![
        step(hyper::Method::POST, "/api/sessions", StatusCode::CREATED, json!({"session_id":"session-1"})),
        step(hyper::Method::POST, "/api/sessions/session-1/message?mode=async", StatusCode::ACCEPTED, accepted("job-1")),
        step(hyper::Method::GET, "/api/jobs/job-1", StatusCode::OK, json!({
            "status":"succeeded","http_status":200,
            "result":{"status":"awaiting_approval","reply":"Approve tool `filesystem.write`?","decision_id":"decision-1"}
        })),
        step(hyper::Method::GET, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, approval_view("decision-1", "1970-01-01T00:05:00Z")),
        step(hyper::Method::POST, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, json!({"approved":true})),
        step(hyper::Method::POST, "/api/sessions/session-1/approvals/decision-1/resume?mode=async", StatusCode::ACCEPTED, accepted("job-2")),
        step(hyper::Method::GET, "/api/jobs/job-2", StatusCode::OK, json!({
            "status":"succeeded","http_status":200,"result":{"status":"ok","reply":"done"}
        })),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    submit(&mut engine).await?;
    let approval = engine.poll(2).await?;
    assert!(
        matches!(approval.as_slice(), [EngineEvent::ApprovalRequired { decision_id, approval, .. }]
        if decision_id == "decision-1" && approval.tool == "filesystem.write" && approval.deadline_ms == 300_000)
    );
    engine.acknowledge(&approval[0])?;
    engine.decide("conversation", "message", "decision-1", true, 2).await?;
    assert!(matches!(engine.poll(3).await?.as_slice(), [EngineEvent::Intents { intents, .. }]
        if matches!(intents.as_slice(), [Intent::ReplyText(reply)] if reply == "done")));
    Ok(())
}

#[tokio::test]
async fn decline_deletes_the_pending_prx_decision() -> TestResult {
    let server = FakePrx::start(vec![
        step(hyper::Method::POST, "/api/sessions", StatusCode::CREATED, json!({"session_id":"session-1"})),
        step(hyper::Method::POST, "/api/sessions/session-1/message?mode=async", StatusCode::ACCEPTED, accepted("job-1")),
        step(hyper::Method::GET, "/api/jobs/job-1", StatusCode::OK, json!({
            "status":"succeeded","http_status":200,
            "result":{"status":"awaiting_approval","reply":"Approve `shell`?","decision_id":"decision-1"}
        })),
        step(hyper::Method::GET, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, approval_view("decision-1", "1970-01-01T00:05:00Z")),
        step(hyper::Method::DELETE, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, json!({"approved":false})),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    submit(&mut engine).await?;
    let approval = engine.poll(2).await?;
    engine.acknowledge(&approval[0])?;
    engine.decide("conversation", "message", "decision-1", false, 2).await?;
    assert!(server.seen().await.iter().any(|line| line.starts_with("DELETE ")));
    Ok(())
}

#[tokio::test]
async fn conversation_removal_cancels_the_job() -> TestResult {
    let server = FakePrx::start(vec![
        step(
            hyper::Method::POST,
            "/api/sessions",
            StatusCode::CREATED,
            json!({"session_id":"session-1"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/message?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-1"),
        ),
        step(
            hyper::Method::POST,
            "/api/jobs/job-1/cancel",
            StatusCode::OK,
            json!({"job_id":"job-1"}),
        ),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    submit(&mut engine).await?;
    engine.cancel("conversation").await?;
    assert_eq!(engine.active_conversations(), Vec::<String>::new());
    assert!(server.seen().await.iter().any(|line| line.contains("/cancel")));
    Ok(())
}

#[tokio::test]
async fn missing_session_is_recreated_once() -> TestResult {
    let server = FakePrx::start(vec![
        step(
            hyper::Method::POST,
            "/api/sessions",
            StatusCode::CREATED,
            json!({"session_id":"session-old"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-old/message?mode=async",
            StatusCode::NOT_FOUND,
            json!({"error":"missing"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions",
            StatusCode::CREATED,
            json!({"session_id":"session-new"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-new/message?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-1"),
        ),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    submit(&mut engine).await?;
    assert_eq!(
        server.seen().await.iter().filter(|line| line.as_str() == "POST /api/sessions").count(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn request_timeout_is_a_typed_visible_failure_without_token_text() -> TestResult {
    let server = FakePrx::start(vec![Step {
        method: hyper::Method::POST,
        path: "/api/sessions",
        status: StatusCode::CREATED,
        body: json!({"session_id":"too-late"}),
        delay_ms: 1500,
    }])
    .await?;
    let (_root, mut engine) = engine(&server, 1)?;
    assert!(matches!(submit(&mut engine).await?.as_slice(), [EngineEvent::VisibleFailure { .. }]));
    let error = Error::EngineTimeout.to_string();
    assert!(!error.contains("test-prx-token"));
    Ok(())
}

#[tokio::test]
async fn detached_job_deadline_cancels_and_frees_the_conversation() -> TestResult {
    let server = FakePrx::start(vec![
        step(
            hyper::Method::POST,
            "/api/sessions",
            StatusCode::CREATED,
            json!({"session_id":"session-1"}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/message?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-1"),
        ),
        step(hyper::Method::GET, "/api/jobs/job-1", StatusCode::OK, json!({"status":"running"})),
        step(hyper::Method::GET, "/api/jobs/job-1", StatusCode::OK, json!({"status":"running"})),
        step(hyper::Method::POST, "/api/jobs/job-1/cancel", StatusCode::OK, json!({})),
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/message?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-2"),
        ),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 1)?;
    submit(&mut engine).await?;
    assert!(matches!(
        submit(&mut engine).await?.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::Busy, .. }]
    ));
    assert!(engine.poll(100).await?.is_empty());
    assert!(engine.poll(120_000).await?.is_empty());
    let events = engine.poll(120_001).await?;
    assert!(matches!(
        events.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::TurnTimeout, .. }]
    ));
    engine.acknowledge(&events[0])?;
    submit(&mut engine).await?;
    assert_eq!(server.seen().await.iter().filter(|r| r.ends_with("/cancel")).count(), 1);
    assert_eq!(server.seen().await.iter().filter(|r| r.contains("message?mode=async")).count(), 2);
    Ok(())
}

#[tokio::test]
async fn restart_restores_sessions_jobs_results_and_original_deadline() -> TestResult {
    let server = FakePrx::start(vec![
        step(hyper::Method::POST, "/api/sessions", StatusCode::CREATED, json!({"session_id":"session-1"})),
        step(hyper::Method::POST, "/api/sessions/session-1/message?mode=async", StatusCode::ACCEPTED, accepted("job-1")),
        step(hyper::Method::GET, "/api/jobs/job-1", StatusCode::OK, json!({"status":"succeeded","http_status":200,"result":{"status":"ok","reply":"restored reply"}})),
        step(hyper::Method::POST, "/api/sessions/session-1/message?mode=async", StatusCode::ACCEPTED, accepted("job-2")),
        step(hyper::Method::POST, "/api/jobs/job-2/cancel", StatusCode::OK, json!({})),
    ]).await?;
    let (_root, mut original) = engine(&server, 1)?;
    submit(&mut original).await?;
    let state = original.checkpoint()?;
    let (_root2, mut restored) = engine(&server, 1)?;
    restored.restore(state.as_ref())?;
    assert_eq!(
        restored.checkpoint()?.ok_or("state")?["jobs"]["conversation"]["deadline_ms"],
        120_001
    );
    let events = restored.poll(2).await?;
    let complete = restored.checkpoint()?;
    let (_root3, mut restored_again) = engine(&server, 1)?;
    restored_again.restore(complete.as_ref())?;
    assert!(events == restored_again.poll(3).await?);
    restored_again.acknowledge(&events[0])?;
    submit(&mut restored_again).await?;
    // A restored resume/job deadline never restarts when a process restarts.
    let deadline = restored_again.poll(120_001).await?;
    assert!(matches!(
        deadline.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::TurnTimeout, .. }]
    ));
    assert_eq!(
        server.seen().await.iter().filter(|s| s.as_str() == "POST /api/sessions").count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn pending_decision_holds_new_turns_and_removal_revokes_it() -> TestResult {
    let mut steps = approval_steps("1970-01-01T00:05:00Z");
    steps.push(step(
        hyper::Method::DELETE,
        "/api/sessions/session-1/approvals/decision-1",
        StatusCode::OK,
        json!({}),
    ));
    let server = FakePrx::start(steps).await?;
    let (_root, mut engine) = engine(&server, 1)?;
    submit(&mut engine).await?;
    let events = engine.poll(2).await?;
    assert!(
        matches!(events.as_slice(), [EngineEvent::ApprovalRequired { approval, .. }] if approval.tool == "filesystem.write")
    );
    engine.acknowledge(&events[0])?;
    let state = engine.checkpoint()?;
    engine.restore(state.as_ref())?;
    assert!(matches!(
        submit(&mut engine).await?.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::Busy, .. }]
    ));
    engine.cancel("conversation").await?;
    assert_eq!(engine.active_conversations(), Vec::<String>::new());
    assert!(server.seen().await.iter().any(|s| s.starts_with("DELETE ")));
    Ok(())
}

#[tokio::test]
async fn full_authorization_declines_unexpected_approvals_without_human_task() -> TestResult {
    let mut steps = approval_steps("1970-01-01T00:05:00Z");
    steps.push(step(
        hyper::Method::DELETE,
        "/api/sessions/session-1/approvals/decision-1",
        StatusCode::OK,
        json!({}),
    ));
    let server = FakePrx::start(steps).await?;
    let (root, _) = engine(&server, 1)?;
    let config: PrxConfig = serde_json::from_value(
        json!({"base_url":server.base_url,"token_file":root.path().join("prx.token"),"session_scope":"per_conversation","request_timeout_s":1,"max_in_flight_per_conversation":1,"authorization":"full"}),
    )?;
    assert_eq!(config.turn_timeout_s, 120);
    assert_eq!(config.approval_timeout_s, 600);
    let mut engine = PrxEngine::new(&config, 8)?;
    submit(&mut engine).await?;
    assert!(matches!(
        engine.poll(2).await?.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::AuthorizationMismatch, .. }]
    ));
    assert!(server.seen().await.iter().any(|s| s.starts_with("DELETE ")));
    assert!(
        !server.seen().await.iter().any(|s| s.contains("/approvals/") && s.starts_with("POST "))
    );
    Ok(())
}

#[tokio::test]
async fn failed_authoritative_view_never_prompts_from_the_llm_reply() -> TestResult {
    let mut steps = approval_steps("1970-01-01T00:05:00Z");
    if let Some(view) = steps.last_mut() {
        view.status = StatusCode::CONFLICT;
    }
    steps.push(step(
        hyper::Method::DELETE,
        "/api/sessions/session-1/approvals/decision-1",
        StatusCode::CONFLICT,
        json!({}),
    ));
    let server = FakePrx::start(steps).await?;
    let (_root, mut engine) = engine(&server, 1)?;
    submit(&mut engine).await?;
    assert!(matches!(
        engine.poll(2).await?.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::ApprovalUnavailable, .. }]
    ));
    Ok(())
}

#[tokio::test]
async fn resumed_job_has_its_own_bounded_turn_deadline() -> TestResult {
    let mut steps = approval_steps("1970-01-01T00:05:00Z");
    steps.extend([
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/approvals/decision-1",
            StatusCode::OK,
            json!({}),
        ),
        step(
            hyper::Method::POST,
            "/api/sessions/session-1/approvals/decision-1/resume?mode=async",
            StatusCode::ACCEPTED,
            accepted("job-2"),
        ),
        step(hyper::Method::GET, "/api/jobs/job-2", StatusCode::OK, json!({"status":"running"})),
        step(hyper::Method::POST, "/api/jobs/job-2/cancel", StatusCode::OK, json!({})),
    ]);
    let server = FakePrx::start(steps).await?;
    let (_root, mut engine) = engine(&server, 1)?;
    submit(&mut engine).await?;
    let events = engine.poll(2).await?;
    engine.acknowledge(&events[0])?;
    engine.decide("conversation", "message", "decision-1", true, 100).await?;
    assert!(engine.poll(120_099).await?.is_empty());
    assert!(matches!(
        engine.poll(120_100).await?.as_slice(),
        [EngineEvent::VisibleFailure { reason: EngineFailure::TurnTimeout, .. }]
    ));
    assert!(server.seen().await.iter().any(|s| s.ends_with("job-2/cancel")));
    Ok(())
}

#[tokio::test]
async fn absent_prx_expiry_uses_the_configured_bound() -> TestResult {
    let mut steps = approval_steps("1970-01-01T00:05:00Z");
    if let Some(view) = steps.last_mut() {
        view.body.as_object_mut().ok_or("view")?.remove("pending_expires_at");
    }
    let server = FakePrx::start(steps).await?;
    let (_root, mut engine) = engine(&server, 1)?;
    submit(&mut engine).await?;
    assert!(
        matches!(engine.poll(2).await?.as_slice(), [EngineEvent::ApprovalRequired {approval, ..}] if approval.deadline_ms == 600_002)
    );
    Ok(())
}

#[tokio::test]
async fn unavailable_prx_is_silent_and_logs_once_without_bearer_on_stderr() -> TestResult {
    if std::env::var_os("RAMFLUX_PRX_STDERR_CHILD").is_some() {
        let server = FakePrx::start(Vec::new()).await?;
        let (_root, mut engine) = engine(&server, 1)?;
        drop(server);
        tokio::task::yield_now().await;
        for _ in 0..4 {
            assert!(submit(&mut engine).await?.is_empty());
        }
        assert!(!serde_json::to_string(&engine.checkpoint()?)?.contains("test-prx-token"));
        let mut steps = approval_steps("1970-01-01T00:05:00Z");
        steps.extend([
            step(hyper::Method::DELETE, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, json!({})),
            step(hyper::Method::POST, "/api/sessions/session-1/message?mode=async", StatusCode::ACCEPTED, accepted("job-2")),
            step(hyper::Method::GET, "/api/jobs/job-2", StatusCode::OK, json!({"status":"succeeded","http_status":200,"result":{"status":"awaiting_approval","decision_id":"decision-2","reply":"test-prx-token"}})),
            step(hyper::Method::DELETE, "/api/sessions/session-1/approvals/decision-2", StatusCode::OK, json!({"error":"test-prx-token"})),
        ]);
        let server = FakePrx::start(steps).await?;
        let (root, _) = crate::engine(&server, 1)?;
        let config = PrxConfig {
            base_url: server.base_url.clone(),
            token_file: root.path().join("prx.token"),
            session_scope: PrxSessionScope::PerConversation,
            request_timeout_s: 1,
            max_in_flight_per_conversation: 1,
            authorization: PrxAuthorization::Full,
            turn_timeout_s: 120,
            approval_timeout_s: 600,
        };
        let mut full = PrxEngine::new(&config, 8)?;
        for now in [2, 3] {
            submit(&mut full).await?;
            let events = full.poll(now).await?;
            assert!(matches!(
                events.as_slice(),
                [EngineEvent::VisibleFailure { reason: EngineFailure::AuthorizationMismatch, .. }]
            ));
            full.acknowledge(&events[0])?;
        }
        return Ok(());
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "unavailable_prx_is_silent_and_logs_once_without_bearer_on_stderr",
            "--nocapture",
        ])
        .env("RAMFLUX_PRX_STDERR_CHILD", "1")
        .output()?;
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(stderr.matches("agent host PRX engine is unavailable").count(), 1);
    assert_eq!(stderr.matches("agent host PRX authorization mismatch").count(), 1);
    assert!(!stderr.contains("test-prx-token"));
    assert!(!String::from_utf8(output.stdout)?.contains("test-prx-token"));
    Ok(())
}
