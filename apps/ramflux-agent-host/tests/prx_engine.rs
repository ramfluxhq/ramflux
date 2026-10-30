// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use ramflux_agent_host::{
    ConversationInput, EngineEvent, EngineInput, EngineProvider, Error, Intent, PrxConfig,
    PrxEngine, PrxSessionScope,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, os::unix::fs::PermissionsExt, sync::Arc};
use tokio::sync::Mutex;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Step {
    method: hyper::Method,
    path: &'static str,
    status: StatusCode,
    body: Value,
    delay_ms: u64,
}

struct FakePrx {
    base_url: String,
    seen: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakePrx {
    async fn start(steps: Vec<Step>) -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let server_steps = Arc::clone(&steps);
        let server_seen = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let steps = Arc::clone(&server_steps);
                let seen = Arc::clone(&server_seen);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let steps = Arc::clone(&steps);
                        let seen = Arc::clone(&seen);
                        async move {
                            let path = request
                                .uri()
                                .path_and_query()
                                .map_or_else(String::new, ToString::to_string);
                            let authorization = request
                                .headers()
                                .get("authorization")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            seen.lock()
                                .await
                                .push(format!("{} {path} {authorization}", request.method()));
                            let Some(step) = steps.lock().await.pop_front() else {
                                return Ok::<_, hyper::Error>(json_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &json!({"error":"unexpected request"}),
                                ));
                            };
                            if request.method() != step.method
                                || path != step.path
                                || authorization != "Bearer test-prx-token"
                            {
                                return Ok(json_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &json!({"error":"request mismatch"}),
                                ));
                            }
                            if step.delay_ms > 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(step.delay_ms))
                                    .await;
                            }
                            Ok(json_response(step.status, &step.body))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Ok(Self { base_url: format!("http://{address}/"), seen, task })
    }

    async fn seen(&self) -> Vec<String> {
        self.seen.lock().await.clone()
    }
}

impl Drop for FakePrx {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap_or_default())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn step(method: hyper::Method, path: &'static str, status: StatusCode, body: Value) -> Step {
    Step { method, path, status, body, delay_ms: 0 }
}

fn accepted(id: &str) -> Value {
    json!({
        "status":"accepted",
        "job_id":id,
        "poll_url":format!("/api/jobs/{id}"),
        "cancel_url":format!("/api/jobs/{id}/cancel")
    })
}

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
    assert!(server.seen().await.iter().all(|line| line.contains("Bearer test-prx-token")));
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
        matches!(approval.as_slice(), [EngineEvent::ApprovalRequired { decision_id, pending_tool, .. }]
        if decision_id == "decision-1" && pending_tool == "filesystem.write")
    );
    engine.acknowledge(&approval[0])?;
    engine.decide("conversation", "message", "decision-1", true).await?;
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
        step(hyper::Method::DELETE, "/api/sessions/session-1/approvals/decision-1", StatusCode::OK, json!({"approved":false})),
    ])
    .await?;
    let (_root, mut engine) = engine(&server, 2)?;
    submit(&mut engine).await?;
    let approval = engine.poll(2).await?;
    engine.acknowledge(&approval[0])?;
    engine.decide("conversation", "message", "decision-1", false).await?;
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
        server.seen().await.iter().filter(|line| line.contains("POST /api/sessions ")).count(),
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
