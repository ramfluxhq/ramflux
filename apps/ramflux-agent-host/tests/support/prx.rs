// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Route-keyed fake PRX server shared by adapter and host approval tests.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Arc};
use tokio::sync::Mutex;

pub type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
pub struct Step {
    pub method: hyper::Method,
    pub path: &'static str,
    pub status: StatusCode,
    pub body: Value,
    pub delay_ms: u64,
}

pub struct FakePrx {
    pub base_url: String,
    seen: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakePrx {
    pub async fn start(steps: Vec<Step>) -> TestResult<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let server_seen = Arc::clone(&seen);
        let server_bodies = Arc::clone(&bodies);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let steps = Arc::clone(&steps);
                let seen = Arc::clone(&server_seen);
                let bodies = Arc::clone(&server_bodies);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let steps = Arc::clone(&steps);
                        let seen = Arc::clone(&seen);
                        let bodies = Arc::clone(&bodies);
                        async move {
                            let path = request
                                .uri()
                                .path_and_query()
                                .map_or_else(String::new, ToString::to_string);
                            let method = request.method().clone();
                            let authorized = request
                                .headers()
                                .get("authorization")
                                .is_some_and(|v| v == "Bearer test-prx-token");
                            seen.lock().await.push(format!("{method} {path}"));
                            let body = request.into_body().collect().await?.to_bytes();
                            bodies
                                .lock()
                                .await
                                .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
                            let mut routes = steps.lock().await;
                            let step = routes
                                .iter()
                                .position(|s| s.method == method && s.path == path)
                                .and_then(|i| routes.remove(i));
                            drop(routes);
                            let Some(step) = step.filter(|_| authorized) else {
                                return Ok::<_, hyper::Error>(json_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    &json!({"error":"unexpected request"}),
                                ));
                            };
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
        Ok(Self { base_url: format!("http://{address}/"), seen, bodies, task })
    }

    pub async fn seen(&self) -> Vec<String> {
        self.seen.lock().await.clone()
    }
    pub async fn bodies(&self) -> Vec<Value> {
        self.bodies.lock().await.clone()
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
        .body(Full::new(Bytes::from(serde_json::to_vec(body).unwrap_or_default())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

pub fn step(method: hyper::Method, path: &'static str, status: StatusCode, body: Value) -> Step {
    Step { method, path, status, body, delay_ms: 0 }
}

pub fn accepted(id: &str) -> Value {
    json!({"status":"accepted","job_id":id,"poll_url":format!("/api/jobs/{id}"),"cancel_url":format!("/api/jobs/{id}/cancel")})
}

pub fn approval_view(decision: &str, expiry: &str) -> Value {
    json!({"decision_id":decision,"tool":"filesystem.write","arguments":{"path":"report.txt","token":"[REDACTED]"},"effect":"file_write","call_digest":"abc123","pending_expires_at":expiry,"single_use":true})
}

pub fn approval_steps(expiry: &str) -> Vec<Step> {
    vec![
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
            json!({"status":"succeeded","http_status":200,"result":{"status":"awaiting_approval","reply":"Approve harmless `read_file`?","decision_id":"decision-1"}}),
        ),
        step(
            hyper::Method::GET,
            "/api/sessions/session-1/approvals/decision-1",
            StatusCode::OK,
            approval_view("decision-1", expiry),
        ),
    ]
}
