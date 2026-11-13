// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The router POST fallback honours the caller's absolute deadline and keeps admission until
//! its blocking worker has actually exited.
use std::time::{Duration, Instant};

use super::tests::{issue_test_ca_and_service_cert, temp_cert_root};
use super::*;

const HANG_GUARD: Duration = Duration::from_secs(10);

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Dropped by the blocking worker as it exits; the receiver observes the release.
struct ReleaseSignal(std::sync::mpsc::Sender<()>);

impl Drop for ReleaseSignal {
    fn drop(&mut self) {
        let _ignored = self.0.send(());
    }
}

type SilentRouter = (String, tokio::sync::mpsc::UnboundedReceiver<()>, std::sync::mpsc::Sender<()>);

/// A TLS-complete router that reads the request, reports it, then stays silent until the test
/// sends (or drops) the release sender, at which point it closes the connection.
fn silent_router(
    server_tls: &ramflux_transport::MeshTlsConfig,
    trusted_gateway_ca: String,
) -> Result<SilentRouter, Box<dyn std::error::Error>> {
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", server_tls)?;
    let endpoint = server.local_addr()?.to_string();
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let tls = server_tls.clone();
    std::thread::spawn(move || {
        let Ok(accepted) = server.accept_authenticated_with_pem_roots(&tls, &[trusted_gateway_ca])
        else {
            return;
        };
        let mut stream = accepted.stream;
        if !matches!(ramflux_transport::read_mesh_http_request(&mut stream), Ok(Some(_))) {
            return;
        }
        let _ignored = seen_tx.send(());
        let _ignored = release_rx.recv();
        drop(stream);
    });
    Ok((endpoint, seen_rx, release))
}

fn router_for(
    router_endpoint: &str,
    quic_endpoint: Option<String>,
    router_ca: &str,
    gateway_tls: &ramflux_transport::MeshTlsConfig,
) -> RouterMeshClient {
    RouterMeshClient {
        endpoint: router_endpoint.to_owned(),
        server_name: "ramflux-router".to_owned(),
        tls: gateway_tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: quic_endpoint.map(|endpoint| RouterAsyncMeshClient {
            endpoint,
            server_name: "ramflux-router".to_owned(),
            tls: gateway_tls.clone(),
            peer_ca_pems: vec![router_ca.to_owned()],
        }),
    }
}

fn run_with_hang_guard<T: Send + 'static>(
    what: &'static str,
    call: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Box<dyn std::error::Error>> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ignored = done_tx.send(call());
    });
    done_rx
        .recv_timeout(HANG_GUARD)
        .map_err(|_| format!("hang guard: {what} did not return within {HANG_GUARD:?}").into())
}

fn is_deadline_timeout(error: &ramflux_transport::TransportError) -> bool {
    matches!(error, ramflux_transport::TransportError::Io(source)
        if source.kind() == std::io::ErrorKind::TimedOut)
}

struct Fixture {
    root: std::path::PathBuf,
    router: super::tests::TestPeerCerts,
    gateway_tls: ramflux_transport::MeshTlsConfig,
    endpoint: String,
    seen: tokio::sync::mpsc::UnboundedReceiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

fn fixture(name: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = temp_cert_root(name)?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-deadline", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&root, "node-deadline", "ramflux-router")?;
    let (endpoint, seen, release) = silent_router(&router.tls, gateway.ca_pem.clone())?;
    let gateway_tls = ramflux_transport::MeshTlsConfig {
        ca_cert: router.tls.ca_cert.clone(),
        service_cert: gateway.tls.service_cert.clone(),
        service_key: gateway.tls.service_key.clone(),
    };
    Ok(Fixture { root, router, gateway_tls, endpoint, seen, release })
}

fn runtime() -> Result<tokio::runtime::Runtime, Box<dyn std::error::Error>> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

/// Records the deadline handed to a stage.
type Recorded = std::sync::Arc<std::sync::Mutex<Vec<Instant>>>;

fn record(recorded: &Recorded, deadline: Instant) {
    if let Ok(mut seen) = recorded.lock() {
        seen.push(deadline);
    }
}

fn recorded(recorded: &Recorded) -> Vec<Instant> {
    recorded.lock().map(|seen| seen.clone()).unwrap_or_default()
}

fn quic_failure() -> ramflux_transport::TransportError {
    ramflux_transport::TransportError::Quic("injected QUIC failure".to_owned())
}

#[tokio::test(start_paused = true)]
async fn failed_quic_fallback_receives_the_callers_original_deadline() -> TestResult {
    // Virtual time: QUIC burns three seconds before failing. A fallback given a fresh budget
    // (for example a new five seconds) would be handed a different absolute deadline.
    let deadline = Instant::now() + Duration::from_secs(5);
    let quic_seen = Recorded::default();
    let fallback_seen = Recorded::default();
    let (quic_log, fallback_log) = (quic_seen.clone(), fallback_seen.clone());
    let result: Result<(), _> = post_quic_then_fallback(
        deadline,
        Some(move |stage_deadline| async move {
            record(&quic_log, stage_deadline);
            tokio::time::sleep(Duration::from_secs(3)).await;
            Err(quic_failure())
        }),
        move |stage_deadline| async move {
            record(&fallback_log, stage_deadline);
            Err(deadline_exceeded())
        },
    )
    .await;
    assert_eq!(recorded(&quic_seen), vec![deadline], "QUIC stage deadline");
    assert_eq!(recorded(&fallback_seen), vec![deadline], "fallback stage deadline");
    assert!(
        matches!(&result, Err(error) if is_deadline_timeout(error)),
        "expected the typed deadline timeout, got {result:?}"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn quic_stage_is_cut_off_at_the_deadline_without_starting_the_fallback() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    let fallback_seen = Recorded::default();
    let fallback_log = fallback_seen.clone();
    let result: Result<(), _> = post_quic_then_fallback(
        deadline,
        Some(|_stage_deadline| async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Err(quic_failure())
        }),
        move |stage_deadline| async move {
            record(&fallback_log, stage_deadline);
            Ok(())
        },
    )
    .await;
    assert!(
        matches!(&result, Err(error) if is_deadline_timeout(error)),
        "expected the typed deadline timeout, got {result:?}"
    );
    assert!(recorded(&fallback_seen).is_empty(), "fallback must not start after the deadline");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn async_disabled_path_runs_only_the_fallback_with_the_original_deadline() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    let fallback_seen = Recorded::default();
    let fallback_log = fallback_seen.clone();
    let result: Result<u8, _> = post_quic_then_fallback(
        deadline,
        None::<fn(Instant) -> std::future::Ready<Result<u8, ramflux_transport::TransportError>>>,
        move |stage_deadline| async move {
            record(&fallback_log, stage_deadline);
            Ok(7)
        },
    )
    .await;
    assert!(matches!(result, Ok(7)));
    assert_eq!(recorded(&fallback_seen), vec![deadline]);
    Ok(())
}

#[test]
fn blocking_worker_ends_with_the_typed_deadline_timeout_against_a_silent_router() -> TestResult {
    // Real sockets, one short deadline: the worker must end with the exact typed timeout, and
    // only after the router has read the request (so the response-read stage was reached).
    let fixture = fixture("gateway_deadline_real_socket")?;
    let client = router_for(&fixture.endpoint, None, &fixture.router.ca_pem, &fixture.gateway_tls);
    let mut seen = fixture.seen;
    let deadline = Instant::now() + Duration::from_secs(1);
    let result = run_with_hang_guard("blocking worker against a silent router", move || {
        runtime()
            .map_err(|error| error.to_string())?
            .block_on(router_post_json_until::<_, serde_json::Value>(
                &client,
                "/mvp1/identity/register",
                &serde_json::json!({"probe": true}),
                deadline,
            ))
            .map_err(|error| is_deadline_timeout(&error))
            .map_or_else(Ok, |_| Err("a silent router answered".to_owned()))
    })??;
    assert!(result, "expected the exact typed deadline timeout");
    assert!(seen.try_recv().is_ok(), "the request never reached the router");
    drop(fixture.release);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn admission_is_released_only_after_the_blocking_worker_exits() -> TestResult {
    let fixture = fixture("gateway_deadline_admission")?;
    let client = router_for(&fixture.endpoint, None, &fixture.router.ca_pem, &fixture.gateway_tls);
    let mut seen = fixture.seen;
    let release = fixture.release;
    let (released_tx, released_rx) = std::sync::mpsc::channel();
    // Far deadline: the worker is ended by the router closing, not by a timer.
    let deadline = Instant::now() + Duration::from_secs(60);
    let outcome = run_with_hang_guard("admission ownership probe", move || {
        let runtime = runtime().map_err(|error| error.to_string())?;
        let still_held = runtime.block_on(async {
            let body = serde_json::json!({"probe": true});
            let mut call = Box::pin(router_post_json_blocking_owned(
                &client,
                "/mvp1/identity/register",
                &body,
                deadline,
                ReleaseSignal(released_tx),
            ));
            tokio::select! {
                _ = call.as_mut() => return Err("the silent router answered".to_owned()),
                _ = seen.recv() => {}
            }
            // The router holds the request, so the worker is mid-flight. Drop the caller now.
            drop(call);
            Ok(released_rx.try_recv().is_err())
        })?;
        // Closing the router connection ends the worker, which then drops its admission.
        drop(release);
        let released = released_rx.recv_timeout(HANG_GUARD).is_ok();
        drop(runtime);
        Ok::<_, String>((still_held, released))
    })??;
    assert!(outcome.0, "admission was released while the worker was still running");
    assert!(outcome.1, "admission was never released after the worker exited");
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}
