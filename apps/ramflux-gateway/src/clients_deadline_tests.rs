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

/// A TLS-complete router that reads the request, reports it, then stays silent until the client
/// closes its socket. Only the caller's deadline can end a request against it.
fn silent_router(
    server_tls: &ramflux_transport::MeshTlsConfig,
    trusted_gateway_ca: String,
) -> Result<(String, tokio::sync::mpsc::UnboundedReceiver<()>), Box<dyn std::error::Error>> {
    use std::io::Read;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", server_tls)?;
    let endpoint = server.local_addr()?.to_string();
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let mut buffer = [0_u8; 256];
        while matches!(stream.read(&mut buffer), Ok(read) if read > 0) {}
    });
    Ok((endpoint, seen_rx))
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
}

fn fixture(name: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = temp_cert_root(name)?;
    let gateway = issue_test_ca_and_service_cert(&root, "node-deadline", "ramflux-gateway")?;
    let router = issue_test_ca_and_service_cert(&root, "node-deadline", "ramflux-router")?;
    let (endpoint, seen) = silent_router(&router.tls, gateway.ca_pem.clone())?;
    let gateway_tls = ramflux_transport::MeshTlsConfig {
        ca_cert: router.tls.ca_cert.clone(),
        service_cert: gateway.tls.service_cert.clone(),
        service_key: gateway.tls.service_key.clone(),
    };
    Ok(Fixture { root, router, gateway_tls, endpoint, seen })
}

fn runtime() -> Result<tokio::runtime::Runtime, Box<dyn std::error::Error>> {
    Ok(tokio::runtime::Builder::new_current_thread().enable_all().build()?)
}

#[test]
fn async_disabled_gateway_path_stops_at_the_caller_deadline() -> TestResult {
    let fixture = fixture("gateway_deadline_async_disabled")?;
    let client = router_for(&fixture.endpoint, None, &fixture.router.ca_pem, &fixture.gateway_tls);
    let mut seen = fixture.seen;
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = run_with_hang_guard("async-disabled router POST", move || {
        runtime()
            .map_err(|error| error.to_string())?
            .block_on(router_post_json_until::<_, serde_json::Value>(
                &client,
                "/mvp1/identity/register",
                &serde_json::json!({"probe": true}),
                deadline,
            ))
            .map_err(|error| format!("{error:?}"))
    })?;
    let Err(error) = result else {
        return Err("a silent router must not complete the request".into());
    };
    assert!(error.contains("TimedOut"), "expected the caller deadline to fire, got {error}");
    assert!(seen.try_recv().is_ok(), "the request never reached the router");
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn failed_quic_fallback_shares_the_callers_single_deadline() -> TestResult {
    // QUIC goes to a UDP socket that never answers, so it spends real time before failing; the
    // fallback must then get only what is left of the caller's bound, not a fresh budget.
    let silent_quic = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let fixture = fixture("gateway_deadline_failed_quic")?;
    let client = router_for(
        &fixture.endpoint,
        Some(silent_quic.local_addr()?.to_string()),
        &fixture.router.ca_pem,
        &fixture.gateway_tls,
    );
    let mut seen = fixture.seen;
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = run_with_hang_guard("failed-QUIC fallback", move || {
        let outcome =
            runtime().map_err(|error| error.to_string())?.block_on(router_post_json_until::<
                _,
                serde_json::Value,
            >(
                &client,
                "/mvp1/identity/register",
                &serde_json::json!({"probe": true}),
                deadline,
            ));
        Ok::<_, String>(outcome.err().map(|error| is_deadline_timeout(&error)))
    })??;
    assert_eq!(result, Some(true), "the fallback must end with the caller deadline timeout");
    assert!(seen.try_recv().is_ok(), "the fallback never reached the router");
    drop(silent_quic);
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn admission_is_released_only_after_the_blocking_worker_exits() -> TestResult {
    let fixture = fixture("gateway_deadline_admission")?;
    let client = router_for(&fixture.endpoint, None, &fixture.router.ca_pem, &fixture.gateway_tls);
    let mut seen = fixture.seen;
    let (released_tx, released_rx) = std::sync::mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(5);
    let released_before_exit = run_with_hang_guard("admission ownership probe", move || {
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
        // The worker ends at the deadline and only then drops its admission.
        let released = released_rx.recv_timeout(HANG_GUARD).is_ok();
        drop(runtime);
        Ok::<_, String>((still_held, released))
    })??;
    assert!(released_before_exit.0, "admission was released while the worker was still running");
    assert!(released_before_exit.1, "admission was never released after the worker exited");
    std::fs::remove_dir_all(fixture.root)?;
    Ok(())
}
