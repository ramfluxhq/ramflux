// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use std::{io::Write, net::SocketAddr, path::Path};

fn start_post(address: SocketAddr, path: &str, body: &[u8]) -> anyhow::Result<TcpStream> {
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    client.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        client,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    client.write_all(body)?;
    Ok(client)
}

fn finish(mut client: TcpStream, status: &str) -> anyhow::Result<()> {
    let mut response = String::new();
    (&mut client).take(65537).read_to_string(&mut response)?;
    anyhow::ensure!(response.len() <= 65536, "test: HTTP response exceeded bound");
    anyhow::ensure!(response.starts_with(status), "test: unexpected route response: {response}");
    Ok(())
}

fn router(
    directory: &Path,
) -> anyhow::Result<(RouterMeshClient, ramflux_transport::MeshTlsServer)> {
    let certificate = rcgen::generate_simple_self_signed(vec![
        "ramflux-router".into(),
        "ramflux-gateway".into(),
    ])?;
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: directory.join("ca.pem"),
        service_cert: directory.join("service.pem"),
        service_key: directory.join("service.key"),
    };
    std::fs::write(&tls.ca_cert, certificate.cert.pem())?;
    std::fs::write(&tls.service_cert, certificate.cert.pem())?;
    std::fs::write(&tls.service_key, certificate.signing_key.serialize_pem())?;
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &tls)?;
    Ok((
        RouterMeshClient {
            endpoint: server.local_addr()?.to_string(),
            server_name: "ramflux-router".into(),
            tls,
            client: ramflux_transport::MeshHttpClient::new(),
            async_mesh: None,
        },
        server,
    ))
}

#[tokio::test]
async fn real_policy_routes_share_and_release_management_slot() -> anyhow::Result<()> {
    const CHILD: &str = "RAMFLUX_TEST_MANAGEMENT_ROUTE_CHILD";
    if let Some(root) = std::env::var_os(CHILD) {
        return route_case(Path::new(&root));
    }
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("route.log");
    let log = std::fs::File::create(&path)?;
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "itest_http::tests::routes::real_policy_routes_share_and_release_management_slot",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(20), command.status()).await??;
    let mut logs = String::new();
    std::fs::File::open(path)?.take(65537).read_to_string(&mut logs)?;
    anyhow::ensure!(logs.len() <= 65536, "test: route child diagnostics exceeded bound");
    anyhow::ensure!(status.success(), "test: real route child failed: {logs}");
    Ok(())
}

fn route_case(root: &Path) -> anyhow::Result<()> {
    let directory = tempfile::TempDir::new_in(root)?;
    let _shutdown = ramflux_node_core::ServiceShutdown::install("gateway-policy-test")?;
    let (router, backend) = router(directory.path())?;
    let store =
        Arc::new(ramflux_node_core::GatewayRedbStore::open(directory.path().join("gateway.redb"))?);
    let mut initial = ramflux_node_core::GatewayState::new();
    let now = initial.observe_pre_auth_time(std::time::SystemTime::now())?;
    let checkpoint = initial.admission_checkpoint(now);
    store.save_state(&initial)?;
    store.save_admission_checkpoint(&checkpoint)?;
    initial.install_admission_checkpoint(&checkpoint);
    let state = Arc::new(Mutex::new(initial));
    let listener = bind_itest_listener("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (worker_store, worker_state) = (Arc::clone(&store), Arc::clone(&state));
    let service = std::thread::spawn(move || {
        serve_itest_http(&listener, &router, &worker_store, &worker_state, "gateway-test")
    });
    exercise_routes(address, &store, &state, backend)?;
    ramflux_node_core::service_shutdown_token().cancel();
    service.join().map_err(|_| anyhow::anyhow!("test: HTTP server panicked"))??;
    drop(store);
    let reopened =
        ramflux_node_core::GatewayRedbStore::open(directory.path().join("gateway.redb"))?;
    assert_eq!(
        reopened
            .load_state()?
            .ok_or_else(|| anyhow::anyhow!("test: policy absent"))?
            .pre_auth_policy()
            .per_source_ip_handshake_rate,
        1,
        "real HTTP policy must survive reopen"
    );
    Ok(())
}

fn exercise_routes(
    address: SocketAddr,
    store: &Arc<ramflux_node_core::GatewayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::GatewayState>>,
    backend: ramflux_transport::MeshTlsServer,
) -> anyhow::Result<()> {
    let preauth = serde_json::to_vec(&ramflux_node_core::GatewayPreAuthConfig {
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    })?;
    let registration = serde_json::to_vec(&ramflux_node_core::RegistrationPolicy::default())?;
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, waiting) = std::sync::mpsc::sync_channel(1);
    store.pause_next_admission_commit_bounded(entered, waiting)?;
    let first = start_post(address, "/mvp6/preauth/policy", &preauth)?;
    observed.recv_timeout(Duration::from_secs(5))?;
    finish(start_post(address, "/mvp6/registration/policy", &registration)?, "HTTP/1.1 503")?;
    let before = {
        let mut live =
            state.try_lock().map_err(|_| anyhow::anyhow!("test: HTTP commit held state lock"))?;
        live.record_slowloris_timeout();
        serde_json::to_value(live.pre_auth_metrics())?
    };
    release.send(())?;
    finish(first, "HTTP/1.1 200")?;
    assert_eq!(
        serde_json::to_value(gateway_state(state)?.pre_auth_metrics())?,
        before,
        "real route must preserve concurrent metrics"
    );
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let (release, waiting) = std::sync::mpsc::sync_channel(1);
    let backend = std::thread::spawn(move || -> anyhow::Result<()> {
        let mut stream = backend.accept()?;
        let request = ramflux_transport::read_mesh_http_request(&mut stream)?
            .ok_or_else(|| anyhow::anyhow!("test: missing router request"))?;
        anyhow::ensure!(request.path == "/mvp6/registration/policy", "test: wrong forwarded route");
        let policy: ramflux_node_core::RegistrationPolicy = serde_json::from_slice(&request.body)?;
        entered.send(())?;
        waiting.recv_timeout(Duration::from_secs(5))?;
        ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &policy)?;
        ramflux_transport::close_mesh_server_stream(&mut stream)?;
        Ok(())
    });
    let first = start_post(address, "/mvp6/registration/policy", &registration)?;
    observed.recv_timeout(Duration::from_secs(5))?;
    finish(start_post(address, "/mvp6/preauth/policy", &preauth)?, "HTTP/1.1 503")?;
    finish(start_post(address, "/mvp6/registration/policy", &registration)?, "HTTP/1.1 503")?;
    release.send(())?;
    finish(first, "HTTP/1.1 200")?;
    backend.join().map_err(|_| anyhow::anyhow!("test: router stub panicked"))??;
    finish(start_post(address, "/mvp6/registration/policy", b"{}")?, "HTTP/1.1 500")?;
    finish(start_post(address, "/mvp6/preauth/policy", &preauth)?, "HTTP/1.1 200")?;
    let _slot = store.try_admit_management_write()?;
    Ok(())
}
