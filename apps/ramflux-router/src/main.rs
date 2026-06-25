// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
mod handlers;
mod lifecycle;
mod router_engine;
mod router_runtime;
mod serve;

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
mod glommio_mesh;
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
mod glommio_runtime;

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::net::TcpStream;
use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
use std::time::Duration;

#[cfg(feature = "itest-http")]
use serve::serve_itest_http;
use serve::serve_router_mesh_mtls;

fn main() {
    if let Err(error) = run_service("ramflux-router") {
        eprintln!("ramflux-router: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    if std::env::args().any(|arg| arg == "--mesh-health-smoke") {
        let _ = tracing_subscriber::fmt().with_target(false).try_init();
        return run_mesh_health_smoke(service);
    }
    if std::env::args().any(|arg| arg == "--glommio-smoke") {
        return run_glommio_smoke();
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::RouterRedbStore::open(redb_path)?;
        let router = match store.load_router()? {
            Some(router) => router,
            None => ramflux_node_core::RouterCore::new(),
        };
        tracing::info!(service, node_id = config.node_id, "router store initialized");
        let state = Arc::new(router);
        let store = Arc::new(store);
        let router = Arc::new(router_handle_from_env(state, store)?);
        serve_router_mesh_from_env(&config, &router)?;
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").as_deref() == Ok("1") {
            return serve_itest_http(&router);
        }
        if std::env::args().any(|arg| arg == "--once") {
            return Ok(());
        }
        std::thread::park();
        return Ok(());
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    std::thread::park();
    Ok(())
}

fn run_mesh_health_smoke(service: &'static str) -> anyhow::Result<()> {
    let args = std::env::args().skip(1).filter(|arg| arg != "--mesh-health-smoke");
    let Some(config) = ramflux_node_core::load_config_from_args(args, service)? else {
        anyhow::bail!("--mesh-health-smoke requires --config");
    };
    #[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
    {
        return run_mesh_health_smoke_with_config(config);
    }
    #[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
    {
        run_mesh_health_smoke_with_config(&config)
    }
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn run_mesh_health_smoke_with_config(
    config: ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<()> {
    let mut server_config = config.clone();
    server_config.mesh.listen_addr = "127.0.0.1:0".to_owned();
    server_config.mesh.allowed_service_ids.insert(server_config.service_id.clone());
    let smoke_redb = std::env::temp_dir()
        .join(format!("ramflux-router-mesh-health-smoke-{}.redb", std::process::id()));
    let _ = std::fs::remove_file(&smoke_redb);
    server_config.redb_path = smoke_redb.to_string_lossy().into_owned();
    let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&server_config.redb_path)?);
    let router = Arc::new(router_runtime::RouterHandle::tokio(
        Arc::new(ramflux_node_core::RouterCore::new()),
        Arc::clone(&store),
    ));
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    glommio_mesh::serve_router_mesh_glommio_mtls_with_ready(
        &server_config,
        &router,
        Some(ready_tx),
        true,
    )?;
    let endpoint = ready_rx.recv_timeout(Duration::from_secs(5)).map_err(|error| {
        anyhow::anyhow!("glommio mesh health smoke server did not become ready: {error}")
    })??;
    run_mesh_health_smoke_client_clean_close(&config, &endpoint)
}

#[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
fn run_mesh_health_smoke_with_config(
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<()> {
    let endpoint = std::env::var("RAMFLUX_ROUTER_MESH_HEALTH_ENDPOINT")
        .ok()
        .or_else(|| config.mesh.endpoints.get("router").cloned())
        .unwrap_or_else(|| config.mesh.listen_addr.clone());
    run_mesh_health_smoke_client(config, &endpoint)
}

#[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
fn run_mesh_health_smoke_client(
    config: &ramflux_node_core::NodeServiceConfig,
    endpoint: &str,
) -> anyhow::Result<()> {
    let server_name = std::env::var("RAMFLUX_ROUTER_MESH_HEALTH_SERVER_NAME")
        .unwrap_or_else(|_| "ramflux-router".to_owned());
    let tls = serve::mesh_tls_config(config);
    let client = ramflux_transport::MeshHttpClient::new();
    for request_index in 0..2 {
        let response: serde_json::Value =
            client.get_json(endpoint, "/healthz", &tls, &server_name)?;
        if response.get("service").and_then(serde_json::Value::as_str) != Some("ramflux-router") {
            anyhow::bail!("unexpected router mesh health response {request_index}: {response}");
        }
        if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
            anyhow::bail!("router mesh health response {request_index} is not ok: {response}");
        }
    }
    println!("ramflux-router:mesh-health-smoke endpoint={endpoint} requests=2 status=ok");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn run_mesh_health_smoke_client_clean_close(
    config: &ramflux_node_core::NodeServiceConfig,
    endpoint: &str,
) -> anyhow::Result<()> {
    let server_name = std::env::var("RAMFLUX_ROUTER_MESH_HEALTH_SERVER_NAME")
        .unwrap_or_else(|_| "ramflux-router".to_owned());
    let tls = serve::mesh_tls_config(config);
    let tcp = TcpStream::connect(endpoint)?;
    tcp.set_nodelay(true)?;
    let client_config = mesh_smoke_client_config(&tls)?;
    let server_name = rustls::pki_types::ServerName::try_from(server_name.clone())?;
    let connection = rustls::ClientConnection::new(Arc::new(client_config), server_name)?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad smoke endpoint {endpoint}: missing port"))?;
    let request = format!(
        "GET /healthz HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n"
    );
    let mut responses = Vec::with_capacity(2);
    for _ in 0..2 {
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut reader = BufReader::new(&mut stream);
        responses.push(read_smoke_http_json_response(&mut reader)?);
    }
    let mut eof_probe = [0_u8; 1];
    match stream.read(&mut eof_probe) {
        Ok(0) => {}
        Ok(read) => anyhow::bail!(
            "router mesh health server sent {read} unexpected plaintext byte(s) after close"
        ),
        Err(error) => return Err(error.into()),
    }
    for (request_index, response) in responses.into_iter().enumerate() {
        if response.get("service").and_then(serde_json::Value::as_str) != Some("ramflux-router") {
            anyhow::bail!("unexpected router mesh health response {request_index}: {response}");
        }
        if response.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
            anyhow::bail!("router mesh health response {request_index} is not ok: {response}");
        }
    }
    println!("ramflux-router:mesh-health-smoke endpoint={endpoint} requests=2 status=ok");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn mesh_smoke_client_config(
    tls: &ramflux_transport::MeshTlsConfig,
) -> anyhow::Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(&tls.ca_cert)?)) {
        roots.add(cert?)?;
    }
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(&tls.service_cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(&tls.service_key)?))?
            .ok_or_else(|| anyhow::anyhow!("missing mesh smoke client private key"))?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?)
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn read_smoke_http_json_response<R: BufRead>(reader: &mut R) -> anyhow::Result<serde_json::Value> {
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().ok_or_else(|| anyhow::anyhow!("missing HTTP version"))?;
    let status = parts.next().ok_or_else(|| anyhow::anyhow!("missing HTTP status code"))?;
    if status != "200" {
        anyhow::bail!("unexpected router mesh health HTTP status {status}");
    }
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }
    let content_length = content_length.ok_or_else(|| anyhow::anyhow!("missing content length"))?;
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn serve_router_mesh_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    // Frozen diagnostic runtime: default production and itest shipping path is
    // tokio; new runtime work follows the compio federation migration plan.
    if std::env::var("RAMFLUX_ROUTER_RUNTIME").as_deref() == Ok("glommio") {
        tracing::info!("router mesh runtime selected: glommio mTLS");
        return glommio_mesh::serve_router_mesh_glommio_mtls(config, router);
    }
    serve_router_mesh_mtls(config, router)
}

#[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
fn serve_router_mesh_from_env(
    config: &ramflux_node_core::NodeServiceConfig,
    router: &Arc<router_runtime::RouterHandle>,
) -> anyhow::Result<()> {
    serve_router_mesh_mtls(config, router)
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn router_handle_from_env(
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
) -> anyhow::Result<router_runtime::RouterHandle> {
    // Frozen diagnostic runtime: do not extend this path for new hot-path work.
    if std::env::var("RAMFLUX_ROUTER_RUNTIME").as_deref() == Ok("glommio") {
        tracing::info!("router runtime selected: glommio");
        return router_runtime::RouterHandle::glommio(state, store);
    }
    tracing::info!("router runtime selected: tokio");
    Ok(router_runtime::RouterHandle::tokio(state, store))
}

#[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
fn router_handle_from_env(
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
) -> anyhow::Result<router_runtime::RouterHandle> {
    if std::env::var("RAMFLUX_ROUTER_RUNTIME").as_deref() == Ok("glommio") {
        anyhow::bail!("RAMFLUX_ROUTER_RUNTIME=glommio requires Linux with glommio-runtime enabled");
    }
    Ok(router_runtime::RouterHandle::tokio(state, store))
}

#[cfg(all(target_os = "linux", feature = "glommio-runtime"))]
fn run_glommio_smoke() -> anyhow::Result<()> {
    glommio_runtime::run_smoke_from_env()
}

#[cfg(not(all(target_os = "linux", feature = "glommio-runtime")))]
fn run_glommio_smoke() -> anyhow::Result<()> {
    anyhow::bail!("glommio smoke requires Linux with the glommio-runtime feature enabled")
}
