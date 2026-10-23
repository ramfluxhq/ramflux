// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Feature-gated compatibility HTTP ingress and response serialization.

use crate::config::relay_service_key;
#[cfg(feature = "itest-object-v2")]
use crate::legacy_object::{
    RelayHandlerContext, RelayRequestPeer, RelayResponseValue, handle_relay_request_value,
};
#[cfg(feature = "itest-object-v2")]
use crate::retention::{RetentionMeshClient, retention_mesh_client};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use std::io::Write as _;

#[cfg(feature = "itest-http")]
pub(crate) struct RelayItestIngressState {
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    pub(crate) store: Arc<ramflux_node_core::RelayRedbStore>,
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    pub(crate) state: Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    #[cfg_attr(not(feature = "itest-object-v2"), allow(dead_code))]
    pub(crate) config: ramflux_node_core::NodeServiceConfig,
    // Object relay HMAC key + retention client only exist when the legacy v2 object
    // surface is compiled. itest-http alone serves only health, no key/object.
    #[cfg(feature = "itest-object-v2")]
    pub(crate) service_key: Vec<u8>,
    #[cfg(feature = "itest-object-v2")]
    pub(crate) retention_client: RetentionMeshClient,
}

#[cfg(feature = "itest-http")]
pub(crate) fn serve_itest_http(
    store: &Arc<ramflux_node_core::RelayRedbStore>,
    state: &Arc<Mutex<ramflux_node_core::RelayCacheState>>,
    config: &ramflux_node_core::NodeServiceConfig,
) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_RELAY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18084".to_owned());
    let listener = TcpListener::bind(&addr)?;
    let worker_count = relay_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let ingress = Arc::new(RelayItestIngressState {
        store: Arc::clone(store),
        state: Arc::clone(state),
        config: config.clone(),
        #[cfg(feature = "itest-object-v2")]
        service_key: relay_service_key(config)?,
        #[cfg(feature = "itest-object-v2")]
        retention_client: retention_mesh_client(config)?,
    });
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        let worker_ingress = Arc::clone(&ingress);
        thread::Builder::new()
            .name(format!("ramflux-relay-http-ingress-{worker_id}"))
            .spawn(move || relay_ingress_worker_loop(&worker_receiver, &worker_ingress))?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "relay itest HTTP surface listening");
    for stream in listener.incoming() {
        let stream = stream?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "failed to enable TCP_NODELAY on relay ingress connection");
        }
        sender.send(stream)?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn relay_ingress_worker_count() -> usize {
    std::env::var("RAMFLUX_RELAY_INGRESS_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        })
        .max(1)
}

#[cfg(feature = "itest-http")]
pub(crate) fn relay_ingress_worker_loop(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<TcpStream>>>,
    ingress: &Arc<RelayItestIngressState>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                tracing::error!("relay ingress receiver lock poisoned");
                return;
            };
            receiver.recv()
        };
        let Ok(mut stream) = stream else {
            return;
        };
        if let Err(error) = handle_itest_request(&mut stream, ingress) {
            let body = format!("{error}");
            if let Err(write_error) = ramflux_node_core::write_itest_text_response(
                &mut stream,
                "500 Internal Server Error",
                &body,
            ) {
                tracing::warn!(%write_error, "failed to write relay itest error response");
            }
        }
    }
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_itest_request(
    stream: &mut TcpStream,
    ingress: &RelayItestIngressState,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    tracing::info!(
        method = %request.method,
        path = %request.path,
        body_len = request.body.len(),
        "relay itest HTTP request received"
    );
    // Health is served directly, decoupled from the v2 object handler, so the
    // itest-http-only build (no itest-object-v2) has no object surface or key.
    if request.method == "GET" && request.path == "/healthz" {
        return ramflux_node_core::write_itest_json_response(
            stream,
            "200 OK",
            &serde_json::json!({"service": "ramflux-relay", "status": "ok"}),
        );
    }
    #[cfg(feature = "itest-object-v2")]
    {
        let context = RelayHandlerContext {
            store: &ingress.store,
            state: &ingress.state,
            config: &ingress.config,
            service_key: ingress.service_key.as_slice(),
            retention_client: &ingress.retention_client,
        };
        let response = handle_relay_request_value(
            &request.method,
            &request.path,
            &request.body,
            &context,
            RelayRequestPeer::Itest,
        )?;
        capture_itest_relay_json(&request.method, &request.path, &request.body, &response)?;
        write_relay_itest_response(stream, &response)?;
        Ok(())
    }
    #[cfg(not(feature = "itest-object-v2"))]
    {
        let _ = ingress;
        ramflux_node_core::write_itest_text_response(
            stream,
            "404 Not Found",
            "object relay surface not built (requires itest-object-v2)",
        )
    }
}

#[cfg(all(feature = "itest-http", feature = "itest-object-v2"))]
pub(crate) fn capture_itest_relay_json(
    method: &str,
    path: &str,
    body: &[u8],
    response: &RelayResponseValue,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let Ok(capture_path) = std::env::var("RAMFLUX_RELAY_ITEST_CAPTURE_JSON") else {
        return Ok(());
    };
    if !path.starts_with("/relay/v1/object/") {
        return Ok(());
    }
    let response_value = match response {
        RelayResponseValue::Json { status, value } => {
            serde_json::json!({ "status": status, "body": value })
        }
        RelayResponseValue::Text { status, body } => {
            serde_json::json!({ "status": status, "body": body })
        }
    };
    let record = serde_json::json!({
        "method": method,
        "path": path,
        "request_body_base64url": ramflux_protocol::encode_base64url(body),
        "response": response_value,
    });
    let capture_path = std::path::PathBuf::from(capture_path);
    if let Some(parent) = capture_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(capture_path)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    writeln!(file, "{record}")
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(all(feature = "itest-http", feature = "itest-object-v2"))]
pub(crate) fn write_relay_itest_response(
    stream: &mut TcpStream,
    response: &RelayResponseValue,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    match response {
        RelayResponseValue::Json { status, value } => {
            ramflux_node_core::write_itest_json_response(stream, status, value)
        }
        RelayResponseValue::Text { status, body } => {
            ramflux_node_core::write_itest_text_response(stream, status, body)
        }
    }
}
