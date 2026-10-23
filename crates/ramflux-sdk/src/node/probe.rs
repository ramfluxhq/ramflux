// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Read-only discovery, transport, application, and account-session diagnostics.
use super::{
    Duration, GatewaySessionEngine, LocalBusDaemonState, LocalBusDispatchResult, LocalBusFrame,
    NodeProfile, Path, SdkError, Serialize, SocketAddr, fetch_client_record, local_bus_ok,
    node_error, now_unix_timestamp, read_local_bus_account_manifest, resolve_node_addr,
};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource};
use std::time::Instant;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct GatewayProbe {
    transport: serde_json::Value,
    app: &'static str,
    session: &'static str,
    rtt_ms: u64,
}

pub(crate) async fn dispatch_probe(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let id = request
        .body
        .get("node_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| node_error("node_id is required"))?;
    let profile =
        state.nodes.selected(Some(id), true)?.ok_or_else(|| node_error("unknown node"))?;
    let now = now_unix_timestamp().unsigned_abs();
    let url = if profile.discovery_url.is_empty() { id } else { &profile.discovery_url };
    let fetched = fetch_client_record(url).await;
    let status = match &fetched {
        Ok(record) if record.node_id != id || record.node_public_key != profile.node_public_key => {
            "key_changed"
        }
        Ok(_) => "ok",
        Err(SdkError::Protocol(ramflux_protocol::ProtocolError::SignedRequestExpired)) => "expired",
        Err(SdkError::Protocol(_)) => "invalid_signature",
        Err(_) => "failed",
    };
    if status == "key_changed" {
        if let Some(stored) = state.nodes.profiles.get_mut(id) {
            stored.safety_warnings.insert("key_changed".to_owned());
        }
        state.nodes.save(&state.config.data_root)?;
    }
    if status != "ok" {
        return Ok(local_bus_ok(serde_json::json!({"node_id": id, "healthy": false,
            "discovery": {"status": status, "expires_at": profile.expires_at},
            "gateway": {"transport": {"quic": "not_attempted", "tcp": "not_attempted"}, "app": "not_available", "session": "not_attempted", "rtt_ms": 0},
            "relay": {"status": "not_attempted"}, "prekey": {"status": "not_attempted"}, "checked_at": now})));
    }
    let record = fetched?;
    let expires_at = record.expires_at;
    let fresh = NodeProfile::from_record(record, now);
    let ca = fresh.write_ca(&state.config.data_root)?;
    let mut gateway = probe_gateway(&fresh, &ca).await;
    gateway.session = probe_bound_session(state, id).await?;
    let relay = probe_relay(&fresh, &ca).await;
    let prekey = tokio::time::timeout(PROBE_TIMEOUT, probe_prekey_tls(&fresh)).await;
    let prekey_ok = matches!(prekey, Ok(Ok(())));
    Ok(local_bus_ok(serde_json::json!({"node_id": id,
        "healthy": status == "ok" && gateway.app == "ok" && relay,
        "discovery": {"status": status, "expires_at": expires_at}, "gateway": gateway,
        "relay": {"status": if relay {"ok"} else {"failed"}},
        "prekey": {"status": if prekey_ok {"ok"} else {"failed"}}, "checked_at": now})))
}

async fn probe_bound_session(
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<&'static str, SdkError> {
    let dir = crate::bus::daemon::local_bus_accounts_dir(&state.config.data_root);
    if dir.exists() {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
                continue;
            }
            let manifest = read_local_bus_account_manifest(&path)?;
            if manifest.node_id.as_deref() != Some(id) {
                continue;
            }
            let Some(account) = state.accounts.get(&manifest.local_account_id) else {
                return Ok("failed");
            };
            return Ok(match GatewaySessionEngine::connect(account.gateway_config.clone()).await {
                Ok(mut engine) => {
                    let _ = engine.close("node probe finished").await;
                    "ok"
                }
                Err(_) => "failed",
            });
        }
    }
    Ok("requires_account")
}

async fn probe_relay(profile: &NodeProfile, ca: &Path) -> bool {
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let addr = resolve_node_addr(&profile.relay.quic_addr).await?;
        let response = crate::object::relay_quic_health_probe(
            &addr.to_string(),
            &profile.relay.server_name,
            ca,
            PROBE_TIMEOUT,
        )
        .await?;
        Ok::<_, SdkError>(response.status == 200)
    })
    .await;
    matches!(result, Ok(Ok(true)))
}

async fn probe_gateway(profile: &NodeProfile, ca: &Path) -> GatewayProbe {
    let started = Instant::now();
    let quic = gateway_quic(profile, ca).await;
    let (quic_transport, quic_app) = probe_outcome(&quic);
    let (tcp_transport, app) = if quic_app == "ok" {
        ("not_attempted", quic_app)
    } else {
        let tcp = gateway_tcp(profile, ca).await;
        let (transport, app) = probe_outcome(&tcp);
        (transport, app)
    };
    GatewayProbe {
        transport: serde_json::json!({"quic": quic_transport, "tcp": tcp_transport}),
        app,
        session: "requires_account",
        rtt_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn probe_outcome(result: &Result<&'static str, SdkError>) -> (&'static str, &'static str) {
    match result {
        Ok(app) => ("ok", app),
        Err(_) => ("failed", "not_available"),
    }
}

fn bind_for(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    }
}

async fn gateway_quic(profile: &NodeProfile, ca: &Path) -> Result<&'static str, SdkError> {
    let addr = resolve_node_addr(&profile.gateway.quic_addr).await?;
    let client = ramflux_transport::QuicGatewayClient::connect(
        bind_for(addr),
        addr,
        &profile.gateway.server_name,
        ca,
        PROBE_TIMEOUT,
    )
    .await?;
    let mut stream = client.open_bidi_stream().await?;
    let result = app_challenge(&mut stream).await;
    let _ = stream.finish();
    client.close();
    Ok(result)
}

async fn gateway_tcp(profile: &NodeProfile, ca: &Path) -> Result<&'static str, SdkError> {
    let addr = resolve_node_addr(&profile.gateway.tcp_addr).await?;
    let (_, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        bind_for(addr),
        addr,
        &profile.gateway.server_name,
        ca,
        PROBE_TIMEOUT,
    )
    .await?;
    Ok(app_challenge(&mut stream).await)
}

async fn app_challenge<T: GatewaySessionFrameSink + GatewaySessionFrameSource>(
    stream: &mut T,
) -> &'static str {
    let challenge =
        serde_json::json!({"frame_type": "heartbeat", "now": now_unix_timestamp().unsigned_abs()});
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        stream.send_frame(&serde_json::to_vec(&challenge)?).await?;
        let bytes = stream.recv_frame().await?;
        let response: serde_json::Value = serde_json::from_slice(&bytes)?;
        Ok::<_, SdkError>(
            response.get("frame_type").and_then(serde_json::Value::as_str) == Some("nack")
                && response.get("reason").and_then(serde_json::Value::as_str)
                    == Some(ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON),
        )
    })
    .await;
    match result {
        Ok(Ok(true)) => "ok",
        Ok(Ok(false) | Err(_)) => "unexpected_response",
        Err(_) => "timeout",
    }
}

async fn probe_prekey_tls(profile: &NodeProfile) -> Result<(), SdkError> {
    let url = reqwest::Url::parse(&profile.prekey_http_url)
        .map_err(|error| node_error(&error.to_string()))?;
    if url.scheme() != "https" {
        return Err(node_error("prekey probe requires HTTPS"));
    }
    let host = url.host_str().ok_or_else(|| node_error("prekey URL has no host"))?;
    let port = url.port_or_known_default().ok_or_else(|| node_error("prekey URL has no port"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut profile.ca_cert_pem.as_bytes()) {
        roots.add(cert?).map_err(|error| node_error(&error.to_string()))?;
    }
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| node_error(&error.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|error| node_error(&error.to_string()))?;
    let tcp = tokio::net::TcpStream::connect((host, port)).await?;
    let _tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|error| node_error(&error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn heartbeat_first_nack_reason_is_a_pinned_contract() {
        assert_eq!(
            ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON,
            "first gateway frame must be open"
        );
    }
}
