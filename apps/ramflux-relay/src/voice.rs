// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production opaque UDP data plane and gateway-only mTLS allocation leases.
use ramflux_node_core::{NodeServiceConfig, VoiceRelayState, VoiceRoute};
use ramflux_protocol::{VoiceLeaseRequest, VoiceLeaseStatus};
use std::sync::{Arc, Mutex};

/// Disabled unless all three explicit operator endpoints are configured.
pub(crate) fn start(config: &NodeServiceConfig) -> anyhow::Result<()> {
    let Some((udp, control, public)) = voice_endpoints()? else {
        return Ok(());
    };
    start_voice_surfaces(config, &udp, &control, &public)
}

fn voice_endpoints() -> anyhow::Result<Option<(String, String, String)>> {
    let variables = [
        "RAMFLUX_RELAY_VOICE_UDP_ADDR",
        "RAMFLUX_RELAY_VOICE_CONTROL_ADDR",
        "RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT",
    ];
    let values = variables.map(|name| {
        ramflux_node_core::environment::var(name).ok().filter(|v| !v.trim().is_empty())
    });
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    let [Some(udp), Some(control), Some(public)] = values else {
        anyhow::bail!("all relay voice endpoints must be configured together");
    };
    Ok(Some((udp, control, public)))
}

fn start_voice_surfaces(
    config: &NodeServiceConfig,
    udp: &str,
    control: &str,
    public: &str,
) -> anyhow::Result<()> {
    let socket = std::net::UdpSocket::bind(udp)?;
    socket.set_nonblocking(true)?;
    let server =
        ramflux_transport::MeshTlsServer::bind(control, &crate::config::mesh_tls_config(config))?;
    server.set_nonblocking(true)?;
    let state = Arc::new(Mutex::new(VoiceRelayState::default()));
    let udp_state = Arc::clone(&state);
    let allow_private = ramflux_node_core::environment::var("RAMFLUX_RELAY_ALLOW_PRIVATE_TARGETS")
        .as_deref()
        == Ok("1");
    ramflux_node_core::spawn_service_worker("voice-udp", move |_| {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(run_udp(socket, udp_state, allow_private)));
        if let Err(error) = result {
            tracing::error!(%error,"voice UDP stopped");
        }
    })?;
    let node = config.node_id.clone();
    // A bounded worker pool prevents authenticated peers from creating unbounded connection threads.
    let server = Arc::new(server);
    for _ in 0..8 {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        let node = node.clone();
        let public = public.to_owned();
        ramflux_node_core::spawn_service_worker("voice-control", move |shutdown| {
            while !shutdown.is_cancelled() {
                let result = (|| -> anyhow::Result<()> {
                    let accepted = match server.accept_authenticated() {
                        Ok(accepted) => accepted,
                        Err(ramflux_transport::TransportError::Io(error))
                            if error.kind() == std::io::ErrorKind::WouldBlock =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(25));
                            return Ok(());
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let identity = ramflux_node_core::parse_mesh_spiffe_uri(
                        accepted.peer_spiffe_uri.as_deref().unwrap_or_default(),
                    )?;
                    if identity.service_id != "ramflux-gateway" || identity.node_id != node {
                        anyhow::bail!("voice control requires local gateway mTLS identity");
                    }
                    let mut stream = accepted.stream;
                    let Some(request) = ramflux_transport::read_mesh_http_request(&mut stream)?
                    else {
                        return Ok(());
                    };
                    if request.method != "POST"
                        || request.path != "/voice/v1/lease"
                        || request.body.len() > 4096
                    {
                        ramflux_transport::write_mesh_text_response(
                            &mut stream,
                            "400 Bad Request",
                            "invalid voice control request",
                        )?;
                        return Ok(());
                    }
                    let request: VoiceLeaseRequest = ramflux_protocol::parse_i_json(&request.body)?;
                    let now = crate::config::now_unix_seconds();
                    let result = mutate(&state, &identity.node_id, &public, request, now);
                    match result {
                        Ok(response) => ramflux_transport::write_mesh_json_response(
                            &mut stream,
                            "200 OK",
                            &response,
                        )?,
                        Err(_) => ramflux_transport::write_mesh_text_response(
                            &mut stream,
                            "403 Forbidden",
                            "voice lease rejected",
                        )?,
                    }
                    ramflux_transport::close_mesh_server_stream(&mut stream)?;
                    Ok(())
                })();
                if let Err(error) = result {
                    tracing::debug!(%error,"voice control rejected");
                }
            }
        })?;
    }
    tracing::info!(udp, control, public, "relay voice surfaces listening");
    Ok(())
}
fn mutate(
    state: &Mutex<VoiceRelayState>,
    owner: &str,
    public: &str,
    request: VoiceLeaseRequest,
    now: u64,
) -> anyhow::Result<serde_json::Value> {
    let mut state = state.lock().map_err(|_| anyhow::anyhow!("voice state poisoned"))?;
    match request {
        VoiceLeaseRequest::Allocate { scope } => {
            Ok(serde_json::to_value(state.allocate(owner, &scope, public, now)?)?)
        }
        VoiceLeaseRequest::Accept { consent } => {
            Ok(serde_json::to_value(state.accept_verified(owner, &consent, public, now)?)?)
        }
        VoiceLeaseRequest::Renew { consent } => Ok(serde_json::to_value(VoiceLeaseStatus {
            expires_at: state.renew_consented(owner, &consent, now)?,
        })?),
        VoiceLeaseRequest::Release { scope } => {
            state.release(owner, &scope)?;
            Ok(serde_json::to_value(VoiceLeaseStatus { expires_at: now })?)
        }
    }
}
pub(crate) async fn run_udp(
    socket: std::net::UdpSocket,
    state: Arc<Mutex<VoiceRelayState>>,
    allow_private: bool,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    // Receive an entire datagram so truncation can never turn an oversized packet into a valid one.
    let mut buffer = vec![0_u8; 65536];
    let mut sweep = tokio::time::interval(std::time::Duration::from_secs(10));
    let shutdown = ramflux_node_core::service_shutdown_token();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            result=socket.recv_from(&mut buffer) => {
                let (len,source)=result?;
                let route={
                    let mut state=state.lock().map_err(|_|anyhow::anyhow!("voice state poisoned"))?;
                    state.route_with_rebinding(&buffer[..len],source,crate::config::now_unix_seconds(),allow_private)
                };
                let sent = match route {
                    Ok(VoiceRoute::Forward { target, packet }) => socket.send_to(packet, target).await,
                    Ok(VoiceRoute::Challenge { target, packet }) => socket.send_to(&packet, target).await,
                    Ok(VoiceRoute::Drop) | Err(_) => continue,
                };
                if sent.is_err() { tracing::debug!("voice datagram forwarding failed"); }
            }
            _=sweep.tick() => { state.lock().map_err(|_|anyhow::anyhow!("voice state poisoned"))?.expire(crate::config::now_unix_seconds()); }
        }
    }
}
