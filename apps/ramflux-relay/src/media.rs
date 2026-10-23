// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Feature-gated UDP media relay transport and packet handling.

use crate::config::now_unix_seconds;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(feature = "itest-media-udp")]
pub(crate) fn serve_media_relay_udp(service_key: Vec<u8>) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_RELAY_MEDIA_UDP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:19000".to_owned());
    let state = Arc::new(Mutex::new(ramflux_node_core::SignalingState::new()));
    thread::Builder::new().name("ramflux-relay-media-udp-itest".to_owned()).spawn(move || {
        let runtime =
            match tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "failed to start media relay UDP runtime");
                    return;
                }
            };
        if let Err(error) = runtime.block_on(run_media_relay_udp(addr, state, service_key)) {
            tracing::error!(%error, "opaque media relay UDP listener stopped");
        }
    })?;
    Ok(())
}

#[cfg(feature = "itest-media-udp")]
pub(crate) async fn run_media_relay_udp(
    addr: String,
    state: Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: Vec<u8>,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind(&addr).await?;
    let relay_address = socket.local_addr()?.to_string();
    tracing::info!(addr, "relay opaque media UDP surface listening");
    let mut buf = vec![0_u8; ramflux_node_core::TURN_MEDIA_RELAY_PACKET_MAX_BYTES];
    let mut sweep = tokio::time::interval(Duration::from_mins(1));
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, peer) = received?;
                if let Err(error) = handle_media_relay_packet(
                    &socket,
                    &state,
                    service_key.as_slice(),
                    relay_address.as_str(),
                    peer,
                    &buf[..len],
                )
                .await
                {
                    tracing::debug!(%error, %peer, "dropping media relay packet");
                }
            }
            _ = sweep.tick() => {
                let now = now_unix_seconds();
                let expired = {
                    let mut state = state
                        .lock()
                        .map_err(|source| anyhow::anyhow!("media relay state lock failed: {source}"))?;
                    state.expire_turn_media_state(now).len()
                };
                if expired > 0 {
                    tracing::debug!(expired, "media relay expired allocations");
                }
            }
        }
    }
}

#[cfg(feature = "itest-media-udp")]
pub(crate) async fn handle_media_relay_packet(
    socket: &tokio::net::UdpSocket,
    state: &Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: &[u8],
    relay_address: &str,
    peer: std::net::SocketAddr,
    packet: &[u8],
) -> anyhow::Result<()> {
    let packet = ramflux_node_core::decode_turn_media_relay_packet(packet)
        .map_err(|source| anyhow::anyhow!("{source}"))?;
    let now = now_unix_seconds();
    let source_ip_hash = format!("media-relay-source-ip:{}", peer.ip());
    let target = {
        let mut state = state
            .lock()
            .map_err(|source| anyhow::anyhow!("media relay state lock failed: {source}"))?;
        state.ensure_turn_media_relay_state(
            &packet.header.token,
            ramflux_node_core::TurnMediaRelayEnsureContext {
                service_key,
                source_ip_hash: &source_ip_hash,
                relay_address,
                now,
                policy: &ramflux_node_core::TurnQuotaPolicy::default(),
            },
        )?;
        let target_allocation_id = state.validate_turn_media_packet(
            &packet.header.token,
            peer,
            packet.payload.len(),
            service_key,
            now,
        )?;
        state.turn_allocation_source(&target_allocation_id).map(str::to_owned)
    };
    let Some(target) = target else {
        tracing::debug!(
            allocation_id = %packet.header.token.allocation_id,
            target_allocation_id = %packet.header.token.target_allocation_id,
            "media relay target allocation has no bound source address yet"
        );
        return Ok(());
    };
    let target: std::net::SocketAddr = target.parse()?;
    let allow_private_targets =
        std::env::var("RAMFLUX_RELAY_ALLOW_PRIVATE_TARGETS").as_deref() == Ok("1");
    if !allow_private_targets && !ramflux_node_core::relay_socket_target_allowed(target, &[]) {
        tracing::warn!(
            %target,
            allocation_id = %packet.header.token.allocation_id,
            "dropping media relay packet to disallowed target address"
        );
        return Ok(());
    }
    socket.send_to(&packet.payload, target).await?;
    Ok(())
}
