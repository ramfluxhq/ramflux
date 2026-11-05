// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit candidate server policy; the production constructors are unchanged.
use super::{MeshRootPemProvider, mesh_server_config_with_dynamic_pem_roots};
use crate::{MeshQuicAdmissionLimits, MeshTlsConfig, TransportError};
use std::sync::Arc;

pub(crate) fn server_config(
    tls: &MeshTlsConfig,
    roots: MeshRootPemProvider,
    limits: MeshQuicAdmissionLimits,
) -> Result<quinn::ServerConfig, TransportError> {
    let limits = limits.bounded();
    let tls = server_tls(tls, roots)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(limits.bidi_streams.into());
    transport.max_concurrent_uni_streams(0_u32.into());
    transport.receive_window(limits.receive_window.into());
    transport.stream_receive_window(limits.stream_receive_window.into());
    transport.send_window(limits.send_window);
    transport.datagram_receive_buffer_size(None);
    transport.datagram_send_buffer_size(0);
    transport.crypto_buffer_size(64 * 1024);
    transport.max_idle_timeout(Some(
        limits
            .idle_timeout
            .try_into()
            .map_err(|error| TransportError::Quic(format!("invalid idle timeout: {error}")))?,
    ));
    server.transport_config(Arc::new(transport));
    server.max_incoming(64);
    server.incoming_buffer_size(64 * 1024);
    server.incoming_buffer_size_total(4 * 1024 * 1024);
    Ok(server)
}

pub(crate) fn server_tls(
    tls: &MeshTlsConfig,
    roots: MeshRootPemProvider,
) -> Result<rustls::ServerConfig, TransportError> {
    let mut config = mesh_server_config_with_dynamic_pem_roots(tls, roots)?;
    config.max_early_data_size = 0;
    Ok(config)
}
