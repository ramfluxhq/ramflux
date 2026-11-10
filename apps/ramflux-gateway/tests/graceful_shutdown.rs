// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::io::{BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[path = "../../../tests/configured_shutdown.rs"]
mod configured_shutdown;

#[cfg(unix)]
#[test]
fn configured_service_closes_tls_and_redb_on_sigterm() -> Result<(), Box<dyn std::error::Error>> {
    configured_shutdown::configured_gateway_shutdown_is_clean(
        env!("CARGO_BIN_EXE_ramflux-gateway"),
        "ramflux-gateway",
        start_gateway_tls_probe,
    )
}

fn start_gateway_tls_probe(
    addr: &str,
    ca_path: &Path,
    shutdown_started: Arc<AtomicBool>,
    connection_closed: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<Result<(), std::io::Error>>, std::io::Error> {
    let mut stream = connect_gateway_tls(addr, ca_path)?;
    let client_frame = ramflux_node_core::GatewayClientFrame::Open {
        open: ramflux_node_core::GatewayOpenFrame {
            protocol_version: ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
            transport_kind: "tcp_tls".to_owned(),
            client_instance_id: "shutdown-probe".to_owned(),
            device_id: "device".to_owned(),
            target_delivery_id: "target".to_owned(),
            stream_nonce: "nonce".to_owned(),
            previous_session_id: None,
            resume_token_hash: None,
            last_seen_inbox_seq: None,
            max_inflight_downstream: 1,
            max_inflight_upstream: 1,
            pre_auth_cookie: None,
            pre_auth_now: None,
            source_ip_hash: None,
        },
    };
    let payload = serde_json::to_vec(&client_frame).map_err(invalid_tls_data)?;
    ramflux_protocol::parse_i_json::<ramflux_node_core::GatewayClientFrame>(&payload)
        .map_err(invalid_tls_data)?;
    let frame = ramflux_transport::encode_gateway_session_frame_for_test(&payload)
        .map_err(invalid_tls_data)?;
    stream.write_all(&frame[..4 + payload.len() / 2])?;
    stream.flush()?;
    stream.get_ref().set_read_timeout(Some(Duration::from_millis(25)))?;
    Ok(std::thread::spawn(move || {
        wait_for_gateway_shutdown_start(
            &shutdown_started,
            Instant::now() + Duration::from_secs(10),
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        read_gateway_response_to_close(&mut stream, deadline)?;
        connection_closed.store(true, Ordering::SeqCst);
        Ok(())
    }))
}

fn connect_gateway_tls(
    addr: &str,
    ca_path: &Path,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, std::io::Error> {
    let mut roots = rustls::RootCertStore::empty();
    let mut ca = BufReader::new(std::fs::File::open(ca_path)?);
    let mut certificate_count = 0;
    for certificate in rustls_pemfile::certs(&mut ca) {
        roots.add(certificate.map_err(invalid_tls_data)?).map_err(invalid_tls_data)?;
        certificate_count += 1;
    }
    if certificate_count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "shutdown fixture CA contains no certificates",
        ));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(invalid_tls_data)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
        .map_err(invalid_tls_data)?;
    let mut socket = TcpStream::connect(addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(invalid_tls_data)?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(invalid_tls_data)?;
    }
    Ok(rustls::StreamOwned::new(connection, socket))
}

fn wait_for_gateway_shutdown_start(
    shutdown_started: &AtomicBool,
    deadline: Instant,
) -> Result<(), std::io::Error> {
    while !shutdown_started.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "gateway shutdown signal exceeded 10-second hang guard",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn read_gateway_response_to_close(
    stream: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    deadline: Instant,
) -> Result<(), std::io::Error> {
    let mut chunk = [0; 1024];
    let mut response = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "gateway socket did not close within the 10-second hang guard",
            ));
        }
        stream.get_ref().set_read_timeout(Some(remaining))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error),
        }
    }
    if !response.is_empty() && !is_well_formed_gateway_close_frame(&response) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "probe received neither TLS close_notify/EOF/reset nor a well-formed GatewayServerFrame::Close: {response:?}"
            ),
        ));
    }
    Ok(())
}

fn is_well_formed_gateway_close_frame(response: &[u8]) -> bool {
    let Some((header, payload)) = response.split_at_checked(4) else {
        return false;
    };
    let Ok(header) = <[u8; 4]>::try_from(header) else {
        return false;
    };
    let length = u32::from_be_bytes(header) as usize;
    if length > ramflux_transport::MAX_GATEWAY_FRAME_BYTES || length != payload.len() {
        return false;
    }
    matches!(
        ramflux_protocol::parse_i_json::<ramflux_node_core::GatewayServerFrame>(payload),
        Ok(ramflux_node_core::GatewayServerFrame::Close { .. })
    )
}

fn invalid_tls_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}
