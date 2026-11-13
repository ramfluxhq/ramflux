// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Health-only test HTTP ingress; object traffic uses the authenticated QUIC surface.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(feature = "itest-http")]
pub(crate) fn serve_itest_http() -> anyhow::Result<()> {
    let addr = ramflux_node_core::environment::var("RAMFLUX_ITEST_RELAY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18084".to_owned());
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;
    let worker_count = relay_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        ramflux_node_core::spawn_service_worker(
            format!("ramflux-relay-http-ingress-{worker_id}"),
            move |_| relay_ingress_worker_loop(&worker_receiver),
        )?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "relay itest HTTP surface listening");
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        let stream = match listener.accept().map(|(stream, _)| stream) {
            Ok(stream) => {
                backoff.success();
                stream
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            Err(error) => {
                backoff.wait_after_failure(&error);
                continue;
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "failed to enable TCP_NODELAY on relay ingress connection");
            continue;
        }
        sender.send(stream)?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
pub(crate) fn relay_ingress_worker_count() -> usize {
    ramflux_node_core::environment::var("RAMFLUX_RELAY_INGRESS_THREADS")
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
        let Some(_in_flight) = ramflux_node_core::begin_service_request() else {
            return;
        };
        if let Err(error) = handle_itest_request(&mut stream) {
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
    // This listener exposes health only; object requests always fail closed.
    if request.method == "GET" && request.path == "/healthz" {
        return ramflux_node_core::write_itest_json_response(
            stream,
            "200 OK",
            &serde_json::json!({"service": "ramflux-relay", "status": "ok"}),
        );
    }

    {
        ramflux_node_core::write_itest_text_response(
            stream,
            "404 Not Found",
            "unsupported relay HTTP route",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        time::{Duration, Instant},
    };
    const RESPONSE_BYTE_CAP: usize = 4096;
    const IO_DEADLINE: Duration = Duration::from_secs(3);

    fn sockets() -> anyhow::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let client = TcpStream::connect_timeout(&listener.local_addr()?, IO_DEADLINE)?;
        // The successful connect has already enqueued this socket; accept cannot wait.
        let (server, _) = listener.accept()?;
        for stream in [&client, &server] {
            stream.set_read_timeout(Some(IO_DEADLINE))?;
            stream.set_write_timeout(Some(IO_DEADLINE))?;
        }
        Ok((client, server))
    }

    fn response(stream: &mut TcpStream, timeout: Duration) -> std::io::Result<String> {
        let deadline = Instant::now() + timeout;
        let mut bytes = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP response deadline",
                ));
            }
            stream.set_read_timeout(Some(remaining))?;
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > RESPONSE_BYTE_CAP {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP response exceeds byte cap",
                ));
            }
            bytes.extend_from_slice(
                chunk.get(..count).ok_or_else(|| std::io::Error::other("HTTP read bounds"))?,
            );
        }
        String::from_utf8(bytes).map_err(std::io::Error::other)
    }

    #[test]
    fn retired_v2_object_http_routes_are_refused() -> anyhow::Result<()> {
        for (method, path, status) in [
            ("POST", "/relay/v1/object/put", "404 Not Found"),
            ("POST", "/relay/v1/object/get", "404 Not Found"),
            ("POST", "/relay/v1/object/ack", "404 Not Found"),
            ("POST", "/relay/v1/object/tombstone", "404 Not Found"),
            ("GET", "/healthz", "200 OK"),
        ] {
            let (mut client, mut server) = sockets()?;
            let body =
                r#"{"schema":"ramflux.object_chunk_frame.v1","relay_token":{"token_version":2}}"#;
            write!(
                client,
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )?;
            handle_itest_request(&mut server)?;
            drop(server);
            let response = response(&mut client, IO_DEADLINE)?;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "retired route/health response mismatch for {path}: {response}"
            );
        }
        Ok(())
    }

    #[test]
    fn oversized_and_stalled_http_peers_terminate_with_bounded_resources() -> anyhow::Result<()> {
        let (mut client, mut server) = sockets()?;
        server.write_all(&[b'x'; RESPONSE_BYTE_CAP + 1])?;
        drop(server);
        let Err(error) = response(&mut client, IO_DEADLINE) else {
            return Err(anyhow::anyhow!("test: oversized response must be refused"));
        };
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "response cap must refuse before input-sized allocation"
        );
        let (mut client, _stalled) = sockets()?;
        let Err(error) = response(&mut client, Duration::from_millis(50)) else {
            return Err(anyhow::anyhow!("test: stalled peer must terminate at its deadline"));
        };
        assert!(
            matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock),
            "stalled socket must return a deadline error"
        );
        Ok(())
    }
}
