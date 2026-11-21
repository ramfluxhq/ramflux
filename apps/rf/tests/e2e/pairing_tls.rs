// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared bounded TLS front for the existing federation and CLI process harness.
use ramflux_node_core::{NodeHttpRequest, pairing_relay::pairing_http_limits as pairing_limits};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub struct TlsFront {
    stop: Arc<AtomicBool>,
    addr: SocketAddr,
    thread: Option<JoinHandle<()>>,
}

impl Drop for TlsFront {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn_tls_front(
    listener: TcpListener,
    backend: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
) -> TestResult<TlsFront> {
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    listener.set_nonblocking(true)?;
    let thread = std::thread::spawn(move || {
        serve_tls_front(&listener, backend, &server_config, &worker_stop);
    });
    Ok(TlsFront { stop, addr, thread: Some(thread) })
}

fn serve_tls_front(
    listener: &TcpListener,
    backend: SocketAddr,
    server_config: &Arc<rustls::ServerConfig>,
    stop: &AtomicBool,
) {
    let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
    while !stop.load(Ordering::Relaxed) {
        let (mut tcp, peer) = match listener.accept() {
            Ok(accepted) => {
                backoff.success();
                accepted
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) => {
                backoff.wait_after_failure(&error);
                continue;
            }
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let _ = tcp.set_nonblocking(false);
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let Ok(mut conn) = rustls::ServerConnection::new(Arc::clone(server_config)) else {
            continue;
        };
        let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
        let request = match read_http_request(&mut tls) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("test: TLS front request read refused: {error}");
                continue;
            }
        };
        let Ok(mut upstream) = TcpStream::connect_timeout(&backend, Duration::from_secs(5)) else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = upstream.set_write_timeout(Some(Duration::from_secs(5)));
        let forwarded = reconstruct_forwarded(&request, peer);
        if upstream.write_all(&forwarded).is_err() {
            continue;
        }
        let mut reply = Zeroizing::new(Vec::new());
        let cap = ramflux_protocol::custody::pairing::full_transfer::PACKET_BYTES
            + pairing_limits().max_header_bytes;
        if let Err(error) = upstream.take(cap as u64 + 1).read_to_end(&mut reply) {
            eprintln!("test: TLS front upstream reply read refused: {error}");
            continue;
        }
        if reply.len() > cap {
            eprintln!("test: TLS front upstream reply exceeded cap");
            continue;
        }
        let _ = tls.write_all(&reply);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
}

struct ForwardRequest {
    request: NodeHttpRequest,
    protected_headers: Zeroizing<Vec<u8>>,
}
fn reconstruct_forwarded(forwarded: &ForwardRequest, peer: SocketAddr) -> Zeroizing<Vec<u8>> {
    let request = &forwarded.request;
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: {}\r\n",
        request.method,
        request.path,
        request.body.len(),
        peer.ip()
    )
    .into_bytes();
    raw.extend_from_slice(&forwarded.protected_headers);
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&request.body);
    Zeroizing::new(raw)
}

pub fn rustls_server_config(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> TestResult<Arc<rustls::ServerConfig>> {
    let mut cert_pem = std::io::BufReader::new(std::fs::File::open(cert)?);
    let mut key_pem = std::io::BufReader::new(std::fs::File::open(key)?);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem)?.ok_or("missing key")?;
    Ok(Arc::new(
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?,
    ))
}

fn read_http_request(tls: &mut impl Read) -> TestResult<ForwardRequest> {
    let mut raw = Zeroizing::new(Vec::new());
    let mut buf = [0_u8; 512];
    let (header_end, start) = loop {
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break (end, end + 4);
        }
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err("headers".into());
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > pairing_limits().max_header_bytes {
            return Err("header cap".into());
        }
    };
    let header = std::str::from_utf8(raw.get(..header_end).ok_or("test: bounded proxy header")?)?;
    let mut parts = header.lines().next().ok_or("line")?.split_whitespace();
    let method = parts.next().ok_or("method")?.to_owned();
    let path = parts.next().ok_or("path")?.to_owned();
    let mut length = 0_usize;
    let mut protected_headers = Zeroizing::new(Vec::new());
    for line in header.lines().skip(1) {
        if let Some((name, _)) = line.split_once(':')
            && ["authorization", "content-type", "x-ramflux-pairing-arm"]
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
        {
            protected_headers.extend_from_slice(line.as_bytes());
            protected_headers.extend_from_slice(b"\r\n");
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("Content-Length")
        {
            length = value.trim().parse()?;
        }
    }
    if length > ramflux_protocol::custody::pairing::full_transfer::PACKET_BYTES {
        return Err("body cap".into());
    }
    while raw.len() < start + length {
        let n = tls.read(&mut buf)?;
        if n == 0 {
            return Err("short body".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    if raw.len() < start + length {
        return Err("short body".into());
    }
    let request = NodeHttpRequest {
        method,
        path,
        body: raw.get(start..start + length).ok_or("test: bounded proxy body")?.to_vec(),
        keep_alive: false,
        source_ip_hash: None,
        pre_auth_cookie: None,
        pre_auth_now: None,
        forwarded_proto: None,
        forwarded_for: None,
    };
    Ok(ForwardRequest { request, protected_headers })
}
