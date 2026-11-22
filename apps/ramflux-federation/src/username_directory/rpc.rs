// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Fresh pinned TLS exchanges. Resolve once, validate those addresses, then dial those exact IPs.
use super::{Result, directory, dns, error, refuse, tls, wire};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

type Stream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;
#[derive(Clone, Copy)]
struct Peer<'a> {
    origin: &'a str,
    name: &'a str,
    ca: &'a [u8],
    id: &'a str,
    key: &'a str,
    private: Option<&'a [directory::PrivateHomePin]>,
}

pub fn center(
    node: &ramflux_node_core::NodeServiceConfig,
    pin: &directory::CenterPin,
    signer: &directory::DirectorySigner,
    evidence: directory::ReportingEvidence,
    root: &str,
    request: &directory::DirectoryRequest,
) -> Result<directory::AuthorityResponse> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let ca = tls::read_file(&pin.ca_file, 16384)?;
    let (mut stream, exporter) = connect(
        node,
        Peer {
            origin: &pin.url,
            name: &pin.tls_server_name,
            ca: &ca,
            id: &pin.id,
            key: &pin.public_key,
            private: None,
        },
        deadline,
    )?;
    let body = signer.reporting_request(
        pin,
        evidence,
        directory::ReportingRequestInput {
            root,
            request: request.clone(),
            exporter: &exporter,
            now: crate::now_unix_seconds()?,
        },
    )?;
    let (status, response) = post::<directory::AuthorityResponse>(
        &mut stream,
        &pin.url,
        request.path(),
        &body,
        deadline,
        8192,
    )?;
    let expected = if let directory::AuthorityResponse::Refused { failure } = &response {
        directory::http_status(failure.code)
    } else {
        200
    };
    if status != expected {
        return refuse("username centre status mismatch");
    }
    Ok(response)
}

pub fn home<T: Serialize, R: DeserializeOwned + Serialize>(
    node: &ramflux_node_core::NodeServiceConfig,
    service: &directory::SignedHomeServiceAddress,
    private: &[directory::PrivateHomePin],
    path: &str,
    request: &T,
) -> Result<R> {
    let deadline = Instant::now() + Duration::from_secs(10);
    service.verify(&service.body.node, &service.body.public_key, crate::now_unix_seconds()?)?;
    let (mut stream, _) = connect(
        node,
        Peer {
            origin: &service.body.origin,
            name: &service.body.tls_server_name,
            ca: service.body.ca_cert_pem.as_bytes(),
            id: &service.body.node,
            key: &service.body.public_key,
            private: Some(private),
        },
        deadline,
    )?;
    let (status, response) = post(
        &mut stream,
        &service.body.origin,
        path,
        &ramflux_protocol::canonical_json_bytes(request)?,
        deadline,
        directory::MAX_REPORT_BYTES,
    )?;
    if status != 200 {
        return refuse("username home HTTP refusal");
    }
    Ok(response)
}

fn connect(
    node: &ramflux_node_core::NodeServiceConfig,
    peer: Peer<'_>,
    deadline: Instant,
) -> Result<(Stream, [u8; 32])> {
    let Peer { origin, name, ca, id, key, private } = peer;
    let origin_parts = directory::parse_https_origin(origin)?;
    let addresses = dns::resolve(&origin_parts.host, origin_parts.port, deadline)?;
    let explicit = private.is_none_or(|pins| {
        pins.iter().any(|pin| pin.node == id && pin.public_key == key && pin.origin == origin)
    });
    if !explicit && addresses.iter().any(|address| !public_address(address.ip())) {
        return refuse("private username home requires explicit peer pin");
    }
    let mut connected = None;
    for address in addresses {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| error("username dial deadline"))?;
        if let Ok(socket) = TcpStream::connect_timeout(&address, left.min(Duration::from_secs(2))) {
            connected = Some(socket);
            break;
        }
    }
    let socket = connected.ok_or_else(|| error("username peer unavailable"))?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    socket.set_write_timeout(Some(Duration::from_millis(250)))?;
    let config = client_config(node, ca)?;
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), name.to_owned().try_into()?)?;
    connection.set_buffer_limit(Some(2 * 1024 * 1024));
    let mut stream = rustls::StreamOwned::new(connection, socket);
    while stream.conn.is_handshaking() {
        check(deadline)?;
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if retry(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if stream.conn.alpn_protocol() != Some(tls::ALPN) {
        return refuse("username ALPN mismatch");
    }
    let exporter = stream.conn.export_keying_material([0; 32], tls::EXPORTER, None)?;
    let challenge = ramflux_crypto::random_32()?;
    write(&mut stream, &challenge, deadline)?;
    let mut prefix = [0; 4];
    read(&mut stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > 2048 {
        return refuse("username channel identity size");
    }
    let mut bytes = vec![0; length];
    read(&mut stream, &mut bytes, deadline)?;
    let identity: directory::DirectoryChannelIdentity = wire::decode(&bytes)?;
    identity.verify(
        id,
        key,
        &exporter,
        &ramflux_protocol::encode_base64url(challenge),
        crate::now_unix_seconds()?,
    )?;
    Ok((stream, exporter))
}

fn client_config(
    node: &ramflux_node_core::NodeServiceConfig,
    ca: &[u8],
) -> Result<rustls::ClientConfig> {
    let _installed = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in tls::certs(ca)? {
        roots.add(cert)?;
    }
    let certificates =
        tls::certs(&tls::read_file(std::path::Path::new(&node.mesh.service_cert), 65536)?)?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(tls::read_file(
        std::path::Path::new(&node.mesh.service_key),
        16384,
    )?))?
    .ok_or_else(|| error("username TLS client key"))?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)?;
    config.alpn_protocols = vec![tls::ALPN.to_vec()];
    Ok(config)
}

fn post<T: DeserializeOwned + Serialize>(
    stream: &mut Stream,
    origin: &str,
    path: &str,
    body: &[u8],
    deadline: Instant,
    max_response: usize,
) -> Result<(u16, T)> {
    if body.len() > directory::MAX_REPORT_BYTES {
        return refuse("username request bound");
    }
    let host = origin.strip_prefix("https://").ok_or_else(|| error("username origin"))?;
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    write(stream, header.as_bytes(), deadline)?;
    write(stream, body, deadline)?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16384 {
            return refuse("username response header bound");
        }
        let mut byte = [0];
        read(stream, &mut byte, deadline)?;
        header.extend(byte);
    }
    let text = std::str::from_utf8(&header)?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|line| line.split_once(' '))
        .map(|(status, _)| status)
        .ok_or_else(|| error("username HTTP response"))?
        .parse::<u16>()?;
    if !(200..600).contains(&status) {
        return refuse("username HTTP status");
    }
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) =
            line.split_once(':').ok_or_else(|| error("username response header"))?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return refuse("username response duplicate length");
            }
            let parsed: usize = value.trim().parse()?;
            if parsed > max_response {
                return refuse("username response bound");
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return refuse("username response transfer encoding");
        }
    }
    let length = length.ok_or_else(|| error("username response length required"))?;
    let mut bytes = vec![0; length];
    read(stream, &mut bytes, deadline)?;
    Ok((status, wire::decode(&bytes)?))
}

fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline || ramflux_node_core::service_shutdown_token().is_cancelled() {
        return refuse("username exchange deadline");
    }
    Ok(())
}
fn retry(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}
fn read(stream: &mut impl Read, output: &mut [u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        check(deadline)?;
        match stream.read(output.get_mut(offset..).ok_or_else(|| error("username read offset"))?) {
            Ok(0) => return refuse("username reply closed"),
            Ok(count) => offset += count,
            Err(error) if retry(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn write(stream: &mut Stream, bytes: &[u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        check(deadline)?;
        match stream.write(bytes.get(offset..).ok_or_else(|| error("username write offset"))?) {
            Ok(0) => return refuse("username request closed"),
            Ok(count) => offset += count,
            Err(error) if retry(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    loop {
        check(deadline)?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) if retry(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && c == 0)
                && !(a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_address(IpAddr::V4(ip));
            }
            let [a, b, c, d, ..] = ip.octets();
            a & 0xe0 == 0x20
                && !(a == 0x20 && b == 1 && c == 0x0d && d == 0xb8)
                && !(a == 0x20 && b == 2)
        }
    }
}
