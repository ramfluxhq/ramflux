// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public fetch of a peer's signed server record.
//!
//! Production connects only to HTTPS port 443 on a public unicast address and does not follow
//! redirects. One test socket, named by the caller, is plain HTTP to that loopback address only.

use crate::TransportError;
use std::io::{BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const RECORD_LIMIT: usize = 1024 * 1024;
const HEADER_LIMIT: usize = 16 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Fetch `/.well-known/ramflux/server` for `node_id`.
///
/// `test_socket` replaces DNS. It must be loopback. The body is at most 1 MiB.
///
/// # Errors
/// Returns an error when the name, address, TLS session, or response is refused.
pub fn fetch_server_well_known(
    node_id: &str,
    test_socket: Option<SocketAddr>,
) -> Result<Vec<u8>, TransportError> {
    match test_socket {
        Some(socket) => http_get_loopback(socket),
        None => https_get_public(node_id),
    }
}

/// The mesh address in a signed record must be public unicast.
///
/// `allow_loopback` is set only after the record was fetched from the test socket.
///
/// # Errors
/// Returns an error when the endpoint is empty, cleartext, or not a public address.
pub fn public_mesh_endpoint(endpoint: &str, allow_loopback: bool) -> Result<(), TransportError> {
    let host_port = mesh_host_port(endpoint)?;
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let addresses = crate::bounded_http_dns::resolve(host_port, deadline)?;
    if addresses.is_empty() || addresses.iter().any(|addr| !allowed_mesh(addr.ip(), allow_loopback))
    {
        return Err(egress_refused());
    }
    Ok(())
}

fn https_get_public(node_id: &str) -> Result<Vec<u8>, TransportError> {
    if !dns_name(node_id) {
        return Err(egress_refused());
    }
    let deadline = Instant::now() + FETCH_TIMEOUT;
    let addresses = crate::bounded_http_dns::resolve(&format!("{node_id}:443"), deadline)?;
    let Some(chosen) = addresses.first().copied() else {
        return Err(egress_refused());
    };
    if addresses.iter().any(|addr| !public_unicast(addr.ip())) {
        return Err(egress_refused());
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .resolve(node_id, chosen)
        .build()
        .map_err(|_| discovery_failed())?;
    let url = format!("https://{node_id}/.well-known/ramflux/server");
    let response = client.get(url).send().map_err(|error| hide_client_error(&error))?;
    if response.status().as_u16() != 200 {
        return Err(egress_refused());
    }
    if response.content_length().is_some_and(|len| len > RECORD_LIMIT as u64) {
        return Err(record_too_large());
    }
    let bytes = response.bytes().map_err(|_| discovery_failed())?;
    if bytes.len() > RECORD_LIMIT {
        return Err(record_too_large());
    }
    Ok(bytes.to_vec())
}

fn http_get_loopback(socket: SocketAddr) -> Result<Vec<u8>, TransportError> {
    if !socket.ip().is_loopback() || socket.port() == 0 {
        return Err(TransportError::Http(
            "federation egress test socket must be loopback".to_owned(),
        ));
    }
    let mut stream = TcpStream::connect_timeout(&socket, FETCH_TIMEOUT)?;
    stream.set_read_timeout(Some(FETCH_TIMEOUT))?;
    stream.set_write_timeout(Some(FETCH_TIMEOUT))?;
    write!(
        stream,
        "GET /.well-known/ramflux/server HTTP/1.1\r\nHost: {socket}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;
    read_fixed_body(&mut stream)
}

fn read_fixed_body(stream: &mut TcpStream) -> Result<Vec<u8>, TransportError> {
    let mut reader = std::io::BufReader::new(stream);
    let mut budget = HEADER_LIMIT;
    let status = header_line(&mut reader, &mut budget)?;
    let status = std::str::from_utf8(&status).map_err(|_| discovery_failed())?;
    let code = status.split_whitespace().nth(1).ok_or_else(discovery_failed)?;
    if code != "200" {
        return Err(egress_refused());
    }
    let mut length = None;
    loop {
        let header = header_line(&mut reader, &mut budget)?;
        if header == b"\r\n" || header == b"\n" {
            break;
        }
        let header = std::str::from_utf8(&header).map_err(|_| discovery_failed())?;
        let (name, value) = header.trim_end().split_once(':').ok_or_else(discovery_failed)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(egress_refused());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(discovery_failed());
            }
            let size = value.trim().parse::<usize>().map_err(|_| discovery_failed())?;
            if size > RECORD_LIMIT {
                return Err(record_too_large());
            }
            length = Some(size);
        }
    }
    let mut left = length.ok_or_else(discovery_failed)?;
    let mut body = Vec::new();
    let mut buffer = [0; 8192];
    while left != 0 {
        let size = left.min(buffer.len());
        let read = reader.read(&mut buffer[..size])?;
        if read == 0 {
            return Err(discovery_failed());
        }
        body.extend_from_slice(&buffer[..read]);
        left -= read;
    }
    Ok(body)
}

fn header_line<R: BufRead>(reader: &mut R, budget: &mut usize) -> Result<Vec<u8>, TransportError> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Err(discovery_failed());
        }
        let size = buffer.iter().position(|byte| *byte == b'\n').map_or(buffer.len(), |p| p + 1);
        if size > *budget || size == 0 {
            return Err(discovery_failed());
        }
        let Some(last) = buffer.get(size - 1) else {
            return Err(discovery_failed());
        };
        let complete = *last == b'\n';
        line.extend_from_slice(&buffer[..size]);
        reader.consume(size);
        *budget -= size;
        if complete {
            return Ok(line);
        }
    }
}

fn mesh_host_port(endpoint: &str) -> Result<&str, TransportError> {
    if endpoint.is_empty() || endpoint.len() > 256 || endpoint.starts_with("http://") {
        return Err(egress_refused());
    }
    let rest = endpoint.strip_prefix("https://").unwrap_or(endpoint);
    if rest
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\'))
    {
        return Err(egress_refused());
    }
    let Some((host, port)) = rest.rsplit_once(':') else {
        return Err(egress_refused());
    };
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.len() > 5
    {
        return Err(egress_refused());
    }
    Ok(rest)
}

fn dns_name(node_id: &str) -> bool {
    let bytes = node_id.as_bytes();
    (1..=63).contains(&bytes.len())
        && !node_id.starts_with(['.', '-'])
        && !node_id.ends_with(['.', '-'])
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && node_id.parse::<IpAddr>().is_err()
}

fn allowed_mesh(ip: IpAddr, allow_loopback: bool) -> bool {
    public_unicast(ip) || (allow_loopback && ip.is_loopback())
}

fn public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => public_v4(ip),
            None => public_v6(ip),
        },
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && !ip.is_unspecified()
        && !ip.is_documentation()
        && !(a == 100 && (b & 0xc0) == 64)
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 198 && (b == 18 || b == 19))
        && a < 240
        && a != 0
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    if octets[0] & 0xe0 != 0x20 {
        return false;
    }
    !(octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8)
}

fn hide_client_error(error: &reqwest::Error) -> TransportError {
    if error.is_redirect() { egress_refused() } else { discovery_failed() }
}

fn egress_refused() -> TransportError {
    TransportError::Http("federation peer egress refused".to_owned())
}

fn discovery_failed() -> TransportError {
    TransportError::Http("federation peer discovery failed".to_owned())
}

fn record_too_large() -> TransportError {
    TransportError::Http("federation discovery record exceeds size limit".to_owned())
}
