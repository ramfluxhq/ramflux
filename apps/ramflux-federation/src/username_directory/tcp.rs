// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded TLS readers transfer the actual response writer to the witness actor.
use super::{Result, directory, error, refuse, tls, wire};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

pub type Stream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

pub struct Incoming {
    pub transport: Transport,
    pub source: IpAddr,
    pub exporter: [u8; 32],
    pub path: String,
    pub body: Vec<u8>,
    pub deadline: Instant,
}

pub enum Transport {
    Tcp { stream: Box<Stream>, staged: Option<usize> },
    Quic(Box<super::quic::Writer>),
}

fn pause(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline
        || !ramflux_node_core::service_shutdown_sleep(Duration::from_millis(5))
    {
        return refuse("directory connection deadline");
    }
    Ok(())
}

fn read_exact(stream: &mut impl Read, output: &mut [u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    let mut idle = Instant::now();
    while offset < output.len() {
        if Instant::now() >= deadline || ramflux_node_core::service_shutdown_token().is_cancelled()
        {
            return refuse("directory read deadline");
        }
        match stream.read(output.get_mut(offset..).ok_or_else(|| error("directory read offset"))?) {
            Ok(0) => return refuse("directory connection closed"),
            Ok(count) => {
                offset += count;
                idle = Instant::now();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if idle.elapsed() >= Duration::from_secs(2) {
                    return refuse("directory read idle");
                }
                pause(deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all(stream: &mut Stream, bytes: &[u8], deadline: Instant) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match stream.write(bytes.get(offset..).ok_or_else(|| error("directory write offset"))?) {
            Ok(0) => return refuse("directory connection closed"),
            Ok(count) => offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => pause(deadline)?,
            Err(error) => return Err(error.into()),
        }
    }
    loop {
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => pause(deadline)?,
            Err(error) => return Err(error.into()),
        }
    }
}

pub fn accept(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    node: &str,
    seed: &[u8; 32],
) -> Result<Incoming> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let source = socket.peer_addr()?.ip();
    socket.set_nonblocking(true)?;
    let mut connection = rustls::ServerConnection::new(config)?;
    connection.set_buffer_limit(Some(16384));
    let mut stream = rustls::StreamOwned::new(connection, socket);
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => pause(deadline)?,
            Err(error) => return Err(error.into()),
        }
    }
    if stream.conn.alpn_protocol() != Some(tls::ALPN) {
        return refuse("directory ALPN mismatch");
    }
    let exporter = stream.conn.export_keying_material([0; 32], tls::EXPORTER, None)?;
    let mut challenge = [0; 32];
    read_exact(&mut stream, &mut challenge, deadline)?;
    let identity = directory::DirectorySigner::from_seed(seed).channel_identity(
        node,
        &exporter,
        &ramflux_protocol::encode_base64url(challenge),
        crate::now_unix_seconds()?,
    )?;
    write_all(&mut stream, &wire::encode(&identity)?, deadline)?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= 16384 {
            return refuse("directory headers bound");
        }
        let mut byte = [0];
        read_exact(&mut stream, &mut byte, deadline)?;
        headers.extend(byte);
    }
    let headers = std::str::from_utf8(&headers)?;
    let mut lines = headers.split("\r\n");
    let first = lines.next().ok_or_else(|| error("directory request line"))?;
    let path = first
        .strip_prefix("POST ")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .ok_or_else(|| error("directory request line"))?
        .to_owned();
    let mut length = None;
    let mut host = false;
    let mut content_type = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| error("directory header"))?;
        if name.is_empty() || name.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-') {
            return refuse("directory header name");
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return refuse("directory duplicate length");
            }
            let parsed: usize = value.parse()?;
            if parsed > directory::MAX_REPORT_BYTES || parsed.to_string() != value {
                return refuse("directory body bound");
            }
            length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return refuse("directory transfer encoding");
        } else if name.eq_ignore_ascii_case("host") {
            if host || value.is_empty() {
                return refuse("directory host header");
            }
            host = true;
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type || value != "application/json" {
                return refuse("directory content type");
            }
            content_type = true;
        }
    }
    if !host || !content_type {
        return refuse("directory required headers");
    }
    let length = length.ok_or_else(|| error("directory length required"))?;
    let mut body = vec![0; length];
    read_exact(&mut stream, &mut body, deadline)?;
    Ok(Incoming {
        transport: Transport::Tcp { stream: Box::new(stream), staged: None },
        source,
        exporter,
        path,
        body,
        deadline,
    })
}

impl Incoming {
    pub fn certificates(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]> {
        match &self.transport {
            Transport::Tcp { stream, .. } => stream.conn.peer_certificates(),
            Transport::Quic(writer) => Some(&writer.chain),
        }
    }
    /// Return progress only after encrypted bytes reach this same socket. Pending ciphertext
    /// remains owned here; every subsequent `write_tls` call must re-enter the witness fence.
    pub fn try_write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Transport::Tcp { stream, staged } = &mut self.transport else {
            if let Transport::Quic(writer) = &mut self.transport {
                return writer.try_write(bytes);
            }
            return Err(std::io::Error::other("directory transport"));
        };
        if let Some(count) = *staged {
            if count > bytes.len() {
                return Err(std::io::Error::other("directory writer mismatch"));
            }
        } else {
            let chunk = bytes
                .get(..bytes.len().min(8192))
                .ok_or_else(|| std::io::Error::other("directory write bound"))?;
            let count = stream.conn.writer().write(chunk)?;
            if count == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            *staged = Some(count);
        }
        if stream.conn.wants_write() {
            stream.conn.write_tls(&mut stream.sock)?;
        }
        if stream.conn.wants_write() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let count =
            staged.take().ok_or_else(|| std::io::Error::other("directory write progress"))?;
        Ok(count)
    }
}
