// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S2 Prepare→Apply native issuance and one temporary pairing HTTP client.
//! Dormant: talks only to pairing routes; grants no account session.
use crate::SdkError;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Failure, Issued};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, RelayFrame, Send, Sent,
};
use ramflux_protocol::encode_base64url;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const POLL_SECS: u64 = 2;
const CHUNK: usize = 8192;

/// Native Issue/Create apply target. Primary uses the existing S2 proof worker.
pub trait PairingNative: std::marker::Send + std::marker::Sync {
    /// # Errors
    /// Native Issue refusal, `Busy`, or `Retired`.
    fn issue(&self, spec: CreateSpec) -> Result<Issued, SdkError>;
    /// # Errors
    /// Native Create refusal, `Busy`, `Expired`, or `Retired`.
    fn create(&self, create: Create) -> Result<Created, SdkError>;
}

/// Prepared Issue body, applied once over the native worker.
pub struct PreparedIssue {
    spec: CreateSpec,
}

impl PreparedIssue {
    /// Validate and freeze the Issue specification before the network apply.
    /// # Errors
    /// Rejects an invalid `CreateSpec`.
    pub fn prepare(spec: CreateSpec) -> Result<Self, SdkError> {
        spec.validate().map_err(|e| wire(&e))?;
        Ok(Self { spec })
    }

    /// Apply the prepared Issue on the native proof path.
    /// # Errors
    /// Native Issue refusal.
    pub fn apply(&self, native: &dyn PairingNative) -> Result<Issued, SdkError> {
        native.issue(self.spec.clone())
    }

    #[must_use]
    pub fn spec(&self) -> &CreateSpec {
        &self.spec
    }
}

/// Prepared Create body, applied once over the native worker.
pub struct PreparedCreate {
    create: Create,
}

impl PreparedCreate {
    /// Freeze Create from the issued ticket and the same spec.
    /// # Errors
    /// Rejects a mismatched ticket or spec.
    pub fn prepare(
        ticket: ramflux_protocol::custody::Envelope<
            ramflux_protocol::custody::pairing::native::CreateTicket,
        >,
        spec: CreateSpec,
    ) -> Result<Self, SdkError> {
        let create =
            Create { schema: "ramflux.pairing.Create.v2".into(), version: 2, ticket, spec };
        create.validate().map_err(|e| wire(&e))?;
        Ok(Self { create })
    }

    /// Apply the prepared Create on the native proof path.
    /// # Errors
    /// Native Create refusal.
    pub fn apply(&self, native: &dyn PairingNative) -> Result<Created, SdkError> {
        native.create(self.create.clone())
    }
}

/// Temporary pairing HTTP client. One job; no resident account session.
#[derive(Clone)]
pub struct HttpRelay {
    origin: String,
}

impl HttpRelay {
    #[must_use]
    pub fn new(origin: String) -> Self {
        Self { origin }
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// POST a Claim.
    /// # Errors
    /// Transport, Busy, or a pairing Failure.
    pub fn claim(&self, claim: &Claim) -> Result<Claimed, SdkError> {
        self.round("claim", claim)
    }

    /// POST a Send frame.
    /// # Errors
    /// Transport, Busy, Replay, or a pairing Failure.
    pub fn send(&self, send: &Send) -> Result<Sent, SdkError> {
        self.round("send", send)
    }

    /// POST a Poll. Bounded to two seconds.
    /// # Errors
    /// Transport, Busy, or a pairing Failure.
    pub fn poll(&self, poll: &Poll) -> Result<Polled, SdkError> {
        self.round("poll", poll)
    }

    /// POST a Close.
    /// # Errors
    /// Transport or a pairing Failure.
    pub fn close(&self, close: &Close) -> Result<Closed, SdkError> {
        self.round("close", close)
    }

    fn round<T: PairingWire, R: PairingWire>(&self, route: &str, value: &T) -> Result<R, SdkError> {
        let body = value.to_wire_bytes().map_err(|e| wire(&e))?;
        let path = format!("/client/pairing/v1/{route}");
        let (status, reply) = post(&self.origin, &path, &body)?;
        if status != "200 OK" {
            return Err(status_error(&status, &reply));
        }
        match R::from_wire_bytes(&reply) {
            Ok(parsed) => Ok(parsed),
            Err(_) => match Failure::from_wire_bytes(&reply) {
                Ok(failure) => Err(failure_error(&failure)),
                Err(_) => Err(SdkError::PairingCode("InvalidInput")),
            },
        }
    }
}

/// Split a reveal object into ≤8KiB relay chunks.
/// # Errors
/// Rejects an empty body or more than three chunks.
pub fn reveal_chunks(object_id: [u8; 32], bytes: &[u8]) -> Result<Vec<RelayFrame>, SdkError> {
    offer_or_reveal_chunks(object_id, bytes, true)
}

fn offer_or_reveal_chunks(
    object_id: [u8; 32],
    bytes: &[u8],
    reveal: bool,
) -> Result<Vec<RelayFrame>, SdkError> {
    if bytes.is_empty() || bytes.len() > 24_576 {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    let total = u64::try_from(bytes.len()).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let count = total.div_ceil(CHUNK as u64);
    if count == 0 || count > 3 {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    let id = encode_base64url(object_id);
    let mut frames = Vec::new();
    for index in 0..count {
        let start = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(CHUNK))
            .ok_or(SdkError::PairingCode("InvalidInput"))?;
        let end = (start + CHUNK).min(bytes.len());
        let encoded = encode_base64url(&bytes[start..end]);
        let frame = if reveal {
            RelayFrame::RevealChunk {
                object_id: id.clone(),
                index,
                count,
                total_bytes: total,
                bytes: encoded,
            }
        } else {
            RelayFrame::OfferChunk {
                object_id: id.clone(),
                index,
                count,
                total_bytes: total,
                bytes: encoded,
            }
        };
        frame.validate().map_err(|e| wire(&e))?;
        frames.push(frame);
    }
    Ok(frames)
}

/// Assemble reveal-chunk bytes in index order.
/// # Errors
/// Rejects a gap, a length mismatch, or mixed object ids.
pub fn assemble_chunks(chunks: &[(u64, String, u64, u64, String)]) -> Result<Vec<u8>, SdkError> {
    if chunks.is_empty() {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    let object = &chunks[0].1;
    let count = chunks[0].2;
    let total = chunks[0].3;
    if u64::try_from(chunks.len()).ok() != Some(count) {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|chunk| chunk.0);
    let mut out = Vec::new();
    for (i, chunk) in ordered.iter().enumerate() {
        let index = u64::try_from(i).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
        if chunk.0 != index || chunk.1 != *object || chunk.2 != count || chunk.3 != total {
            return Err(SdkError::PairingCode("InvalidInput"));
        }
        let part = ramflux_protocol::decode_base64url(&chunk.4)
            .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
        out.extend_from_slice(&part);
    }
    if u64::try_from(out.len()).ok() != Some(total) {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok(out)
}

pub(super) fn wire(error: &ramflux_protocol::custody::pairing::WireError) -> SdkError {
    match error {
        ramflux_protocol::custody::pairing::WireError::Field(name) => SdkError::PairingField(name),
        ramflux_protocol::custody::pairing::WireError::Size
        | ramflux_protocol::custody::pairing::WireError::Json
        | ramflux_protocol::custody::pairing::WireError::Shape
        | ramflux_protocol::custody::pairing::WireError::NonCanonical => {
            SdkError::PairingCode("InvalidInput")
        }
    }
}

fn failure_error(failure: &Failure) -> SdkError {
    match failure.code.as_str() {
        "Busy" => SdkError::PairingCode("Busy"),
        "Expired" => SdkError::PairingCode("Expired"),
        "Retired" => SdkError::PairingCode("Retired"),
        "WrongRole" => SdkError::PairingCode("WrongRole"),
        "WrongContext" => SdkError::PairingCode("WrongContext"),
        "Replay" => SdkError::PairingCode("Replay"),
        "HeadChanged" => SdkError::PairingCode("HeadChanged"),
        "PrimaryRequired" => SdkError::PairingCode("PrimaryRequired"),
        "SasMismatch" => SdkError::PairingCode("SasMismatch"),
        "PublicationPending" => SdkError::PairingCode("PublicationPending"),
        "TransferCapacity" => SdkError::PairingCode("TransferCapacity"),
        "UpdateRequired" => SdkError::PairingCode("UpdateRequired"),
        "VaultUnavailable" => SdkError::PairingCode("VaultUnavailable"),
        "NotFound" => SdkError::PairingCode("NotFound"),
        _ => SdkError::PairingCode("InvalidInput"),
    }
}

fn status_error(status: &str, body: &[u8]) -> SdkError {
    let text = std::str::from_utf8(body).unwrap_or("request rejected");
    SdkError::LocalBus(format!("{status}: {text}"))
}

fn post(origin: &str, path: &str, body: &[u8]) -> Result<(String, Vec<u8>), SdkError> {
    let (host, addr) = dial_addr(origin)?;
    let addr = addr
        .to_socket_addrs()
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?
        .next()
        .ok_or(SdkError::PairingCode("InvalidInput"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(POLL_SECS))?;
    stream.set_read_timeout(Some(Duration::from_secs(POLL_SECS)))?;
    stream.set_write_timeout(Some(Duration::from_secs(POLL_SECS)))?;
    stream.set_nodelay(true)?;
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    split_http(&raw)
}

fn dial_addr(origin: &str) -> Result<(String, String), SdkError> {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or(origin);
    let host = rest.split('/').next().ok_or(SdkError::PairingCode("InvalidInput"))?;
    if host.is_empty() {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok((host.to_owned(), host.to_owned()))
}

fn split_http(raw: &[u8]) -> Result<(String, Vec<u8>), SdkError> {
    let text = std::str::from_utf8(raw).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or(SdkError::PairingCode("InvalidInput"))?;
    let status = head.lines().next().and_then(|line| {
        let mut parts = line.splitn(3, ' ');
        let _ = parts.next()?;
        let code = parts.next()?;
        let reason = parts.next().unwrap_or("");
        Some(format!("{code} {reason}"))
    });
    let status = status.ok_or(SdkError::PairingCode("InvalidInput"))?;
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.eq_ignore_ascii_case("content-length"))
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let bytes = body.as_bytes();
    let body = match length {
        Some(n) => bytes.get(..n).unwrap_or(bytes).to_vec(),
        None => bytes.to_vec(),
    };
    Ok((status, body))
}
