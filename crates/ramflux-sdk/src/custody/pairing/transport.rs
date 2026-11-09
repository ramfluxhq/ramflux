// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S2 Prepare→Apply native issuance and the pairing HTTPS client.
//! Dormant: talks only to pairing routes; grants no account session.
use crate::SdkError;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::native::{Create, CreateSpec, Created, Failure, Issued};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, RelayFrame, Send, Sent,
};
use ramflux_protocol::encode_base64url;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

const POLL_SECS: u64 = 2;
const CHUNK: usize = 8192;
/// P06 relay body cap (`PAIRING_MAX_BODY_BYTES`).
const MAX_BODY: usize = 16 * 1024;
/// P06 relay request timeout (`PAIRING_REQUEST_TIMEOUT`).
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + std::marker::Send>>;

/// Injected pairing capability and HTTPS trust. Built once at SDK startup.
#[derive(Clone, Debug, Default)]
pub struct PairingConfig {
    pub enabled: bool,
    pub extra_root_ca_pem: Option<String>,
}

impl PairingConfig {
    /// Production reader: env once at process start. Tests construct this directly.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            enabled: matches!(std::env::var("RAMFLUX_DEVICE_PAIRING_ENABLED").as_deref(), Ok("1")),
            extra_root_ca_pem: None,
        }
    }
}

/// Native Issue/Create apply target. Primary uses the existing S2 proof worker.
pub trait PairingNative: std::marker::Send + std::marker::Sync {
    /// # Errors
    /// Native Issue refusal, `Busy`, or `Retired`.
    fn issue(&self, spec: CreateSpec) -> Result<Issued, SdkError>;
    /// # Errors
    /// Native Create refusal, `Busy`, `Expired`, or `Retired`.
    fn create(&self, create: Create) -> Result<Created, SdkError>;
}

/// HTTPS (or in-process) pairing relay. Production is [`HttpRelay`].
pub trait PairingTransport: std::marker::Send + Sync {
    fn claim(&self, origin: String, claim: Claim) -> BoxFut<Result<Claimed, SdkError>>;
    fn send(&self, origin: String, send: Send) -> BoxFut<Result<Sent, SdkError>>;
    fn poll(&self, origin: String, poll: Poll) -> BoxFut<Result<Polled, SdkError>>;
    fn close(&self, origin: String, close: Close) -> BoxFut<Result<Closed, SdkError>>;
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

    #[must_use]
    pub fn create(&self) -> &Create {
        &self.create
    }
}

/// Temporary pairing HTTPS client. One job; no resident account session.
#[derive(Clone)]
pub struct HttpRelay {
    client: reqwest::Client,
}

impl HttpRelay {
    /// Build a rustls HTTPS client. `extra_root_ca_pem` is test-only fixture trust.
    /// # Errors
    /// Rejects a malformed extra root CA or a client that cannot be built.
    pub fn from_config(config: &PairingConfig) -> Result<Self, SdkError> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_DEADLINE)
            .pool_max_idle_per_host(0);
        if let Some(pem) = &config.extra_root_ca_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|error| SdkError::LocalBus(error.to_string()))?;
            builder = builder.add_root_certificate(cert);
        }
        let client =
            builder.build().map_err(|error| SdkError::LocalBus(error.without_url().to_string()))?;
        Ok(Self { client })
    }

    async fn round<T: PairingWire, R: PairingWire>(
        &self,
        origin: &str,
        route: &str,
        value: &T,
    ) -> Result<R, SdkError> {
        require_https_origin(origin)?;
        let body = value.to_wire_bytes().map_err(|e| wire(&e))?;
        let path = format!("/client/pairing/v1/{route}");
        let (status, reply) = post(&self.client, origin, &path, &body).await?;
        if status != reqwest::StatusCode::OK {
            return Err(status_error(status, &reply));
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

impl PairingTransport for HttpRelay {
    fn claim(&self, origin: String, claim: Claim) -> BoxFut<Result<Claimed, SdkError>> {
        let this = self.clone();
        Box::pin(async move { this.round(&origin, "claim", &claim).await })
    }
    fn send(&self, origin: String, send: Send) -> BoxFut<Result<Sent, SdkError>> {
        let this = self.clone();
        Box::pin(async move { this.round(&origin, "send", &send).await })
    }
    fn poll(&self, origin: String, poll: Poll) -> BoxFut<Result<Polled, SdkError>> {
        let this = self.clone();
        Box::pin(async move { this.round(&origin, "poll", &poll).await })
    }
    fn close(&self, origin: String, close: Close) -> BoxFut<Result<Closed, SdkError>> {
        let this = self.clone();
        Box::pin(async move { this.round(&origin, "close", &close).await })
    }
}

/// Split a reveal object into ≤8KiB relay chunks.
/// # Errors
/// Rejects an empty body or more than three chunks.
pub fn reveal_chunks(object_id: [u8; 32], bytes: &[u8]) -> Result<Vec<RelayFrame>, SdkError> {
    offer_or_reveal_chunks(object_id, bytes, true)
}

/// Split a context-offer object into ≤8KiB relay chunks.
/// # Errors
/// Rejects an empty body or more than three chunks.
pub fn offer_chunks(object_id: [u8; 32], bytes: &[u8]) -> Result<Vec<RelayFrame>, SdkError> {
    offer_or_reveal_chunks(object_id, bytes, false)
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

fn status_error(status: reqwest::StatusCode, body: &[u8]) -> SdkError {
    let text = std::str::from_utf8(body).unwrap_or("request rejected");
    SdkError::LocalBus(format!("{status}: {text}"))
}

fn require_https_origin(origin: &str) -> Result<(), SdkError> {
    let url = reqwest::Url::parse(origin).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok(())
}

async fn post(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    body: &[u8],
) -> Result<(reqwest::StatusCode, Vec<u8>), SdkError> {
    let url = format!("{origin}{path}");
    let request = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONNECTION, "close")
        .body(body.to_vec());
    let response = tokio::time::timeout(REQUEST_DEADLINE, request.send())
        .await
        .map_err(|_| {
            SdkError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pairing HTTPS deadline expired",
            ))
        })?
        .map_err(http_error)?;
    let status = response.status();
    if let Some(length) = response.content_length()
        && length > MAX_BODY as u64
    {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = tokio::time::timeout(REQUEST_DEADLINE, response.chunk())
        .await
        .map_err(|_| {
            SdkError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pairing HTTPS deadline expired",
            ))
        })?
        .map_err(http_error)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(SdkError::PairingCode("InvalidInput"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

fn http_error(error: reqwest::Error) -> SdkError {
    SdkError::LocalBus(error.without_url().to_string())
}

const _: () = assert!(POLL_SECS >= 1);
