// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! S2 Prepare→Apply native issuance and the pairing HTTPS client.
//! Dormant: talks only to pairing routes; grants no account session.
use crate::SdkError;
use crate::custody::CustodyConnection;
use ramflux_protocol::custody::Envelope;
use ramflux_protocol::custody::pairing::PairingWire;
use ramflux_protocol::custody::pairing::full_transfer::lease::{DataLease, LeaseRequest};
use ramflux_protocol::custody::pairing::native::{
    Create, CreateSpec, Created, Failure, Issue, Issued, NativeReply,
};
use ramflux_protocol::custody::pairing::relay::{
    Claim, Claimed, Close, Closed, Poll, Polled, RelayFrame, Send, Sent,
};
use ramflux_protocol::custody::{CustodyProofAction, CustodyServerFrame};
use ramflux_protocol::encode_base64url;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

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
    /// Release the ceremony's proof connection on every terminal exit.
    fn close(&self) {}
    /// # Errors
    /// Native Issue refusal, `Busy`, or `Retired`.
    fn issue(&self, spec: CreateSpec) -> BoxFut<Result<Issued, SdkError>>;
    /// # Errors
    /// Native Create refusal, `Busy`, `Expired`, or `Retired`.
    fn create(&self, create: Create) -> BoxFut<Result<Created, SdkError>>;
    /// A data lease uses this ceremony's separate proof connection and grants no session.
    fn data_lease(&self, _request: LeaseRequest) -> BoxFut<Result<Envelope<DataLease>, SdkError>> {
        Box::pin(async { Err(SdkError::PairingCode("UpdateRequired")) })
    }
    /// Publish a user-approved exact candidate on this ceremony's authenticated connection.
    fn publish(
        &self,
        _publication: ramflux_protocol::custody::Publication,
    ) -> BoxFut<Result<String, SdkError>> {
        Box::pin(async { Err(SdkError::PairingCode("UpdateRequired")) })
    }
}

type NativeOpen<S> =
    dyn Fn() -> BoxFut<Result<CustodyConnection<S>, SdkError>> + std::marker::Send + Sync;

struct NativeState<S> {
    generation: u64,
    connection: Option<Arc<tokio::sync::Mutex<CustodyConnection<S>>>>,
}
type NativeConnection<S> = Arc<std::sync::Mutex<NativeState<S>>>;

/// A ceremony owns a fresh connection; the ordinary gateway connection is never shared.
pub struct FreshPairingNative<S = ramflux_transport::GatewayTcpTlsStream> {
    open: Arc<NativeOpen<S>>,
    connection: NativeConnection<S>,
}

impl FreshPairingNative {
    /// Build a factory over the ordinary authenticated custody connection constructor.
    #[must_use]
    pub fn new(
        config: crate::custody::CustodyNetworkConfig,
        vault: Arc<dyn crate::custody::PrimaryVault>,
    ) -> Self {
        Self::with_factory(Arc::new(move || {
            let config = config.clone();
            let vault = Arc::clone(&vault);
            Box::pin(CustodyConnection::connect_for_proof(config, vault))
        }))
    }
}

impl<S> FreshPairingNative<S> {
    /// Factory seam for real transport fixtures. One call for each Issue, never gateway handoff.
    #[must_use]
    pub fn with_factory(open: Arc<NativeOpen<S>>) -> Self {
        Self {
            open,
            connection: Arc::new(std::sync::Mutex::new(NativeState {
                generation: 0,
                connection: None,
            })),
        }
    }
}

impl<S: ramflux_transport::GatewaySessionTransport + std::marker::Send + 'static> PairingNative
    for FreshPairingNative<S>
{
    fn data_lease(&self, request: LeaseRequest) -> BoxFut<Result<Envelope<DataLease>, SdkError>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connection
            .clone();
        Box::pin(async move {
            ProofPairingNative::from_connection(
                connection.ok_or(SdkError::PairingCode("WrongContext"))?,
            )
            .data_lease(request)
            .await
        })
    }
    fn publish(
        &self,
        publication: ramflux_protocol::custody::Publication,
    ) -> BoxFut<Result<String, SdkError>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connection
            .clone();
        Box::pin(async move {
            ProofPairingNative::from_connection(
                connection.ok_or(SdkError::PairingCode("WrongContext"))?,
            )
            .publish(publication)
            .await
        })
    }
    fn close(&self) {
        let mut state = self.connection.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state.connection.take();
    }

    fn issue(&self, spec: CreateSpec) -> BoxFut<Result<Issued, SdkError>> {
        self.close();
        let open = Arc::clone(&self.open);
        let slot = Arc::clone(&self.connection);
        let generation = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).generation;
        Box::pin(async move {
            let connection = Arc::new(tokio::sync::Mutex::new(open().await?));
            let native = ProofPairingNative::from_connection(Arc::clone(&connection));
            match native.issue(spec).await {
                Ok(issued) => {
                    let mut state = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if state.generation != generation {
                        return Err(SdkError::PairingCode("WrongContext"));
                    }
                    state.connection = Some(connection);
                    Ok(issued)
                }
                Err(error) => Err(error),
            }
        })
    }

    fn create(&self, create: Create) -> BoxFut<Result<Created, SdkError>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .connection
            .clone();
        let slot = Arc::clone(&self.connection);
        Box::pin(async move {
            let connection = connection.ok_or(SdkError::PairingCode("WrongContext"))?;
            let result =
                ProofPairingNative::from_connection(Arc::clone(&connection)).create(create).await;
            if result.is_err() {
                let mut state = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if state
                    .connection
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &connection))
                {
                    state.connection.take();
                }
            }
            result
        })
    }
}

impl<S> Drop for FreshPairingNative<S> {
    fn drop(&mut self) {
        let mut state = self.connection.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state.connection.take();
    }
}

type ProveFn = dyn Fn(CustodyProofAction) -> BoxFut<Result<CustodyServerFrame, SdkError>>
    + std::marker::Send
    + Sync;

/// Production Issue/Create: authenticated custody `pairing_issue` / `pairing_create`.
pub struct ProofPairingNative {
    prove: Arc<ProveFn>,
}

impl ProofPairingNative {
    /// Wrap a custody proof worker (challenge → prove → Pairing reply).
    /// Test fixtures may inject a hand-signed closure; production uses [`Self::from_connection`].
    #[must_use]
    pub fn new(prove: Arc<ProveFn>) -> Self {
        Self { prove }
    }

    /// Production constructor: Issue/Create run through `CustodyConnection::prove`.
    /// Wiring into SDK construction stays CARRY P16.
    #[must_use]
    pub fn from_connection<S>(connection: Arc<tokio::sync::Mutex<CustodyConnection<S>>>) -> Self
    where
        S: ramflux_transport::GatewaySessionTransport + std::marker::Send + 'static,
    {
        Self::new(Arc::new(move |action| {
            let connection = Arc::clone(&connection);
            Box::pin(async move { connection.lock().await.prove(action).await })
        }))
    }
}

impl PairingNative for ProofPairingNative {
    fn data_lease(&self, request: LeaseRequest) -> BoxFut<Result<Envelope<DataLease>, SdkError>> {
        let prove = Arc::clone(&self.prove);
        Box::pin(async move {
            request.validate().map_err(|error| wire(&error))?;
            let expected = request.grant.clone();
            match prove(CustodyProofAction::PairingDataLease { request: Box::new(request) }).await?
            {
                CustodyServerFrame::PairingDataLease { lease } => {
                    lease.body.validate().map_err(|error| wire(&error))?;
                    if lease.body.grant != expected {
                        return Err(SdkError::PairingCode("WrongContext"));
                    }
                    Ok(*lease)
                }
                CustodyServerFrame::Pairing { reply } => match reply.reply {
                    NativeReply::Failure(failure) => Err(failure_error(&failure)),
                    _ => Err(SdkError::PairingCode("InvalidInput")),
                },
                CustodyServerFrame::Refused { code, .. } => Err(code.into()),
                _ => Err(SdkError::PairingCode("InvalidInput")),
            }
        })
    }

    fn publish(
        &self,
        publication: ramflux_protocol::custody::Publication,
    ) -> BoxFut<Result<String, SdkError>> {
        let prove = Arc::clone(&self.prove);
        Box::pin(async move {
            match prove(CustodyProofAction::Publish { publication: Box::new(publication) }).await? {
                CustodyServerFrame::Published { record_hash } => Ok(record_hash),
                CustodyServerFrame::Refused { code, .. } => Err(code.into()),
                _ => Err(SdkError::PairingCode("InvalidInput")),
            }
        })
    }
    fn issue(&self, spec: CreateSpec) -> BoxFut<Result<Issued, SdkError>> {
        let prove = Arc::clone(&self.prove);
        Box::pin(async move {
            let action = CustodyProofAction::PairingIssue {
                request: Box::new(Issue {
                    schema: "ramflux.pairing.Issue.v2".into(),
                    version: 2,
                    spec,
                }),
            };
            match apply_prove(prove.as_ref(), action).await? {
                NativeReply::Issued(issued) => Ok(*issued),
                NativeReply::Failure(failure) => Err(failure_error(&failure)),
                NativeReply::Created(_) => Err(SdkError::PairingCode("InvalidInput")),
            }
        })
    }

    fn create(&self, create: Create) -> BoxFut<Result<Created, SdkError>> {
        let prove = Arc::clone(&self.prove);
        Box::pin(async move {
            let action = CustodyProofAction::PairingCreate { request: Box::new(create) };
            match apply_prove(prove.as_ref(), action).await? {
                NativeReply::Created(created) => Ok(*created),
                NativeReply::Failure(failure) => Err(failure_error(&failure)),
                NativeReply::Issued(_) => Err(SdkError::PairingCode("InvalidInput")),
            }
        })
    }
}

async fn apply_prove(prove: &ProveFn, action: CustodyProofAction) -> Result<NativeReply, SdkError> {
    match prove(action).await? {
        CustodyServerFrame::Pairing { reply } => Ok(reply.reply),
        CustodyServerFrame::Refused { code, .. } => Err(code.into()),
        _ => Err(SdkError::PairingCode("InvalidInput")),
    }
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
    pub async fn apply(&self, native: &dyn PairingNative) -> Result<Issued, SdkError> {
        native.issue(self.spec.clone()).await
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
    pub async fn apply(&self, native: &dyn PairingNative) -> Result<Created, SdkError> {
        native.create(self.create.clone()).await
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
        let body = Zeroizing::new(value.to_wire_bytes().map_err(|e| wire(&e))?);
        let path = format!("/client/pairing/v1/{route}");
        let (status, reply) = post(&self.client, origin, &path, body).await?;
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
        ramflux_protocol::custody::pairing::WireError::Field(
            code @ ("TransferFloorsTooLarge"
            | "UpdateRequired"
            | "LeaseExpired"
            | "ChunkMismatch"
            | "SchemaMismatch"
            | "ManifestMismatch"),
        ) => SdkError::PairingCode(code),
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
        "TransferFloorsTooLarge" => SdkError::PairingCode("TransferFloorsTooLarge"),
        "TransferCapacity" => SdkError::PairingCode("TransferCapacity"),
        "UpdateRequired" => SdkError::PairingCode("UpdateRequired"),
        "VaultUnavailable" => SdkError::PairingCode("VaultUnavailable"),
        "NotFound" => SdkError::PairingCode("NotFound"),
        _ => SdkError::PairingCode("InvalidInput"),
    }
}

fn status_error(status: reqwest::StatusCode, _body: &[u8]) -> SdkError {
    SdkError::LocalBus(format!("pairing HTTPS status {status}"))
}

pub(super) fn require_https_origin(origin: &str) -> Result<(), SdkError> {
    let url = reqwest::Url::parse(origin).map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SdkError::PairingCode("InvalidInput"));
    }
    Ok(())
}

struct ErasingBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for ErasingBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

async fn post(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    body: Zeroizing<Vec<u8>>,
) -> Result<(reqwest::StatusCode, Vec<u8>), SdkError> {
    tokio::time::timeout(REQUEST_DEADLINE, async {
        let url = format!("{}{path}", origin.trim_end_matches('/'));
        let mut response = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONNECTION, "close")
            .body(bytes::Bytes::from_owner(ErasingBody(body)))
            .send()
            .await
            .map_err(http_error)?;
        let status = response.status();
        if response.content_length().is_some_and(|length| length > MAX_BODY as u64) {
            return Err(SdkError::PairingCode("InvalidInput"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(http_error)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(SdkError::PairingCode("InvalidInput"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    })
    .await
    .map_err(|_| {
        SdkError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "pairing HTTPS deadline expired",
        ))
    })?
}

fn http_error(error: reqwest::Error) -> SdkError {
    SdkError::LocalBus(error.without_url().to_string())
}

const _: () = assert!(POLL_SECS >= 1);
