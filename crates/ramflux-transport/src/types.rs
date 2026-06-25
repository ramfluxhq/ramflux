use ramflux_protocol::{Ack, Cursor, Envelope, Nack, ObjectChunkRequest, SignedRequest};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use crate::TransportError;

pub type TransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum BackendKind {
    GrpcH2,
    QuicQuinn,
    HttpsJson,
}

impl BackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GrpcH2 => "grpc_h2",
            Self::QuicQuinn => "quic_quinn",
            Self::HttpsJson => "https_json",
        }
    }

    #[must_use]
    pub const fn production_status(self) -> BackendProductionStatus {
        match self {
            Self::GrpcH2 => BackendProductionStatus::NonProduction {
                reason: "grpc_h2 remains a compatibility/test seam until TLS server streaming is wired",
            },
            Self::QuicQuinn => BackendProductionStatus::Production {
                role: "primary production envelope and object transport",
            },
            Self::HttpsJson => {
                BackendProductionStatus::Production { role: "mTLS JSON compatibility fallback" }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendProductionStatus {
    Production { role: &'static str },
    NonProduction { reason: &'static str },
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct AuthRequest {
    pub device_id: String,
    pub signed_request_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TransportSession {
    pub backend: BackendKind,
    pub session_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SubmitEnvelopeRequest {
    pub signed_request: SignedRequest,
    pub envelope: Envelope,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SubmitEnvelopeResult {
    pub backend: BackendKind,
    pub signed_request_canonical: Vec<u8>,
    pub envelope_canonical: Vec<u8>,
    pub envelope: Envelope,
}

pub type SendEnvelopeRequest = SubmitEnvelopeRequest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeBatch {
    pub backend: BackendKind,
    pub cursor: Cursor,
    pub envelopes: Vec<Envelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectChunkStream {
    pub backend: BackendKind,
    pub request: ObjectChunkRequest,
    pub chunks: Vec<Vec<u8>>,
    pub resume_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryFrame {
    pub backend: BackendKind,
    pub envelope: Envelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckFrame {
    pub backend: BackendKind,
    pub ack: Ack,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NackFrame {
    pub backend: BackendKind,
    pub nack: Nack,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorFrame {
    pub backend: BackendKind,
    pub cursor: Cursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshTlsConfig {
    pub ca_cert: PathBuf,
    pub service_cert: PathBuf,
    pub service_key: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshHttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct GatewayQuicRequest {
    pub method: String,
    pub path: String,
    pub body: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct GatewayQuicResponse {
    pub status: u16,
    pub body: serde_json::Value,
}
pub trait TransportBackend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn production_status(&self) -> BackendProductionStatus {
        self.kind().production_status()
    }
    fn open(&self) -> TransportFuture<'_, TransportSession>;
    fn auth(
        &self,
        session: TransportSession,
        request: AuthRequest,
    ) -> TransportFuture<'_, TransportSession>;
    fn submit_envelope(
        &self,
        request: SubmitEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult>;
    fn send_envelope(
        &self,
        request: SendEnvelopeRequest,
    ) -> TransportFuture<'_, SubmitEnvelopeResult> {
        self.submit_envelope(request)
    }
    fn pull_envelopes(&self, cursor: Cursor) -> TransportFuture<'_, EnvelopeBatch>;
    fn deliver(&self) -> TransportFuture<'_, DeliveryFrame>;
    fn ack(&self, ack: Ack) -> TransportFuture<'_, AckFrame>;
    fn nack(&self, nack: Nack) -> TransportFuture<'_, NackFrame>;
    fn cursor(&self, cursor: Cursor) -> TransportFuture<'_, CursorFrame>;
    fn request_object_chunks(
        &self,
        request: ObjectChunkRequest,
    ) -> TransportFuture<'_, ObjectChunkStream>;
}

pub trait TransportListener: Send + Sync {
    fn accept(&self) -> TransportFuture<'_, TransportSession>;
}
