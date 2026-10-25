// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport is not open")]
    NotOpen,
    #[error("transport is not authenticated")]
    NotAuthenticated,
    #[error("backend mismatch: expected {expected}, got {actual}")]
    BackendMismatch { expected: &'static str, actual: &'static str },
    #[error("codec error: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("state lock poisoned")]
    LockPoisoned,
    #[error("delivery queue is empty")]
    EmptyDeliveryQueue,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("HTTP client error: {0}")]
    HttpClient(#[source] reqwest::Error),
    #[error("QUIC error: {0}")]
    Quic(String),
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    #[error("frame too large: {len} bytes")]
    FrameTooLarge { len: usize },
    #[error("transport backend is not production-grade: backend={backend}, reason={reason}")]
    NonProductionBackend { backend: &'static str, reason: &'static str },
    #[error("backpressure rejected request: capacity={capacity}, in_flight={in_flight}")]
    BackpressureRejected { capacity: u64, in_flight: u64 },
    #[error("transport is draining and no longer accepts new work")]
    ShutdownDraining,
    #[error("shutdown drain timed out with {in_flight} in-flight operations")]
    ShutdownTimeout { in_flight: u64 },
    #[error("retry attempts exhausted after {attempts} attempts")]
    RetryExhausted { attempts: u32 },
    #[error("transport operation unsupported: {operation}")]
    UnsupportedOperation { operation: &'static str },
}
use ramflux_protocol::ProtocolError;

impl From<reqwest::Error> for TransportError {
    fn from(error: reqwest::Error) -> Self {
        if tls_source(&error) { Self::Tls(error.to_string()) } else { Self::HttpClient(error) }
    }
}
impl TransportError {
    /// Reports a TLS failure even when an HTTP caller retained the original source chain.
    #[must_use]
    pub fn is_tls_failure(&self) -> bool {
        matches!(self, Self::Tls(_)) || matches!(self, Self::HttpClient(error) if tls_source(error))
    }
}
pub(crate) fn tls_source(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<rustls::Error>() {
            return match error {
                rustls::Error::AlertReceived(alert) => {
                    crate::quic_errors::trust_alert(0x100 + u64::from(u8::from(*alert)))
                }
                _ => true,
            };
        }
        // Some I/O wrappers expose their custom payload separately from Error::source.
        if let Some(inner) =
            error.downcast_ref::<std::io::Error>().and_then(std::io::Error::get_ref)
            && tls_source(inner)
        {
            return true;
        }
        current = error.source();
    }
    false
}
