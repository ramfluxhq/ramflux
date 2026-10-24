// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared error classification for bus responses and bounded task background work.
use crate::{SdkError, TaskRefusalCode};
use ramflux_transport::TransportError;

pub(crate) fn transport_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::NotAuthenticated => "Unauthenticated",
        TransportError::Tls(_) => "TransportSecurity",
        _ if transport_transient(error) => "Unavailable",
        _ => "ValidationFailed",
    }
}
fn transport_transient(error: &TransportError) -> bool {
    match error {
        TransportError::Quic(_)
        | TransportError::Io(_)
        | TransportError::NotOpen
        | TransportError::BackpressureRejected { .. }
        | TransportError::ShutdownDraining
        | TransportError::ShutdownTimeout { .. }
        | TransportError::RetryExhausted { .. } => true,
        TransportError::HttpClient(error) => {
            error.is_timeout()
                || error.is_connect()
                || error.status().is_some_and(|status| status.is_server_error())
        }
        TransportError::Http(message) => message
            .strip_prefix("HTTP ")
            .or_else(|| message.strip_prefix("HTTP/2 "))
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|code| code.trim_end_matches(':').parse::<u16>().ok())
            .is_some_and(|code| (500..600).contains(&code)),
        _ => false,
    }
}
pub(crate) fn approval_retryable(error: &SdkError) -> bool {
    match error {
        SdkError::InboundPending(_)
        | SdkError::Storage(_)
        | SdkError::Io(_)
        | SdkError::GatewaySessionNotEstablished
        | SdkError::GatewaySessionRejected(_) => true,
        SdkError::Transport(error) => transport_transient(error),
        _ => false,
    }
}

/// Isolates task-local failures while preserving storage and account-capacity backpressure.
pub(crate) fn task_scan<T>(result: Result<T, SdkError>) -> Result<Option<T>, SdkError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(
            error @ (SdkError::Storage(_)
            | SdkError::Io(_)
            | SdkError::TaskRefused {
                reason: TaskRefusalCode::AccountQuotaExhausted, ..
            }),
        ) => Err(error),
        Err(error) => {
            tracing::warn!(%error, "task row skipped; background scan continues");
            Ok(None)
        }
    }
}
