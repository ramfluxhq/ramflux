// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared error classification for bus responses and bounded task background work.
use crate::{SdkError, TaskRefusalCode};
use ramflux_transport::TransportError;

pub(crate) fn transport_code(error: &TransportError) -> &'static str {
    if error.is_tls_failure() {
        return "TransportSecurity";
    }
    match error {
        TransportError::NotAuthenticated => "Unauthenticated",
        TransportError::Tls(_) => "TransportSecurity",
        _ if transport_transient(error) => "Unavailable",
        _ => "ValidationFailed",
    }
}
fn transport_transient(error: &TransportError) -> bool {
    if error.is_tls_failure() {
        return false;
    }
    match error {
        TransportError::Quic(_)
        | TransportError::Io(_)
        | TransportError::NotOpen
        | TransportError::BackpressureRejected { .. }
        | TransportError::ShutdownDraining
        | TransportError::ShutdownTimeout { .. }
        | TransportError::RetryExhausted { .. } => true,
        TransportError::HttpClient(error) => http_transient(error),
        TransportError::Http(message) => message
            .strip_prefix("HTTP ")
            .or_else(|| message.strip_prefix("HTTP/2 "))
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|code| code.trim_end_matches(':').parse::<u16>().ok())
            .is_some_and(retry_status),
        _ => false,
    }
}
pub(crate) fn approval_retryable(error: &SdkError) -> bool {
    match error {
        SdkError::InboundPending(_)
        | SdkError::ContactRequestCapacity(_)
        | SdkError::TaskManifestWorkerCapacity
        | SdkError::Storage(_)
        | SdkError::Io(_)
        | SdkError::GatewaySessionNotEstablished
        | SdkError::GatewaySessionRejected(_) => true,
        SdkError::Transport(error) => transport_transient(error),
        _ => false,
    }
}

/// Isolates task-local failures while preserving storage and account-capacity backpressure.
pub(crate) fn task_scan<T>(row: &str, result: Result<T, SdkError>) -> Result<Option<T>, SdkError> {
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
            crate::task_warnings::warn(row, &error, "task row skipped; background scan continues");
            Ok(None)
        }
    }
}

fn retry_status(code: u16) -> bool {
    matches!(code, 408 | 429 | 500..=599)
}

fn http_transient(error: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<reqwest::Error>()
            && (error.is_timeout()
                || error.is_connect()
                || error.is_body()
                || error.status().is_some_and(|status| retry_status(status.as_u16())))
        {
            return true;
        }
        source = error.source();
    }
    false
}

/// Domain availability wrappers cannot downgrade a failed authentication or trust check.
pub(crate) fn security_code(mut error: &SdkError) -> Option<&'static str> {
    while let SdkError::ContactUnavailable(source) = error {
        error = source;
    }
    if let SdkError::Transport(error) = error {
        let code = transport_code(error);
        if matches!(code, "Unauthenticated" | "TransportSecurity") {
            return Some(code);
        }
    }
    None
}
