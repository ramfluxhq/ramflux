// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Preserve typed QUIC TLS alerts instead of reducing trust failures to availability strings.
use crate::TransportError;

pub(crate) fn connection(error: &quinn::ConnectionError) -> TransportError {
    let code = match error {
        quinn::ConnectionError::TransportError(error) => Some(u64::from(error.code)),
        quinn::ConnectionError::ConnectionClosed(close) => Some(u64::from(close.error_code)),
        _ => None,
    };
    if code.is_some_and(|code| (0x100..=0x1ff).contains(&code)) {
        TransportError::Tls(error.to_string())
    } else {
        TransportError::Quic(error.to_string())
    }
}
pub(crate) fn connect(error: quinn::ConnectError) -> TransportError {
    if crate::error::tls_source(&error) {
        return TransportError::Tls(error.to_string());
    }
    match error {
        quinn::ConnectError::InvalidServerName(name) => TransportError::InvalidDnsName(name),
        quinn::ConnectError::EndpointStopping | quinn::ConnectError::CidsExhausted => {
            TransportError::Quic(error.to_string())
        }
        other => wire(other.to_string()),
    }
}
pub(crate) fn wire(message: impl Into<String>) -> TransportError {
    TransportError::Protocol(ramflux_protocol::ProtocolError::TransportProtocol(message.into()))
}
