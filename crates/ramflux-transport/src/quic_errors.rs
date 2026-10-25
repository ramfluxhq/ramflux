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
    if code.is_some_and(|code| trust_alert(code)) {
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
        other => TransportError::Quic(other.to_string()),
    }
}
pub(crate) fn wire(message: impl Into<String>) -> TransportError {
    TransportError::Protocol(ramflux_protocol::ProtocolError::TransportProtocol(message.into()))
}

pub(crate) fn read(error: &quinn::ReadError) -> TransportError {
    if let quinn::ReadError::ConnectionLost(cause) = error
        && let TransportError::Tls(message) = connection(cause)
    {
        return TransportError::Tls(message);
    }
    TransportError::Quic(format!("{error}; detail={error:?}"))
}
pub(crate) fn write(error: &quinn::WriteError) -> TransportError {
    if let quinn::WriteError::ConnectionLost(cause) = error
        && let TransportError::Tls(message) = connection(cause)
    {
        return TransportError::Tls(message);
    }
    TransportError::Quic(format!("{error}; detail={error:?}"))
}
pub(crate) fn read_to_end(error: &quinn::ReadToEndError) -> TransportError {
    if let quinn::ReadToEndError::Read(cause) = error
        && let TransportError::Tls(message) = read(cause)
    {
        return TransportError::Tls(message);
    }
    TransportError::Quic(error.to_string())
}

pub(crate) fn trust_alert(code: u64) -> bool {
    matches!(code, 0x12a..=0x12e | 0x130 | 0x131 | 0x133 | 0x174 | 0x178)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_certificate_and_trust_alerts_are_permanent_tls_failures() {
        for code in [0x12a, 0x12b, 0x12c, 0x12d, 0x12e, 0x130, 0x131, 0x133, 0x174, 0x178] {
            assert!(trust_alert(code));
        }
        for code in [0x100, 0x128, 0x132, 0x150, 0x1ff, 0x200] {
            assert!(!trust_alert(code));
        }
        assert!(!crate::error::tls_source(&rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure
        )));
        assert!(!crate::error::tls_source(&rustls::Error::AlertReceived(
            rustls::AlertDescription::InternalError
        )));
        assert!(crate::error::tls_source(&rustls::Error::AlertReceived(
            rustls::AlertDescription::UnknownCA
        )));
    }
}
