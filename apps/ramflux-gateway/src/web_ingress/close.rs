// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Close codes of the web listener. The reason string is the fixed name and nothing else.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseCode {
    Normal,
    ProtocolError,
    UnsupportedData,
    Policy,
    MessageTooBig,
    InternalError,
    BadFrame,
    ReauthRequired,
    AuthRefused,
    Timeout,
    RateLimited,
    NodeUnavailable,
}

impl CloseCode {
    #[must_use]
    pub(crate) const fn code(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::ProtocolError => 1002,
            Self::UnsupportedData => 1003,
            Self::Policy => 1008,
            Self::MessageTooBig => 1009,
            Self::InternalError => 1011,
            Self::BadFrame => 4400,
            Self::ReauthRequired => 4401,
            Self::AuthRefused => 4403,
            Self::Timeout => 4408,
            Self::RateLimited => 4429,
            Self::NodeUnavailable => 4503,
        }
    }

    #[must_use]
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::ProtocolError => "protocol_error",
            Self::UnsupportedData => "unsupported_data",
            Self::Policy => "policy",
            Self::MessageTooBig => "message_too_big",
            Self::InternalError => "internal_error",
            Self::BadFrame => "bad_frame",
            Self::ReauthRequired => "reauth_required",
            Self::AuthRefused => "auth_refused",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::NodeUnavailable => "node_unavailable",
        }
    }

    /// Close frame payload: big-endian status code followed by the reason (RFC 6455 §5.5.1).
    #[must_use]
    pub(crate) fn payload(self) -> Vec<u8> {
        let mut payload = self.code().to_be_bytes().to_vec();
        payload.extend_from_slice(self.reason().as_bytes());
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::CloseCode;

    #[test]
    fn close_payload_is_code_then_fixed_reason() {
        assert_eq!(CloseCode::AuthRefused.payload(), [&[0x11, 0x33][..], b"auth_refused"].concat());
        assert_eq!(CloseCode::MessageTooBig.code(), 1009);
        assert_eq!(CloseCode::Timeout.code(), 4408);
        assert!(CloseCode::NodeUnavailable.payload().len() <= 125);
    }
}
