// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! C consumers see the same trust, authentication and retry boundaries as local bus clients.
use super::*;
use ramflux_transport::TransportError as T;
#[test]
fn r8_c_abi_distinguishes_authentication_security_and_invalid_frames_from_outages() {
    for (error, code) in [
        (T::NotAuthenticated, RamfluxErrorCode::AuthFailed),
        (T::Tls("untrusted CA".into()), RamfluxErrorCode::AuthFailed),
        (T::Quic("deadline".into()), RamfluxErrorCode::TransportUnavailable),
        (T::Http("HTTP 429: slow down".into()), RamfluxErrorCode::TransportUnavailable),
        (T::Http("HTTP 403: denied".into()), RamfluxErrorCode::InvalidArgument),
        (T::FrameTooLarge { len: 2_000_000 }, RamfluxErrorCode::InvalidArgument),
        (
            T::Protocol(ramflux_protocol::ProtocolError::NotObject),
            RamfluxErrorCode::InvalidArgument,
        ),
    ] {
        assert_eq!(map_sdk_error(&SdkError::Transport(error)).code, code);
    }
    assert_eq!(
        map_sdk_error(&SdkError::ContactUnavailable(Box::new(SdkError::Transport(T::Tls(
            "untrusted CA".into()
        )))))
        .code,
        RamfluxErrorCode::AuthFailed
    );
}
