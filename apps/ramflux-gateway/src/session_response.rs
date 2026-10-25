// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Distinguish failures writing to this client from recoverable request/upstream failures.
#[derive(Debug)]
pub(crate) struct ClientWriteFailure(pub ramflux_transport::TransportError);
impl std::fmt::Display for ClientWriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "client frame write failed: {}", self.0)
    }
}
impl std::error::Error for ClientWriteFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
pub(crate) fn request_kind(frame: &ramflux_node_core::GatewayClientFrame) -> &'static str {
    use ramflux_node_core::GatewayClientFrame as Frame;
    match frame {
        Frame::PushRouteRegister { .. } => "push_route_register",
        Frame::PushRouteDeregister { .. } => "push_route_deregister",
        Frame::VoiceLease { .. } => "voice_lease",
        Frame::Open { .. } => "open",
        Frame::Auth { .. } => "auth",
        Frame::Submit { .. } => "submit",
        Frame::OwnDeviceFanout { .. } => "own_device_fanout",
        Frame::IdentityRegister { .. } => "identity_register",
        Frame::PrekeyPublish { .. } => "prekey_publish",
        Frame::PrekeyFetch { .. } => "prekey_fetch",
        Frame::PrincipalManifestFetch { .. } => "principal_manifest_fetch",
        Frame::RelayTokenIssue { .. } => "relay_token_issue",
        Frame::RelayTokenV3Issue { .. } => "relay_token_v3_issue",
        Frame::Ack { .. } => "ack",
        Frame::Cursor { .. } => "cursor",
        Frame::Resume { .. } => "resume",
        Frame::Nack { .. } => "nack",
        Frame::Heartbeat { .. } => "heartbeat",
        Frame::Close { .. } => "close",
    }
}
