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
/// Retain the exact overload discriminator while keeping context on other failures.
pub(crate) fn durable_rejection_reason(context: &str, error: &anyhow::Error) -> String {
    if matches!(
        error.downcast_ref::<ramflux_node_core::NodeCoreError>(),
        Some(ramflux_node_core::NodeCoreError::GatewayWriterBusy)
    ) {
        ramflux_node_core::NodeCoreError::GatewayWriterBusy.to_string()
    } else {
        format!("{context}: {error}")
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busy_rejection_preserves_wire_type_and_other_context() {
        let busy = anyhow::Error::new(ramflux_node_core::NodeCoreError::GatewayWriterBusy)
            .context("waiting for disk");
        assert_eq!(
            durable_rejection_reason("submit source rejected", &busy),
            "gateway_writer_busy: retryable"
        );
        for source in ["invalid signature", "gateway_writer_busy: retryable"] {
            assert_eq!(
                durable_rejection_reason(
                    "submit source rejected",
                    &anyhow::anyhow!(source.to_owned())
                ),
                format!("submit source rejected: {source}")
            );
        }
    }
}
