// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
mod async_send;
pub(crate) use crate::client::routed::SealForward;
pub(crate) use async_send::PlaintextForward;

mod forward;

pub(crate) fn forward_slots() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    forward::slots()
}

struct FederatedSendOptions {
    franking: bool,
    route: crate::client::routed::Route,
}

impl RamfluxClient {
    #[cfg(test)]
    pub(crate) async fn forward_federated_envelope(
        engine: &mut impl GatewaySessionAccess,
        federation: &LocalBusFederationRoute,
        envelope: ramflux_protocol::Envelope,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        async_send::submit_over_session(engine, federation, envelope).await
    }

    pub async fn send_plaintext_federated_direct_message(
        &self,
        engine: &mut impl GatewaySessionAccess,
        mut message: GatewayDirectMessage,
        plaintext: &[u8],
        federation: &LocalBusFederationRoute,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        message.ttl = self.content_ttl()?;
        Self::normalize_recipient(&mut message)?;
        let text = std::str::from_utf8(plaintext)
            .map_err(|_| SdkError::LocalBus("Message text must be UTF-8".into()))?;
        let prepared = self.prepare_authored_content(
            &mut message,
            None,
            &ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Message(
                    ramflux_protocol::message::Message { text: text.into(), ..Default::default() },
                )),
            },
        )?;
        self.send_plaintext_federated_direct_message_inner(
            engine,
            message,
            &prepared.wire,
            federation,
            &FederatedSendOptions { franking: true, route: crate::client::routed::Route::direct() },
        )
        .await
    }

    pub(crate) async fn send_plaintext_federated_direct_message_without_franking(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: GatewayDirectMessage,
        plaintext: &[u8],
        federation: &LocalBusFederationRoute,
        route: crate::client::routed::Route,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        self.send_plaintext_federated_direct_message_inner(
            engine,
            message,
            plaintext,
            federation,
            &FederatedSendOptions { franking: false, route },
        )
        .await
    }

    async fn send_plaintext_federated_direct_message_inner(
        &self,
        engine: &mut impl GatewaySessionAccess,
        mut message: GatewayDirectMessage,
        plaintext: &[u8],
        federation: &LocalBusFederationRoute,
        options: &FederatedSendOptions,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        Self::normalize_recipient(&mut message)?;
        let prekey_url = federation
            .recipient_prekey_url
            .as_deref()
            .or(engine.config().prekey_http_url.as_deref());
        let sealed = self.seal_routed_federated_as(
            engine,
            &message,
            plaintext,
            prekey_url,
            options.route.clone(),
        )?;
        let pending =
            self.prepare_federated_packet(engine, &mut message, plaintext, sealed, options)?;
        trace_forward(federation, &pending.envelope);
        async_send::submit_over_session(engine, federation, pending.envelope).await
    }

    fn prepare_federated_packet(
        &self,
        engine: &impl GatewaySessionAccess,
        message: &mut GatewayDirectMessage,
        plaintext: &[u8],
        sealed: crate::client::routed::SealedRouted,
        options: &FederatedSendOptions,
    ) -> Result<PendingForward, SdkError> {
        let _ = options.franking;
        let envelope =
            crate::dm::gateway_envelope_from_sealed(engine.config(), message, sealed, None)?;
        if options.route.kind == crate::client::routed::Kind::Direct {
            self.project_authored_message(message, plaintext, &message.encrypted_body)?;
        }
        Ok(PendingForward { envelope })
    }

    /// # Errors
    /// Returns an error when envelope construction or the federation forward request fails.
    pub async fn forward_federated_gateway_message(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &GatewayDirectMessage,
        federation: &LocalBusFederationRoute,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let envelope = gateway_direct_message_envelope(engine.config(), message, None)?;
        tracing::info!(
            source_node_id = %federation.source_node_id,
            target_node_id = %federation.target_node_id,
            federation_url = %federation.federation_url,
            envelope_id = %envelope.envelope_id,
            target_delivery_id = %envelope.target_delivery_id,
            route_decision = "remote_federation_forward",
            "submitting federated gateway message to source node federation surface"
        );
        async_send::submit_over_session(engine, federation, envelope).await
    }

    /// # Errors
    /// Returns an error when the contact event cannot be encrypted or forwarded.
    pub async fn send_plaintext_federated_contact_event(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event_type: &str,
        request: &LocalBusContactFederatedRequest,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let (message, body) = contact_message(self, event_type, request)?;
        self.send_plaintext_federated_direct_message_without_franking(
            engine,
            message,
            &body,
            &request.federation,
            crate::client::routed::Route::control(),
        )
        .await
    }

    /// # Errors
    pub fn register_node(&mut self, node_id: &str, endpoint: &str) -> ramflux_sync::FederationNode {
        self.federation_mesh.register_node(node_id, endpoint)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn establish_trusted_link(&mut self, left: &str, right: &str) -> Result<(), SdkError> {
        Ok(self.federation_mesh.establish_trusted_link(left, right)?)
    }

    /// # Errors
    /// Returns an error when the node is not active or cannot be bound.
    pub fn bind_identity_home(&mut self, identity: &str, node_id: &str) -> Result<(), SdkError> {
        Ok(self.federation_mesh.bind_identity_home(identity, node_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn send_cross_node_message(
        &mut self,
        from_identity: &str,
        to_identity: &str,
        body_ciphertext: &[u8],
    ) -> Result<FederationMessage, SdkError> {
        Ok(self.federation_mesh.send_cross_node_message(
            from_identity,
            to_identity,
            body_ciphertext,
        )?)
    }
}

struct PendingForward {
    envelope: ramflux_protocol::Envelope,
}

fn contact_message(
    client: &RamfluxClient,
    event_type: &str,
    request: &LocalBusContactFederatedRequest,
) -> Result<(GatewayDirectMessage, Vec<u8>), SdkError> {
    use ramflux_protocol::message as g;
    let action = match event_type {
        "friend.requested" => 1,
        "friend.accepted" => 2,
        "friend.removed" => 3,
        "friend.blocked" => 4,
        "friend.unblocked" => 5,
        _ => return Err(SdkError::LocalBus("unknown Friend action".into())),
    };
    let mut message = GatewayDirectMessage {
        conversation_id: request.conversation_id.clone(),
        message_id: request.message_id.clone(),
        envelope_id: request.envelope_id.clone(),
        source_principal_id: request.source_principal_id.clone(),
        sender_id: request.sender_id.clone(),
        recipient_device_id: Some(request.recipient_device_id.clone()),
        recipient_principal_commitment: Some(if action == 1 {
            request.target_id.clone()
        } else {
            request.requester_id.clone()
        }),
        target_delivery_id: request.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: client.content_ttl()?,
    };
    let control = crate::client::generated_control::control_from_payload(
        g::control::Payload::Friend(g::FriendControl {
            action,
            link_id: request.link_id.clone(),
            requester: request.requester_id.clone(),
            target: request.target_id.clone(),
            blocked: action == 4,
            ..Default::default()
        }),
    )?;
    let prepared = client.prepare_authored_content(
        &mut message,
        None,
        &g::Content { value: Some(g::content::Value::Control(control)) },
    )?;
    Ok((message, prepared.wire.clone()))
}

fn trace_forward(route: &LocalBusFederationRoute, envelope: &ramflux_protocol::Envelope) {
    tracing::info!(
        source_node_id = %route.source_node_id,
        target_node_id = %route.target_node_id,
        federation_url = %route.federation_url,
        envelope_id = %envelope.envelope_id,
        target_delivery_id = %envelope.target_delivery_id,
        route_decision = "remote_federation_forward",
        "submitting federated direct message to source node federation surface"
    );
}
