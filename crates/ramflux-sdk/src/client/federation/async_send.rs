// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancellable federation steps preserve the ordinary command's local signing and projection.

use super::{FederatedSendOptions, RamfluxClient, SealForward, contact_message, trace_forward};
use crate::client::routed::Route;
use crate::prelude::*;

pub(crate) struct PlaintextForward<'a> {
    pub message: GatewayDirectMessage,
    pub plaintext: &'a [u8],
    pub content: Option<&'a ramflux_protocol::message::Content>,
    pub federation: &'a LocalBusFederationRoute,
    pub route: Route,
    pub franking: bool,
    pub timeout: Duration,
}
impl RamfluxClient {
    pub(crate) async fn send_plaintext_federated_message_async(
        &self,
        engine: &mut impl GatewaySessionAccess,
        request: PlaintextForward<'_>,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let PlaintextForward {
            mut message,
            plaintext,
            content,
            federation,
            route,
            franking,
            timeout,
        } = request;
        Self::normalize_recipient(&mut message)?;
        let authored;
        let plaintext = if route.kind == crate::client::routed::Kind::Direct {
            use ramflux_protocol::message as g;
            let text_content;
            let content = if let Some(content) = content {
                self.validate_user_authored_content(content, &message.conversation_id)?;
                content
            } else {
                let text = std::str::from_utf8(plaintext)
                    .map_err(|_| SdkError::LocalBus("Message text must be UTF-8".into()))?;
                text_content = g::Content {
                    value: Some(g::content::Value::Message(g::Message {
                        text: text.into(),
                        ..Default::default()
                    })),
                };
                &text_content
            };
            authored = self.prepare_authored_content(&mut message, None, content)?;
            authored.wire.as_slice()
        } else {
            plaintext
        };
        let sealed = self
            .seal_federated_message_async(
                engine,
                SealForward {
                    message: &message,
                    plaintext,
                    federation,
                    route: route.clone(),
                    timeout,
                },
            )
            .await?;
        let pending = self.prepare_federated_packet(
            engine,
            &mut message,
            plaintext,
            sealed,
            &FederatedSendOptions { franking, route },
        )?;
        trace_forward(federation, &pending.envelope);
        let home = crate::client::recipient_home::pin_choice(
            self,
            message.recipient_principal_commitment.as_deref().unwrap_or(""),
            Some(federation.target_node_id.as_str()),
        )?;
        bounded_submit(engine, federation, home.as_deref(), pending.envelope, timeout).await
    }

    pub(crate) async fn send_plaintext_federated_contact_event_async(
        &self,
        engine: &mut impl GatewaySessionAccess,
        event_type: &str,
        request: &LocalBusContactFederatedRequest,
        timeout: Duration,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let (message, body) = contact_message(self, event_type, request)?;
        self.send_plaintext_federated_message_async(
            engine,
            PlaintextForward {
                content: None,
                message,
                plaintext: &body,
                federation: &request.federation,
                route: Route::control(),
                franking: false,
                timeout,
            },
        )
        .await
    }

    pub(crate) async fn forward_federated_sealed_async(
        &self,
        engine: &mut impl GatewaySessionAccess,
        message: &mut GatewayDirectMessage,
        sealed: crate::client::routed::SealedRouted,
        federation: &LocalBusFederationRoute,
        timeout: Duration,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let envelope =
            gateway_envelope_from_sealed(&engine.sealing_config()?, message, sealed, None)?;
        trace_forward(federation, &envelope);
        let home = crate::client::recipient_home::pin_choice(
            self,
            message.recipient_principal_commitment.as_deref().unwrap_or(""),
            Some(federation.target_node_id.as_str()),
        )?;
        bounded_submit(engine, federation, home.as_deref(), envelope, timeout).await
    }
}

async fn bounded_submit(
    engine: &mut impl GatewaySessionAccess,
    route: &LocalBusFederationRoute,
    submit_target: Option<&str>,
    envelope: ramflux_protocol::Envelope,
    timeout: Duration,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    tokio::time::timeout(timeout, submit_over_session(engine, route, submit_target, envelope))
        .await
        .map_err(|_| {
            SdkError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "home submit timed out"))
        })?
}

pub(super) async fn submit_over_session(
    engine: &mut impl GatewaySessionAccess,
    route: &LocalBusFederationRoute,
    submit_target: Option<&str>,
    envelope: ramflux_protocol::Envelope,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    let target = submit_target.filter(|id| !id.is_empty()).map(str::to_owned);
    let entry = match engine.submit_classified_to(envelope, target).await? {
        Ok(entry) => entry,
        Err(refusal) => {
            return Err(SdkError::GatewaySessionRejected(refusal.reason().to_owned()));
        }
    };
    Ok(SdkFederatedEnvelopeForwardResponse {
        accepted: true,
        source_node_id: String::new(),
        target_node_id: route.target_node_id.clone(),
        delivery: SdkFederatedSubmitResponse {
            outcome: if entry.forwarded { "forwarded" } else { "online" }.to_owned(),
            target_delivery_id: entry.target_delivery_id,
            inbox_seq: Some(entry.inbox_seq),
            cursor: None,
        },
    })
}
