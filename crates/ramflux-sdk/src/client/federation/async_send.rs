// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancellable federation steps preserve the ordinary command's local signing and projection.

use super::{
    FederatedSendOptions, RamfluxClient, SealForward, contact_message, federated_forward_request,
    trace_forward,
};
use crate::client::routed::Route;
use crate::prelude::*;

pub(crate) struct PlaintextForward<'a> {
    pub message: GatewayDirectMessage,
    pub plaintext: &'a [u8],
    pub federation: &'a LocalBusFederationRoute,
    pub route: Route,
    pub franking: bool,
    pub timeout: Duration,
}
impl RamfluxClient {
    pub(crate) async fn send_plaintext_federated_message_async(
        &self,
        engine: &impl GatewaySessionAccess,
        request: PlaintextForward<'_>,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let PlaintextForward { mut message, plaintext, federation, route, franking, timeout } =
            request;
        Self::normalize_recipient(&mut message)?;
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
            &sealed,
            &FederatedSendOptions { franking, route },
        )?;
        trace_forward(federation, &pending.envelope);
        let result = post(federation, pending.envelope, timeout).await;
        self.finish_own_sent_copy(&pending.message, pending.own_copy.as_deref(), result.is_ok());
        result
    }

    pub(crate) async fn send_plaintext_federated_contact_event_async(
        &self,
        engine: &impl GatewaySessionAccess,
        event_type: &str,
        request: &LocalBusContactFederatedRequest,
        timeout: Duration,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let (message, body) = contact_message(self, event_type, request)?;
        self.send_plaintext_federated_message_async(
            engine,
            PlaintextForward {
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
        engine: &impl GatewaySessionAccess,
        message: &mut GatewayDirectMessage,
        sealed: crate::client::routed::SealedRouted,
        federation: &LocalBusFederationRoute,
        timeout: Duration,
    ) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
        let envelope = gateway_envelope_from_sealed(engine.config(), message, sealed, None)?;
        trace_forward(federation, &envelope);
        post(federation, envelope, timeout).await
    }
}
async fn post(
    route: &LocalBusFederationRoute,
    envelope: ramflux_protocol::Envelope,
    timeout: Duration,
) -> Result<SdkFederatedEnvelopeForwardResponse, SdkError> {
    crate::prekey::http_async::post(
        &route.federation_url,
        "/s8/federation/forward",
        &federated_forward_request(route, envelope),
        timeout,
    )
    .await
}
