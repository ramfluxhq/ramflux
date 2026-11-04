// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation keeps the existing pair authority and candidate rules across a cancellable lookup.

use super::{
    Duration, GatewayDirectMessage, GatewaySessionAccess, LocalBusFederationRoute, RamfluxClient,
    Route, SdkDmEncryptedEnvelope, SdkError, SealPair, invalid,
};

pub(crate) struct SealForward<'a> {
    pub message: &'a GatewayDirectMessage,
    pub plaintext: &'a [u8],
    pub federation: &'a LocalBusFederationRoute,
    pub route: Route,
    pub timeout: Duration,
}
impl RamfluxClient {
    pub(crate) async fn seal_federated_message_async(
        &self,
        engine: &impl GatewaySessionAccess,
        request: SealForward<'_>,
    ) -> Result<SdkDmEncryptedEnvelope, SdkError> {
        let SealForward { message, plaintext, federation, route, timeout } = request;
        let local = self.local_device_identity(&engine.config().device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        // Match send_pair_session_from_url, including revocation and unconfirmed-candidate
        // handling before any remote lookup. No stale authority is admitted by the transport.
        let pair = if let Ok(remote) = self.device_identity(&recipient) {
            self.sendable_pair(&local, &remote)?
        } else {
            None
        };
        let (mut session, header, bundle) = if let Some(pair) = pair {
            pair
        } else {
            let url = federation
                .recipient_prekey_url
                .as_deref()
                .or(engine.config().prekey_http_url.as_deref())
                .ok_or_else(|| invalid("prekey url missing"))?;
            let lookup = self.root_qualified_device_lookup(&recipient)?;
            let bundle = crate::prekey::http_async::get::<crate::prekey::SdkPrekeyResponse>(
                url,
                &format!("/mvp1/prekey/{lookup}"),
                timeout,
            )
            .await?
            .bundle
            .ok_or_else(|| invalid("recipient prekey missing"))?;
            self.new_send_pair(&local, message, bundle)?
        };
        self.bind_outgoing_delivery(&local, message, &route.kind)?;
        self.seal_routed_with_route(
            message,
            plaintext,
            route,
            SealPair {
                local: &engine.config().device_id,
                remote: &recipient,
                session: &mut session,
                header,
                bundle,
            },
        )
    }
}
