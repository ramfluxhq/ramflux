// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Federation seals through the same MLS channel as a local send.

use super::{
    Duration, GatewayDirectMessage, GatewaySessionAccess, LocalBusFederationRoute, RamfluxClient,
    Route, SdkError, SealPair,
};

pub(crate) struct SealForward<'a> {
    pub message: &'a GatewayDirectMessage,
    pub plaintext: &'a [u8],
    pub federation: &'a LocalBusFederationRoute,
    pub route: Route,
    pub timeout: Duration,
}
impl RamfluxClient {
    /// Seal for a recipient on another node. The one `PrivateMessage` of the conversation group
    /// does not depend on the recipient's node; the group's first `KeyPackage` fetch from a foreign
    /// node belongs to the lifecycle (D5).
    pub(crate) async fn seal_federated_message_async(
        &self,
        engine: &impl GatewaySessionAccess,
        request: SealForward<'_>,
    ) -> Result<super::SealedRouted, SdkError> {
        let SealForward { message, plaintext, federation, route, timeout } = request;
        if !federation.target_node_id.is_empty()
            && let Some(anchor) = message.recipient_principal_commitment.as_deref()
        {
            if let Err(error) =
                crate::bus::dispatch::conversation_security::cache_foreign_key_packages(
                    self, anchor, timeout,
                )
                .await
            {
                tracing::debug!(%error, "foreign key package fetch");
            }
        }
        let local = self.local_device_identity(&engine.config().device_id)?;
        self.require_pair_device_active(&local)?;
        let recipient = Self::qualified_recipient(message)?;
        self.bind_outgoing_delivery(&local, message, &route.kind)?;
        self.seal_routed_with_route(
            message,
            plaintext,
            route,
            SealPair { local: &engine.config().device_id, remote: &recipient },
        )
    }
}
