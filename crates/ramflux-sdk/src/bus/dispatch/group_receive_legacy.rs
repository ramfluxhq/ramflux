// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticate and isolate one bound legacy group entry without aborting its page.
use crate::client::group_quarantine::LegacyGroupDelivery;
use crate::prelude::*;
pub(super) async fn apply(
    client: &RamfluxClient,
    gateway: &GatewaySessionConfig,
    body: &LocalBusGroupReceiveRequest,
    entry: &GatewayInboxEntry,
) -> Result<LegacyGroupDelivery, SdkError> {
    client.retain_legacy_group_entry(entry)?;
    if let Some(error) = crate::client::inbox_failure::wire_signature_error(entry) {
        return client.isolate_legacy_group_delivery(entry, Err(error));
    }
    if let Err(error) = client.authenticated_envelope_sender(entry)
        && crate::client::inbox_failure::deterministic(&error).is_some()
    {
        return client.isolate_legacy_group_delivery(entry, Err(error));
    }
    if !client.legacy_group_retry_ready(entry)? {
        return Ok(LegacyGroupDelivery::Held);
    }
    let result = async {
        if let Err(error) = client.ensure_inbound_device(gateway, entry).await {
            if let Err(auth_error) = client.authenticated_envelope_sender(entry)
                && crate::client::inbox_failure::deterministic(&auth_error).is_some()
            {
                return Err(auth_error);
            }
            return Err(match error {
                SdkError::Json(_) | SdkError::Protocol(_) | SdkError::Crypto(_) => {
                    SdkError::InboundPending("sender directory verification is incomplete".into())
                }
                other => other,
            });
        }
        client
            .append_group_gateway_delivery_for_recipient_with_gateway(
                gateway,
                &body.conversation_id,
                &body.group_id,
                &entry.envelope.envelope_id,
                entry,
                &gateway.device_id,
            )
            .await
    }
    .await;
    client.isolate_legacy_group_delivery(entry, result)
}
