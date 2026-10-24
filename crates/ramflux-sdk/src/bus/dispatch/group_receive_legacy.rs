// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticate and isolate one bound legacy group entry without aborting its page.
use crate::prelude::*;
pub(super) async fn apply(
    client: &RamfluxClient,
    gateway: &GatewaySessionConfig,
    body: &LocalBusGroupReceiveRequest,
    entry: &GatewayInboxEntry,
) -> Result<Option<GroupGatewayDeliveryResult>, SdkError> {
    let result = async {
        client.ensure_inbound_device(gateway, entry).await?;
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
