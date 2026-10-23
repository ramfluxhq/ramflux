// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-object deferred fetch, serialized by the owning account actor.
use crate::bus::protocol::LocalBusObjectFetchRequest;
use crate::prelude::*;

pub(crate) async fn dispatch(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectFetchRequest = serde_json::from_value(request.body.clone())?;
    if let Some(receipt) =
        account.client.received_attachment_receipt(&body.object_id, &body.operation_id)?
    {
        return Ok(local_bus_ok(receipt));
    }
    let Ok(pool) = account.relay_quic_pool() else {
        return failed(account, &body).await;
    };
    let Ok(Ok(mut engine)) =
        tokio::time::timeout(std::time::Duration::from_secs(15), account.take_live_engine()).await
    else {
        return failed(account, &body).await;
    };
    let result = account
        .client
        .fetch_received_attachment(&mut engine, &pool, &body.object_id, &body.operation_id)
        .await;
    account.put_engine(engine);
    Ok(local_bus_ok(result?))
}

async fn failed(
    account: &mut LocalBusAccountState,
    body: &LocalBusObjectFetchRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    Ok(local_bus_ok(
        account.client.fail_received_attachment_fetch(&body.object_id, &body.operation_id).await?,
    ))
}

#[cfg(test)]
#[path = "tests/deferred_attachment.rs"]
mod tests;

/// A completed received object is local data, even when discovery configured a default relay.
pub(super) fn read_relay_options(
    account: &LocalBusAccountState,
    object_id: &str,
    endpoint: Option<String>,
    service_key: Option<String>,
    interrupt: Option<u32>,
) -> Result<Option<RelayTransferOptions>, SdkError> {
    if endpoint.is_none()
        && service_key.is_none()
        && interrupt.is_none()
        && account
            .client
            .received_attachment_status(object_id)?
            .is_some_and(|status| status["transfer_state"] == "available")
    {
        return Ok(None);
    }
    account.client.relay_transfer_options(endpoint, service_key, interrupt)
}
