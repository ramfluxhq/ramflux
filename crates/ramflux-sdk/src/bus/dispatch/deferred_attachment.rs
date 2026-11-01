// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Per-object deferred fetch, serialized by the owning account actor.
use crate::bus::protocol::LocalBusObjectFetchRequest;
use crate::prelude::*;

pub(crate) async fn dispatch(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<LocalBusDispatchResult, SdkError> {
    dispatch_until(account, request, None).await
}

pub(crate) async fn dispatch_until(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
    deadline: Option<tokio::time::Instant>,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectFetchRequest = serde_json::from_value(request.body.clone())?;
    if let Some(receipt) =
        account.client.received_attachment_receipt(&body.object_id, &body.operation_id)?
    {
        return Ok(local_bus_ok(receipt));
    }
    let pool = match account.relay_quic_pool() {
        Ok(pool) => pool,
        Err(error) => {
            crate::client::attachment_diagnostics::failed(&body.object_id, "relay_pool", &error);
            return failed(account, &body).await;
        }
    };
    let connect_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let connect_deadline = deadline.map_or(connect_deadline, |at| at.min(connect_deadline));
    let mut engine =
        match tokio::time::timeout_at(connect_deadline, account.take_live_engine()).await {
            Ok(Ok(engine)) => engine,
            Ok(Err(error)) => {
                crate::client::attachment_diagnostics::failed(
                    &body.object_id,
                    "gateway_session",
                    &error,
                );
                return failed(account, &body).await;
            }
            Err(_) => {
                crate::client::attachment_diagnostics::failed(
                    &body.object_id,
                    "gateway_session_deadline",
                    &SdkError::GatewaySessionNotEstablished,
                );
                return failed(account, &body).await;
            }
        };
    // Ownership stays outside the timed future. A cancelled frame read must retire its stream,
    // but keep the updated gateway resume credentials and verified attachment progress.
    let fetch = account.client.fetch_received_attachment(
        &mut engine,
        &pool,
        &body.object_id,
        &body.operation_id,
    );
    let result = if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, fetch).await
    } else {
        Ok(fetch.await)
    };
    finish_fetch(account, engine, &body.object_id, result)
}

fn finish_fetch(
    account: &mut LocalBusAccountState,
    engine: GatewaySessionEngine,
    object_id: &str,
    result: Result<Result<serde_json::Value, SdkError>, tokio::time::error::Elapsed>,
) -> Result<LocalBusDispatchResult, SdkError> {
    let Ok(result) = result else {
        let error = SdkError::LocalBus("attachment fetch deferred; retry object.fetch".into());
        crate::client::attachment_diagnostics::failed(
            object_id,
            "scheduler_fetch_deadline",
            &error,
        );
        account.retire_engine(engine)?;
        account.client.recover_received_attachment_fetches()?;
        return Err(error);
    };
    if result.as_ref().is_ok_and(|receipt| {
        receipt["last_error"] == "attachment fetch deadline exceeded; retry object.fetch"
    }) {
        account.retire_engine(engine)?;
    } else {
        account.put_engine(engine);
    }
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
