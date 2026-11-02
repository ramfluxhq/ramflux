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
    let engine = match tokio::time::timeout_at(connect_deadline, account.take_live_engine()).await {
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
    run_fetch(account, engine, &body.object_id, deadline, async |client, engine| {
        client.fetch_received_attachment(engine, &pool, &body.object_id, &body.operation_id).await
    })
    .await
}

async fn run_fetch<F>(
    account: &mut LocalBusAccountState,
    mut engine: GatewaySessionEngine,
    object_id: &str,
    deadline: Option<tokio::time::Instant>,
    fetch: F,
) -> Result<LocalBusDispatchResult, SdkError>
where
    F: for<'a> std::ops::AsyncFnOnce(
            &'a mut RamfluxClient,
            &'a mut GatewaySessionEngine,
        ) -> Result<serde_json::Value, SdkError>,
{
    // The engine remains owned outside either timed future, including a simultaneous expiry.
    let fetch = fetch(&mut account.client, &mut engine);
    let result = if let Some(deadline) = deadline {
        tokio::time::timeout_at(deadline, fetch).await
    } else {
        Ok(fetch.await)
    };
    finish_fetch(account, engine, object_id, result, deadline)
}

fn finish_fetch(
    account: &mut LocalBusAccountState,
    engine: GatewaySessionEngine,
    object_id: &str,
    result: Result<Result<serde_json::Value, SdkError>, tokio::time::error::Elapsed>,
    deadline: Option<tokio::time::Instant>,
) -> Result<LocalBusDispatchResult, SdkError> {
    let available = result.as_ref().is_ok_and(|result| {
        result.as_ref().is_ok_and(|receipt| receipt["transfer_state"] == "available")
    });
    let expired = result.is_err()
        || (!available && deadline.is_some_and(|at| tokio::time::Instant::now() >= at));
    if expired {
        let error = SdkError::LocalBus("attachment fetch deferred; retry object.fetch".into());
        if result.is_err() {
            crate::client::attachment_diagnostics::failed(
                object_id,
                "scheduler_fetch_deadline",
                &error,
            );
        } else {
            // An inner failure already emitted its warning before the shared deadline was observed.
            crate::client::attachment_diagnostics::context(
                object_id,
                "scheduler_fetch_deadline",
                &error,
            );
        }
        account.retire_engine(engine)?;
        account.client.recover_received_attachment_fetches()?;
        return Err(error);
    }
    let result = result.map_err(|_| SdkError::LocalBus("attachment deadline elapsed".into()))?;
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
    account.client.account_db()?.check_object_access(object_id)?;
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
