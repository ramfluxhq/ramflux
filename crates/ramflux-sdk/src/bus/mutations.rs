// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordered mutation execution, durable retry receipts and control state commits.

use super::actor::{AccountCommand, ActorResponse};
use crate::prelude::*;

pub(super) async fn execute(
    state: &mut LocalBusDaemonState,
    account_id: &str,
    command: &AccountCommand,
) -> Result<ActorResponse, SdkError> {
    if let Some(nodes) = &command.nodes {
        state.nodes = nodes.clone();
    }
    super::read_model::validate(&command.request)?;
    let mut connection =
        LocalBusConnectionState::new(command.connection_id, command.outbound.clone());
    connection.topics.clone_from(&command.topics);
    if command.attended {
        state.attended_accounts.insert(account_id.to_owned());
    } else {
        state.attended_accounts.remove(account_id);
    }
    let key = command.request.operation_id.as_deref().or_else(|| {
        command.request.body.get("idempotency_key").and_then(serde_json::Value::as_str)
    });
    if let Some(key) = key
        && (key.is_empty() || key.len() > 256)
    {
        return Err(SdkError::LocalBus("operation_id must contain 1 to 256 bytes".to_owned()));
    }
    // Fetch owns retryable receipts, but generic header validation above still applies.
    let key = key.filter(|_| command.request.method != "object.fetch");
    let fingerprint = if key.is_some() {
        let intent = ramflux_protocol::canonical_json_bytes(&(
            &command.request.method,
            &command.request.body,
        ))?;
        Some(ramflux_crypto::blake3_256_base64url("ramflux.operation.v1", &intent))
    } else {
        None
    };
    if let (Some(key), Some(account), Some(fingerprint)) =
        (key, state.accounts.get(account_id), fingerprint.as_deref())
        && let Some(body) = account.client.account_db()?.reserve_operation(key, fingerprint)?
    {
        return Ok(ActorResponse { body, events: Vec::new(), nodes: None });
    }
    let snapshot = state
        .accounts
        .get_mut(account_id)
        .map(|account| super::control_state::snapshot(account, &command.request))
        .transpose()?
        .flatten();
    let result = dispatch_local_bus_request(&command.request, state, &mut connection).await?;
    if let Some(account) = state.accounts.get(account_id) {
        super::read_model::capture(account, &command.request, &result.response_body)?;
    }
    if let (Some(snapshot), Some(account)) = (snapshot, state.accounts.get_mut(account_id)) {
        super::control_state::commit(account, snapshot)?;
    }
    if let (Some(key), Some(account)) = (key, state.accounts.get(account_id)) {
        let db = account.client.account_db()?;
        db.complete_operation(key, &result.response_body)?;
    }
    let mut events = connection.drain_events();
    if let Some(event) = result.event {
        events.push(event);
    }
    Ok(ActorResponse {
        body: result.response_body,
        events,
        nodes: command.request.method.starts_with("node.").then(|| state.nodes.clone()),
    })
}
