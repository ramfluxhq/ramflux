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
    let needs_network = state.accounts.get(account_id).is_some_and(|account| {
        super::method_table::account_requires_network(&command.request, account)
    });
    super::read_model::validate(&command.request)?;
    // A cold account can admit a read to its mailbox before its reader pool exists.
    // Once restored, use the same read dispatcher as the warm-pool path.
    if super::readers::is_reader_request(&command.request.method) {
        let account = local_bus_account(state, account_id)?;
        return Ok(ActorResponse {
            body: super::readers::read(&account.client, &command.request)?,
            events: Vec::new(),
            nodes: None,
        });
    }
    let mut connection =
        LocalBusConnectionState::new(command.connection_id, command.outbound.clone());
    connection.topics.clone_from(&command.topics);
    let intent = super::mutation_intent::MutationIntent::new(&command.request)?;
    let key = intent.key;
    if let Some(account) = state.accounts.get(account_id) {
        let db = account.client.account_db()?;
        if let Some(body) = intent.lookup(db)? {
            return Ok(ActorResponse { body, events: Vec::new(), nodes: None });
        }
    }
    if needs_network {
        let account = local_bus_account_mut(state, account_id)?;
        account.ensure_gateway_live().await?;
    }
    if super::method_table::classify(&command.request.method)
        .is_some_and(|entry| entry.class == super::method_table::MethodClass::LocalFirst)
    {
        let account = local_bus_account(state, account_id)?;
        super::dispatch::object::prepare_local_first_network(account, &command.request)?;
    }
    if let Some(account) = state.accounts.get(account_id)
        && let Some(body) = intent.reserve(account.client.account_db()?)?
    {
        return Ok(ActorResponse { body, events: Vec::new(), nodes: None });
    }
    if let Some(nodes) = &command.nodes {
        state.nodes = nodes.clone();
    }
    if command.attended {
        state.attended_accounts.insert(account_id.to_owned());
    } else {
        state.attended_accounts.remove(account_id);
    }
    bind_operation_objects(state, account_id, key, &command.request.body)?;
    let snapshot = state
        .accounts
        .get_mut(account_id)
        .map(|account| super::control_state::snapshot(account, &command.request))
        .transpose()?
        .flatten();
    let result = match Box::pin(dispatch_local_bus_request(
        &command.request,
        state,
        &mut connection,
    ))
    .await
    {
        Ok(result) => result,
        Err(SdkError::ObjectErased) => {
            if let (Some(key), Some(account)) = (key, state.accounts.get(account_id)) {
                account
                    .client
                    .account_db()?
                    .complete_operation(key, &serde_json::json!({"object_erased":true}))?;
            }
            return Err(SdkError::ObjectErased);
        }
        Err(error) => return Err(error),
    };
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
    if let Some(account) = state.accounts.get(account_id) {
        super::journal::capture_events(&account.client, &events)?;
    }
    Ok(ActorResponse {
        body: result.response_body,
        events,
        nodes: command.request.method.starts_with("node.").then(|| state.nodes.clone()),
    })
}

fn bind_operation_objects(
    state: &LocalBusDaemonState,
    account_id: &str,
    key: Option<&str>,
    body: &serde_json::Value,
) -> Result<(), SdkError> {
    if let (Some(key), Some(account)) = (key, state.accounts.get(account_id)) {
        let db = account.client.account_db()?;
        if let Err(error) = db.bind_operation_objects(key, body) {
            if matches!(error, StorageError::ObjectErased) {
                db.complete_operation(key, &serde_json::json!({"object_erased":true}))?;
            }
            return Err(error.into());
        }
    }
    Ok(())
}
