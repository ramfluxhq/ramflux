// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Card session bus methods. Submit is the only call that touches the network.
use crate::client::surface::card_session::{self, SubmitPrep};
use crate::prelude::*;

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account = request_account_id(request)?.to_owned();
    let method = request.method.clone();
    match method.as_str() {
        "card.session.submit" => submit(request, state, &account).await,
        "card.session.open" => {
            local(state, &account, |client| card_session::open(client, &account, &request.body))
        }
        "card.session.update" => {
            local(state, &account, |client| card_session::update(client, &account, &request.body))
        }
        "card.session.present" => {
            local(state, &account, |client| card_session::present(client, &account, &request.body))
        }
        "card.session.event" => {
            local(state, &account, |client| card_session::event(client, &account, &request.body))
        }
        "card.session.slot" => {
            local(state, &account, |client| card_session::slot(client, &account, &request.body))
        }
        "card.session.suspend" => {
            local(state, &account, |client| card_session::suspend(client, &account, &request.body))
        }
        "card.session.resume" => {
            local(state, &account, |client| card_session::resume(client, &account, &request.body))
        }
        "card.session.dispose" => {
            local(state, &account, |client| card_session::dispose(client, &account, &request.body))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn recheck(
    state: &LocalBusDaemonState,
    account: &str,
    session: u64,
    version: u64,
    hash: &str,
) -> Result<Option<serde_json::Value>, SdkError> {
    let client = &local_bus_account(state, account)?.client;
    card_session::admit_send(client, account, session, version, hash)
}

fn local(
    state: &LocalBusDaemonState,
    account: &str,
    call: impl FnOnce(&RamfluxClient) -> Result<serde_json::Value, SdkError>,
) -> Result<LocalBusDispatchResult, SdkError> {
    let client = &local_bus_account(state, account)?.client;
    Ok(local_bus_ok(call(client)?))
}

async fn submit(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
    account: &str,
) -> Result<LocalBusDispatchResult, SdkError> {
    let prepared = {
        let client = &local_bus_account(state, account)?.client;
        card_session::prepare_submit(client, account, &request.body)?
    };
    match prepared {
        SubmitPrep::Done(value) => Ok(local_bus_ok(value)),
        SubmitPrep::Send {
            session,
            message_id,
            carrier,
            surface_version,
            surface_hash,
            fallback,
        } => {
            if let Some(value) = recheck(state, account, session, surface_version, &surface_hash)? {
                return Ok(local_bus_ok(value));
            }
            super::surface_transport::send(local_bus_account_mut(state, account)?, &carrier)
                .await?;
            if let Some(value) = recheck(state, account, session, surface_version, &surface_hash)? {
                return Ok(local_bus_ok(value));
            }
            card_session::commit_submit(account, session, &message_id)?;
            Ok(local_bus_ok(card_session::submitted(
                session,
                &message_id,
                surface_version,
                &surface_hash,
                &fallback,
            )))
        }
    }
}
