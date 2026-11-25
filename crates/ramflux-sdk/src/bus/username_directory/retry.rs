// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Autonomous delivery always observes fresh home/centre state before resending identical bytes.
use super::{Prepared, prepare, w};
use crate::username_directory::SignedUsernameChange;
use crate::{
    SdkError,
    prelude::{LocalBusDaemonState, LocalBusFrame, local_bus_account},
};

pub(in crate::bus) fn delivery_status(
    state: &LocalBusDaemonState,
    id: &str,
) -> Result<Option<Prepared>, SdkError> {
    if !w::enabled() {
        return Ok(None);
    }
    let account = local_bus_account(state, id)?;
    if let Some(policy) = account
        .client
        .account_db()?
        .load_actor_state::<ramflux_protocol::account_reach::ReachPolicy>(
        &format!("reach/change/{}", account.principal_commitment),
    )? {
        return Ok(Some(prepare(
            &LocalBusFrame::request(
                "reach-retry",
                Some(id.into()),
                "account",
                "account.reach.set",
                serde_json::json!({"mode":policy.body.mode,"expected_revision":policy.body.expected_revision,"operation_id":policy.body.operation_id}),
            ),
            state,
        )?));
    }
    if state.config.username_directory.is_some()
        && crate::account_reach::sync_pending(
            account.client.account_db()?,
            &account.principal_commitment,
        )?
    {
        return Ok(Some(prepare(
            &LocalBusFrame::request(
                "reach-sync",
                Some(id.into()),
                "account",
                "account.reach.get",
                serde_json::json!({}),
            ),
            state,
        )?));
    }
    if state.config.username_directory.is_some()
        && account
            .client
            .account_db()?
            .load_actor_state::<ramflux_protocol::account_reach::ReachRecord>(&format!(
                "reach/floor/{}",
                account.principal_commitment
            ))?
            .is_none()
    {
        return Ok(Some(prepare(
            &LocalBusFrame::request(
                "reach-initialize",
                Some(id.into()),
                "account",
                "account.reach.get",
                serde_json::json!({}),
            ),
            state,
        )?));
    }
    if account
        .client
        .account_db()?
        .load_actor_state::<SignedUsernameChange>(&format!(
            "username/intent/{}",
            account.principal_commitment
        ))?
        .is_none()
        && account
            .client
            .account_db()?
            .username_recovery_candidates(&account.principal_commitment)?
            .is_empty()
        && account.client.account_db()?.username_floor(&account.principal_commitment)?.is_none()
    {
        return Ok(None);
    }
    Ok(Some(prepare(
        &LocalBusFrame::request(
            "username-reconcile",
            Some(id.into()),
            "username",
            "username.status",
            serde_json::json!({}),
        ),
        state,
    )?))
}
pub(in crate::bus) fn delivery_retry(
    state: &LocalBusDaemonState,
    id: &str,
    body: &serde_json::Value,
) -> Result<Option<Prepared>, SdkError> {
    if body.get("policy").is_some() && body.get("revision").is_some() {
        return Ok(None);
    }
    let status: w::NativeUsernameStatus = serde_json::from_value(body.clone())?;
    let account = local_bus_account(state, id)?;
    let Some(intent) = account.client.account_db()?.load_actor_state::<SignedUsernameChange>(
        &format!("username/intent/{}", account.principal_commitment),
    )?
    else {
        return Ok(None);
    };
    // A pending home owns delivery already. Never rebase, extend, or sign replacement work.
    if status.state == w::NativeUsernameState::Pending
        || crate::custody::network_now()? >= intent.operation.body.expires_at
        || status.receipt.as_ref().map_or(0, |receipt| receipt.body.epoch)
            != intent.operation.body.expected_epoch
    {
        return Ok(None);
    }
    Ok(Some(prepare(
        &LocalBusFrame::request(
            "username-retry",
            Some(id.into()),
            "username",
            "username.mutate",
            serde_json::json!({"phase":"submit", "signed":intent}),
        ),
        state,
    )?))
}
