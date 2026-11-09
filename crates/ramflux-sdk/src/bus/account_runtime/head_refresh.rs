// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-specific command demand with the original network admission deadline.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::{actor::AccountCommand, state::LocalBusAccountState};
use crate::client::identity_authority::HeadUse;
use std::cell::Cell;
use std::collections::BTreeSet;
use tokio::time::Instant;

// The account command owns this scope, never the account or connection. Dropping
// its future on cancellation/preemption also drops any completed preparation.
tokio::task_local! {
    pub(super) static RECEIVE_PREPARED: Cell<bool>;
}

pub(crate) fn take_receive_preparation() -> bool {
    RECEIVE_PREPARED.try_with(|prepared| prepared.replace(false)).unwrap_or(false)
}

/// Test fixture: the account actor sets this after a successful `group.receive` prepare.
#[cfg(test)]
pub(crate) async fn with_receive_prepared<T>(fut: impl std::future::Future<Output = T>) -> T {
    RECEIVE_PREPARED.scope(std::cell::Cell::new(true), fut).await
}

pub(crate) fn is_freshness_refusal(error: &SdkError) -> bool {
    matches!(error, SdkError::FreshHeadRequired { .. })
}

pub(crate) fn pending(account: &LocalBusAccountState) -> SdkError {
    let networking =
        account.connection.as_ref().map(crate::bus::connection_manager::ConnectionHandle::snapshot);
    SdkError::NetworkingPendingContext {
        retry_after_ms: Some(1_000),
        networking: Box::new(serde_json::json!(networking)),
    }
}

pub(crate) fn stale_roots(
    account: &LocalBusAccountState,
    request: &crate::LocalBusFrame,
) -> Result<BTreeSet<String>, SdkError> {
    // Read/receive must retain their existing inline peer fetch and first-pass admission.
    let method = request.method.as_str();
    if matches!(method, "group.read" | "group.receive") {
        return crate::bus::couriers::head_refresh::inbound::blocked_roots(
            account,
            request.body.get("group_id").and_then(serde_json::Value::as_str).unwrap_or(""),
        );
    }
    if account.client.born_v3_account.is_none()
        || !(method == "group.send"
            || method.starts_with("group.member.")
            || method.starts_with("group.invite.")
            || matches!(method, "group.name.set" | "group.owner.transfer" | "group.role.set"))
    {
        return Ok(BTreeSet::new());
    }
    let mut roots = BTreeSet::from([account.principal_commitment.clone()]);
    if let Some(group) = request.body.get("group_id").and_then(serde_json::Value::as_str)
        && let Some(state) = account.client.account_db()?.shared_group_state(group)?
    {
        roots.extend(state.view().members.iter().map(|m| m.identity.root_commitment.clone()));
    }
    let now = crate::custody::network_now()?;
    let mut stale = BTreeSet::new();
    for root in roots {
        if let Some(record) = account.client.current_custody_authority(&root, now)? {
            match account.client.require_fresh_custody_head(
                HeadUse::NewAuthorization,
                &root,
                record.envelope(),
            ) {
                Err(error) if is_freshness_refusal(&error) => {
                    stale.insert(root);
                }
                result => result?,
            }
        }
    }
    Ok(stale)
}

impl AccountRuntime {
    pub(super) async fn prepare_command_heads(
        &mut self,
        command: &AccountCommand,
        admitted_at: Instant,
    ) -> Result<(), SdkError> {
        let deadline = admitted_at + self.timeouts.network_wait;
        let mut enqueued = BTreeSet::new();
        let mut receive_prepared = false;
        if matches!(command.request.method.as_str(), "group.read" | "group.receive")
            && let Some(account) = self.state.accounts.get_mut(&self.id)
        {
            // Cancellation is replay-safe: receive persists a committed receipt or
            // durable hold/retry before advancing its cursor and acknowledging.
            // Redelivery uses the admission key/receipt to avoid a second apply;
            // an unfinished pass never grants reusable preparation.
            tokio::time::timeout_at(deadline, crate::bus::sync_driver::run(account))
                .await
                .map_err(|_| pending(account))??;
            receive_prepared = true;
        }
        loop {
            let Some(account) = self.state.accounts.get_mut(&self.id) else {
                return Ok(());
            };
            let roots = stale_roots(account, &command.request)?;
            if roots.is_empty() {
                let _ = RECEIVE_PREPARED.try_with(|prepared| prepared.set(receive_prepared));
                return Ok(());
            }
            // A refresh only makes held entries ready; dispatch must replay them.
            receive_prepared = false;
            if Instant::now() >= deadline {
                return Err(pending(account));
            }
            for root in roots {
                if enqueued.insert(root.clone()) && !account.head_refresh.enqueue(root) {
                    return Err(pending(account));
                }
            }
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => {
                    return Err(pending(self.state.accounts.get(&self.id).ok_or(SdkError::AccountDbNotUnlocked)?));
                }
                work = self.connection_work.recv() => {
                    let Some(work) = work else { return Err(SdkError::NetworkingPending); };
                    self.apply_connection_work(work).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod receive_tests;
#[cfg(test)]
mod tests;
