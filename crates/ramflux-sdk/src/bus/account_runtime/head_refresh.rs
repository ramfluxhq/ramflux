// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-specific command demand. The fetch uses the network admission deadline.
//! A head already fetched for that demand is applied before other connection work.

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

/// `None` outside an actor command (direct dispatch). `Some(true)` means prepare
/// already ran receive; `Some(false)` means a refresh cleared that and dispatch
/// must replay under the actor bind.
pub(crate) fn take_receive_preparation() -> Option<bool> {
    RECEIVE_PREPARED.try_with(|prepared| prepared.replace(false)).ok()
}

/// Test fixture: the account actor sets this after a successful `group.read` prepare.
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

#[cfg(test)]
pub(crate) fn stale_roots(
    account: &LocalBusAccountState,
    request: &crate::LocalBusFrame,
) -> Result<BTreeSet<String>, SdkError> {
    stale_roots_since(account, request, None)
}

/// Roots whose authority a NEW send authorization must fetch afresh: the DM recipient, or every
/// group member. A pure retry of an already authorized send is not asked again by this check.
fn send_roots(
    account: &LocalBusAccountState,
    request: &crate::LocalBusFrame,
) -> Result<BTreeSet<String>, SdkError> {
    let body = &request.body;
    match request.method.as_str() {
        "message.submit" => Ok(body
            .get("recipient_principal_commitment")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .into_iter()
            .collect()),
        "conversation.send" => {
            let Some(id) = body.get("conversation_id").and_then(serde_json::Value::as_str) else {
                return Ok(BTreeSet::new());
            };
            let Some(thread) = account.client.account_db()?.client_record("conversation", id)?
            else {
                return Ok(BTreeSet::new());
            };
            if let Some(group) = thread.get("group_id").and_then(serde_json::Value::as_str) {
                return group_member_roots(account, group);
            }
            let principal = account
                .client
                .device_branch
                .as_ref()
                .map(|branch| branch.principal_id.clone())
                .ok_or(SdkError::IdentityRootMissing)?;
            let (_, root) =
                crate::bus::dispatch::conversation_send::peer_root(account, &thread, &principal)?;
            Ok(BTreeSet::from([root]))
        }
        _ => Ok(BTreeSet::new()),
    }
}

fn group_member_roots(
    account: &LocalBusAccountState,
    group: &str,
) -> Result<BTreeSet<String>, SdkError> {
    let mut roots = BTreeSet::new();
    if let Some(state) = account.client.account_db()?.shared_group_state(group)? {
        roots.extend(state.view().members.iter().map(|m| m.identity.root_commitment.clone()));
    }
    Ok(roots)
}

/// `since` set: a root is stale unless its authority was fetched at or after that instant
/// (per-authorization fetch). `None` keeps the process-wide observation window.
pub(crate) fn stale_roots_since(
    account: &LocalBusAccountState,
    request: &crate::LocalBusFrame,
    since: Option<std::time::Instant>,
) -> Result<BTreeSet<String>, SdkError> {
    // Read/receive must retain their existing inline peer fetch and first-pass admission.
    let method = request.method.as_str();
    if method == "group.read" {
        return crate::bus::couriers::head_refresh::inbound::blocked_roots(
            account,
            request.body.get("group_id").and_then(serde_json::Value::as_str).unwrap_or(""),
        );
    }
    if account.client.born_v3_account.is_none() {
        return Ok(BTreeSet::new());
    }
    let mut roots = if since.is_some() { send_roots(account, request)? } else { BTreeSet::new() };
    if method == "group.send"
        || method.starts_with("group.member.")
        || matches!(method, "group.name.set" | "group.owner.transfer" | "group.role.set")
    {
        roots.insert(account.principal_commitment.clone());
        if let Some(group) = request.body.get("group_id").and_then(serde_json::Value::as_str) {
            roots.extend(group_member_roots(account, group)?);
        }
    }
    let now = crate::custody::network_now()?;
    let mut stale = BTreeSet::new();
    for root in roots {
        if let Some(record) = account.client.current_custody_authority(&root, now)? {
            if let Some(since) = since {
                if !account.client.native_head_freshness.borrow().observed_since(&root, since) {
                    stale.insert(root);
                }
                continue;
            }
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
        self.refuse_ineligible_explicit_send(command)?;
        let network_deadline = admitted_at + self.timeouts.network_wait;
        // Every NEW send authorization needs an authority fetched after this command began.
        let since = std::time::Instant::now();
        let mut enqueued = BTreeSet::new();
        let mut receive_prepared = false;
        let mut demand = None;
        if command.request.method == "group.read"
            && let Some(account) = self.state.accounts.get_mut(&self.id)
        {
            // Cancellation is replay-safe: receive persists a committed receipt or
            // durable hold/retry before advancing its cursor and acknowledging.
            // Redelivery uses the admission key/receipt to avoid a second apply;
            // an unfinished pass never grants reusable preparation.
            // The actor bind owns receive after start_connection. Standalone run
            // would return AccountWriterBusy. Unbound tests still Resume here.
            if !crate::bus::push_receiver::apply_w1::receive_executor_bound(account)? {
                tokio::time::timeout_at(network_deadline, crate::bus::sync_driver::run(account))
                    .await
                    .map_err(|_| pending(account))??;
            }
            // A held retry must be replayed after refresh. `run` may persist-without-cover
            // while the head is still stale; claiming preparation would skip dispatch.
            receive_prepared =
                account.client.account_db()?.due_inbox_retry_rows(i64::MAX)?.is_empty();
        }
        loop {
            let roots = {
                let Some(account) = self.state.accounts.get_mut(&self.id) else {
                    return Ok(());
                };
                stale_roots_since(account, &command.request, Some(since))?
            };
            if roots.is_empty() {
                let _ = RECEIVE_PREPARED.try_with(|prepared| prepared.set(receive_prepared));
                return Ok(());
            }
            // A refresh only makes held entries ready; dispatch must replay them.
            receive_prepared = false;
            if demand.is_none() {
                demand = Some(super::head_demand::HeadDemand::arm(&self.command_waiting));
            }
            // Leave once the fetch budget ends. Waiting here for a fetch that has
            // not queued its Apply holds the only reader of `connection_work`.
            if Instant::now() >= network_deadline {
                return self.refuse_or_apply_queued(command, since).await;
            }
            let Some(account) = self.state.accounts.get_mut(&self.id) else {
                return Ok(());
            };
            for root in roots {
                if enqueued.insert(root.clone()) && !account.head_refresh.enqueue(root) {
                    return Err(pending(account));
                }
            }
            tokio::select! {
                biased;
                work = self.head_rx.recv() => {
                    let Some(work) = work else { return Err(SdkError::NetworkingPending); };
                    self.admit_during_head_demand(work).await?;
                }
                () = tokio::time::sleep_until(network_deadline) => {}
                work = self.connection_work.recv() => {
                    let Some(work) = work else { return Err(SdkError::NetworkingPending); };
                    self.admit_during_head_demand(work).await?;
                }
            }
        }
    }

    /// Apply a demanded head already in the completion slot or the shared queue,
    /// then refuse if the authority is still stale.
    async fn refuse_or_apply_queued(
        &mut self,
        command: &AccountCommand,
        since: std::time::Instant,
    ) -> Result<(), SdkError> {
        self.prefer_demanded_head().await?;
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(());
        };
        if stale_roots_since(account, &command.request, Some(since))?.is_empty() {
            let _ = RECEIVE_PREPARED.try_with(|prepared| prepared.set(false));
            return Ok(());
        }
        Err(pending(account))
    }

    /// An explicit send whose root is not this account, an accepted contact, or a
    /// shared-group member fails before any fetch. A failed contact setup must not
    /// wait out the head deadline.
    fn refuse_ineligible_explicit_send(&self, command: &AccountCommand) -> Result<(), SdkError> {
        let method = command.request.method.as_str();
        if method != "message.submit" && method != "conversation.send" {
            return Ok(());
        }
        let Some(account) = self.state.accounts.get(&self.id) else {
            return Ok(());
        };
        if account.client.born_v3_account.is_none() {
            return Ok(());
        }
        let roots = send_roots(account, &command.request)?;
        if roots.is_empty() {
            return Ok(());
        }
        let eligible = crate::bus::couriers::head_refresh::eligible_roots(account)?;
        if roots.iter().any(|root| !eligible.contains(root)) {
            return Err(crate::ContactReason::UnknownPrincipal.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod receive_tests;
#[cfg(test)]
mod tests;
