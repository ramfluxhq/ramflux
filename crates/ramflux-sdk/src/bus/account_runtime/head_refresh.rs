// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-specific command demand. The fetch uses the network admission deadline.
//! A head already fetched for that demand is applied before other connection work.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::{actor::AccountCommand, state::LocalBusAccountState};
use crate::client::identity_authority::HeadUse;
use std::collections::BTreeSet;
#[cfg(test)]
use tokio::time::Instant;

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

/// Roots whose authority a NEW send authorization must fetch afresh: the DM recipient.
/// A pure retry of an already authorized send is not asked again by this check.
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

/// `since` set: a root is stale unless its authority was fetched at or after that instant
/// (per-authorization fetch). `None` keeps the process-wide observation window.
pub(crate) fn stale_roots_since(
    account: &LocalBusAccountState,
    request: &crate::LocalBusFrame,
    since: Option<std::time::Instant>,
) -> Result<BTreeSet<String>, SdkError> {
    if account.client.born_v3_account.is_none() {
        return Ok(BTreeSet::new());
    }
    let roots = if since.is_some() { send_roots(account, request)? } else { BTreeSet::new() };
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
    #[cfg(test)]
    pub(super) async fn prepare_command_heads(
        &mut self,
        command: &AccountCommand,
        admitted_at: Instant,
    ) -> Result<(), SdkError> {
        self.refuse_ineligible_explicit_send(command)?;
        let network_deadline = admitted_at + self.timeouts.network_wait;
        // Every NEW send authorization needs an authority fetched after this command began.
        let since = std::time::Instant::now();
        let mut demand = None;
        loop {
            let roots = {
                let Some(account) = self.state.accounts.get_mut(&self.id) else {
                    return Ok(());
                };
                stale_roots_since(account, &command.request, Some(since))?
            };
            if roots.is_empty() {
                return Ok(());
            }
            if let Some(error) = self.demanded_foreign(&roots, since) {
                return Err(error);
            }
            if demand.is_none() {
                demand = Some(super::head_demand::HeadDemand::arm(&self.command_waiting));
            }
            // Leave once the fetch budget ends. This select keeps reading both queues.
            // A root stays demanded after a fetch that began before `since`: that
            // observation cannot authorize this command, and enqueue is idempotent
            // while a pass is already in flight.
            if Instant::now() >= network_deadline {
                return self.refuse_or_apply_queued(command, since).await;
            }
            let Some(account) = self.state.accounts.get_mut(&self.id) else {
                return Ok(());
            };
            for root in &roots {
                if !account.head_refresh.enqueue(root.clone()) {
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
                    if let Some(error) = self.demanded_foreign(&roots, since) {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Apply a demanded head already in the completion slot or the shared queue,
    /// then refuse if the authority is still stale.
    #[cfg(test)]
    async fn refuse_or_apply_queued(
        &mut self,
        command: &AccountCommand,
        since: std::time::Instant,
    ) -> Result<(), SdkError> {
        self.prefer_demanded_head().await?;
        let Some(account) = self.state.accounts.get_mut(&self.id) else {
            return Ok(());
        };
        let roots = stale_roots_since(account, &command.request, Some(since))?;
        if let Some(error) = account.head_refresh.take_demanded_foreign(&roots, since) {
            return Err(error);
        }
        if roots.is_empty() {
            return Ok(());
        }
        Err(pending(account))
    }

    #[cfg(test)]
    fn demanded_foreign(
        &mut self,
        roots: &BTreeSet<String>,
        since: std::time::Instant,
    ) -> Option<SdkError> {
        self.state.accounts.get_mut(&self.id)?.head_refresh.take_demanded_foreign(roots, since)
    }

    /// An explicit send whose root is not this account, an accepted contact, or a
    /// contact fails before any fetch. A failed contact setup must not
    /// wait out the head deadline.
    pub(super) fn refuse_ineligible_explicit_send(
        &self,
        command: &AccountCommand,
    ) -> Result<(), SdkError> {
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
mod tests;
