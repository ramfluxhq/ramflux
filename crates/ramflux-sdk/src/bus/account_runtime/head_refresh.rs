// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-specific command demand with the original network admission deadline.

use super::AccountRuntime;
use crate::SdkError;
use crate::bus::{actor::AccountCommand, state::LocalBusAccountState};
use crate::client::identity_authority::HeadUse;
use std::collections::BTreeSet;
use tokio::time::Instant;

pub(crate) fn is_freshness_refusal(error: &SdkError) -> bool {
    matches!(error, SdkError::InboundPending(message)
        if message == "native current-head freshness expired; refresh directory")
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
        if matches!(command.request.method.as_str(), "group.read" | "group.receive")
            && let Some(account) = self.state.accounts.get_mut(&self.id)
        {
            tokio::time::timeout_at(deadline, crate::bus::sync_driver::run(account))
                .await
                .map_err(|_| pending(account))??;
        }
        loop {
            let Some(account) = self.state.accounts.get_mut(&self.id) else {
                return Ok(());
            };
            let roots = stale_roots(account, &command.request)?;
            if roots.is_empty() {
                return Ok(());
            }
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
mod tests;
