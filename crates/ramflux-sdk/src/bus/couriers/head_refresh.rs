// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant writer Prepare / off-actor fetch / writer Apply for current heads.
//! No child, timer or demand producer is registered until command activation.

use crate::bus::connection_manager::{AccountWork, ConnectionPhase, SessionContext};
use crate::bus::state::LocalBusAccountState;
use crate::{GatewaySessionConfig, SdkDeviceManifestResponse, SdkError};
use std::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    time::Instant,
};
use tokio::sync::{mpsc, oneshot};

const MAX_PENDING: usize = 512;
const PASS_ROOTS: usize = 32;

#[derive(Default)]
pub(crate) struct RefreshState {
    pending: BTreeSet<String>,
    // A dropped/cancelled pass releases ownership without needing an actor message.
    active: Weak<()>,
}
impl RefreshState {
    /// Returns false at capacity so activation can return a retryable result.
    pub(crate) fn enqueue(&mut self, root: String) -> bool {
        if self.pending.contains(&root) {
            return true;
        }
        if self.pending.len() == MAX_PENDING {
            return false;
        }
        self.pending.insert(root);
        true
    }
}

#[derive(Clone)]
pub(crate) struct Fence {
    generation: u64,
    session_id: String,
}
impl Fence {
    fn current(&self, account: &LocalBusAccountState) -> bool {
        account.connection.as_ref().is_some_and(|connection| {
            let snapshot = connection.snapshot();
            snapshot.generation == self.generation
                && snapshot.phase == ConnectionPhase::Live
                && snapshot.session_id.as_deref() == Some(self.session_id.as_str())
        })
    }
}

pub(crate) struct Plan {
    fence: Fence,
    lease: Arc<()>,
    roots: Vec<String>,
    config: GatewaySessionConfig,
}
pub(crate) enum Work {
    Prepare {
        fence: Fence,
        reply: oneshot::Sender<Result<Option<Plan>, SdkError>>,
    },
    Apply {
        plan: Arc<Plan>,
        root: String,
        fetched_after: Instant,
        outcome: Box<Result<SdkDeviceManifestResponse, SdkError>>,
        reply: oneshot::Sender<Result<bool, SdkError>>,
    },
}

fn eligible(account: &LocalBusAccountState, root: &str) -> Result<bool, SdkError> {
    if account.principal_commitment == root {
        return Ok(true);
    }
    if account.client.friend_links()?.iter().any(|link| {
        link.state == "accepted" && (link.requester_id == root || link.target_id == root)
    }) {
        return Ok(true);
    }
    let db = account.client.account_db()?;
    for group in account.client.groups()? {
        if let Some(state) = db.shared_group_state(&group.group_id)?
            && state.view().members.iter().any(|member| member.identity.root_commitment == root)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prepare(account: &mut LocalBusAccountState, fence: Fence) -> Result<Option<Plan>, SdkError> {
    if !fence.current(account) || account.head_refresh.active.upgrade().is_some() {
        return Ok(None);
    }
    let mut roots = Vec::new();
    let mut removed = Vec::new();
    for root in &account.head_refresh.pending {
        if eligible(account, root)? {
            roots.push(root.clone());
        } else {
            removed.push(root.clone());
        }
        if roots.len() == PASS_ROOTS {
            break;
        }
    }
    for root in removed {
        account.head_refresh.pending.remove(&root);
    }
    if roots.is_empty() {
        return Ok(None);
    }
    let lease = Arc::new(());
    account.head_refresh.active = Arc::downgrade(&lease);
    Ok(Some(Plan { fence, lease, roots, config: account.gateway_config.clone() }))
}

fn apply(
    account: &mut LocalBusAccountState,
    plan: &Plan,
    root: &str,
    fetched_after: Instant,
    outcome: Result<SdkDeviceManifestResponse, SdkError>,
) -> Result<bool, SdkError> {
    if !plan.fence.current(account)
        || !account.head_refresh.active.ptr_eq(&Arc::downgrade(&plan.lease))
        || !plan.roots.iter().any(|candidate| candidate == root)
        || !eligible(account, root)?
    {
        return Ok(false);
    }
    let manifest = outcome?;
    crate::client::identity_authority::verify_manifest_authority(&manifest, root)?;
    account.client.persist_fetched_identity_directory_at(&manifest, fetched_after)?;
    let fresh = if let Some(native) = &manifest.custody {
        account
            .client
            .require_fresh_custody_head(
                crate::client::identity_authority::HeadUse::NewAuthorization,
                root,
                &native.publication.record,
            )
            .is_ok()
    } else {
        false
    };
    if fresh {
        account.head_refresh.pending.remove(root);
    }
    Ok(fresh)
}

/// Invoked only on the account writer. All network inputs are owned values.
pub(crate) fn apply_work(account: &mut LocalBusAccountState, work: Work) {
    match work {
        Work::Prepare { fence, reply } => {
            if !reply.is_closed() {
                let _ = reply.send(prepare(account, fence));
            }
        }
        Work::Apply { plan, root, fetched_after, outcome, reply } => {
            if !reply.is_closed() {
                let _ = reply.send(apply(account, &plan, &root, fetched_after, *outcome));
            }
        }
    }
}

/// A session child may call this once per demand wake. It owns no account data.
pub(crate) async fn pass(
    context: SessionContext,
    writer: mpsc::Sender<AccountWork>,
) -> Result<(), SdkError> {
    if *context.cancel.borrow() {
        return Ok(());
    }
    let mut cancel = context.cancel.clone();
    tokio::select! {
        biased;
        _ = cancel.changed() => Ok(()),
        result = fetch_pass(&context, &writer) => result,
    }
}
async fn fetch_pass(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
) -> Result<(), SdkError> {
    let (reply, response) = oneshot::channel();
    send(
        writer,
        Work::Prepare {
            fence: Fence { generation: context.generation, session_id: context.session_id.clone() },
            reply,
        },
    )
    .await?;
    let Some(plan) = response.await.map_err(|_| stopped())?? else {
        return Ok(());
    };
    let plan = Arc::new(plan);
    for root in &plan.roots {
        // Lower bound taken BEFORE the request, never when the writer drains its queue.
        let fetched_after = Instant::now();
        let outcome = super::directory::fetch(&plan.config, root).await;
        let (reply, response) = oneshot::channel();
        send(
            writer,
            Work::Apply {
                plan: plan.clone(),
                root: root.clone(),
                fetched_after,
                outcome: Box::new(outcome),
                reply,
            },
        )
        .await?;
        // A failed root stays pending, but does not prevent this bounded pass from continuing.
        let _ = response.await.map_err(|_| stopped())?;
    }
    Ok(())
}
async fn send(writer: &mpsc::Sender<AccountWork>, work: Work) -> Result<(), SdkError> {
    writer
        .send(AccountWork::Directory(Box::new(super::directory::DirectoryWork::HeadRefresh(work))))
        .await
        .map_err(|_| stopped())
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

#[cfg(test)]
mod tests;
