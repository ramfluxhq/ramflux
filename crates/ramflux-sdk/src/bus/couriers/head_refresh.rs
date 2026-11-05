// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Demand and periodic writer Prepare / off-actor fetch / writer Apply for current heads.

use crate::bus::connection_manager::{AccountWork, ConnectionPhase, SessionContext};
use crate::bus::state::LocalBusAccountState;
use crate::{GatewaySessionConfig, SdkDeviceManifestResponse, SdkError};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

pub(crate) mod inbound;

const MAX_PENDING: usize = 512;
const PASS_ROOTS: usize = 32;
const MAX_CYCLE_PASSES: usize = 4;
const PASS_PAUSE: Duration = Duration::from_millis(25);
const REFRESH_INTERVAL: Duration = Duration::from_secs(150);

#[derive(Default)]
pub(crate) struct RefreshState {
    pending: BTreeSet<String>,
    cursor: Option<(bool, String)>,
    failures: BTreeMap<String, (tokio::time::Instant, u8)>,
    inbound: inbound::Inbound,
    wake: Arc<tokio::sync::Notify>,
    // A dropped/cancelled pass releases ownership without needing an actor message.
    active: Weak<()>,
}
impl RefreshState {
    fn retry_ready(&self, root: &str) -> bool {
        self.failures.get(root).is_none_or(|(until, _)| *until <= tokio::time::Instant::now())
    }

    /// Returns false at capacity so activation can return a retryable result.
    pub(crate) fn enqueue(&mut self, root: String) -> bool {
        if self.pending.contains(&root) {
            if self.active.upgrade().is_none() && self.retry_ready(&root) {
                self.wake.notify_one();
            }
            return true;
        }
        if self.pending.len() == MAX_PENDING {
            return false;
        }
        self.pending.insert(root);
        self.wake.notify_one();
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
    remaining_passes: usize,
    config: GatewaySessionConfig,
}
pub(crate) enum Work {
    Subscribe {
        reply: oneshot::Sender<Arc<tokio::sync::Notify>>,
    },
    Prepare {
        fence: Fence,
        periodic: bool,
        attempted: BTreeSet<String>,
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

fn eligible_roots(account: &LocalBusAccountState) -> Result<BTreeSet<String>, SdkError> {
    let mut roots = BTreeSet::from([account.principal_commitment.clone()]);
    for link in account.client.friend_links()? {
        if link.state == "accepted" {
            roots.insert(link.requester_id);
            roots.insert(link.target_id);
        }
    }
    let db = account.client.account_db()?;
    for group in account.client.groups()? {
        if let Some(state) = db.shared_group_state(&group.group_id)? {
            roots.extend(
                state.view().members.iter().map(|member| member.identity.root_commitment.clone()),
            );
        }
    }
    Ok(roots)
}

#[cfg(test)]
fn prepare(account: &mut LocalBusAccountState, fence: Fence) -> Result<Option<Plan>, SdkError> {
    prepare_due(account, fence, false, &BTreeSet::new())
}

#[cfg(test)]
fn prepare_due(
    account: &mut LocalBusAccountState,
    fence: Fence,
    periodic: bool,
    attempted: &BTreeSet<String>,
) -> Result<Option<Plan>, SdkError> {
    prepare_due_limit(account, fence, periodic, attempted, PASS_ROOTS)
}

fn prepare_due_limit(
    account: &mut LocalBusAccountState,
    fence: Fence,
    periodic: bool,
    attempted: &BTreeSet<String>,
    limit: usize,
) -> Result<Option<Plan>, SdkError> {
    if !fence.current(account) || account.head_refresh.active.upgrade().is_some() {
        return Ok(None);
    }
    if !periodic && account.head_refresh.pending.is_empty() {
        return Ok(None);
    }
    let eligible = eligible_roots(account)?;
    account.head_refresh.pending.retain(|root| eligible.contains(root));
    account.head_refresh.failures.retain(|root, _| eligible.contains(root));
    let now = Instant::now();
    let freshness = account.client.native_head_freshness.borrow();
    let candidates: BTreeSet<_> = eligible
        .into_iter()
        .filter(|root| !attempted.contains(root) && account.head_refresh.retry_ready(root))
        .filter_map(|root| {
            let observed = freshness.observation(&root);
            let due = observed.is_none_or(|at| {
                now.checked_duration_since(at).is_none_or(|age| age >= REFRESH_INTERVAL)
            });
            (account.head_refresh.pending.contains(&root) || (periodic && due))
                .then_some((observed.is_some(), root))
        })
        .collect();
    drop(freshness);
    // Demand precedes sweep work. Each class rotates through never-observed and
    // observed roots with a persistent cursor, including after failed fetches.
    let cursor = account.head_refresh.cursor.as_ref();
    let after = candidates.iter().filter(|key| cursor.is_none_or(|last| *key > last));
    let before = candidates.iter().filter(|key| cursor.is_some_and(|last| *key <= last));
    let ordered: Vec<_> = after.chain(before).collect();
    let demand = ordered.iter().filter(|(_, root)| account.head_refresh.pending.contains(root));
    let sweep = ordered.iter().filter(|(_, root)| !account.head_refresh.pending.contains(root));
    let selected: Vec<_> = demand.chain(sweep).take(limit).map(|key| (*key).clone()).collect();
    if selected.is_empty() {
        return Ok(None);
    }
    account.head_refresh.cursor = selected.last().cloned();
    let remaining_passes = candidates.len().saturating_sub(selected.len()).div_ceil(PASS_ROOTS);
    let roots = selected.into_iter().map(|(_, root)| root).collect();
    let lease = Arc::new(());
    account.head_refresh.active = Arc::downgrade(&lease);
    Ok(Some(Plan { fence, lease, roots, remaining_passes, config: account.gateway_config.clone() }))
}

fn apply(
    account: &mut LocalBusAccountState,
    plan: &Plan,
    root: &str,
    fetched_after: Instant,
    outcome: Result<SdkDeviceManifestResponse, SdkError>,
) -> Result<bool, SdkError> {
    let result = apply_verified(account, plan, root, fetched_after, outcome);
    if plan.fence.current(account)
        && account.head_refresh.active.ptr_eq(&Arc::downgrade(&plan.lease))
        && plan.roots.iter().any(|candidate| candidate == root)
    {
        if matches!(result, Ok(true)) {
            account.head_refresh.failures.remove(root);
        } else {
            let previous = account.head_refresh.failures.get(root).map_or(0, |(_, count)| *count);
            let count = previous.saturating_add(1).min(6);
            let delay = Duration::from_secs((5_u64 << (count - 1)).min(150));
            account
                .head_refresh
                .failures
                .insert(root.to_owned(), (tokio::time::Instant::now() + delay, count));
        }
    }
    result
}

fn apply_verified(
    account: &mut LocalBusAccountState,
    plan: &Plan,
    root: &str,
    fetched_after: Instant,
    outcome: Result<SdkDeviceManifestResponse, SdkError>,
) -> Result<bool, SdkError> {
    if !plan.fence.current(account)
        || !account.head_refresh.active.ptr_eq(&Arc::downgrade(&plan.lease))
        || !plan.roots.iter().any(|candidate| candidate == root)
    {
        return Ok(false);
    }
    // Rebuild once for this writer turn; membership may have changed since Prepare.
    if !eligible_roots(account)?.contains(root) {
        return Ok(false);
    }
    let manifest = outcome?;
    crate::client::identity_authority::verify_manifest_authority(&manifest, root)?;
    account.client.persist_fetched_identity_directory_at(&manifest, fetched_after)?;
    let ready = if let Some(native) = &manifest.custody {
        account
            .client
            .require_fresh_custody_head(
                crate::client::identity_authority::HeadUse::NewAuthorization,
                root,
                &native.publication.record,
            )
            .is_ok()
    } else {
        // Verified legacy authority has no native observation clock to satisfy.
        true
    };
    if ready {
        account.head_refresh.pending.remove(root);
        inbound::refreshed(account, root)?;
    }
    Ok(ready)
}

/// Invoked only on the account writer. All network inputs are owned values.
pub(crate) fn apply_work(account: &mut LocalBusAccountState, work: Work) {
    match work {
        Work::Subscribe { reply } => {
            let _ = reply.send(account.head_refresh.wake.clone());
        }
        Work::Prepare { fence, periodic, attempted, reply } => {
            if !reply.is_closed() {
                let _ = reply.send(prepare_due_limit(account, fence, periodic, &attempted, 1));
            }
        }
        Work::Apply { plan, root, fetched_after, outcome, reply } => {
            if !reply.is_closed() {
                let _ = reply.send(apply(account, &plan, &root, fetched_after, *outcome));
            }
        }
    }
}

/// Test entry for cancellation of a single demand pass.
#[cfg(test)]
pub(crate) async fn pass(
    context: SessionContext,
    writer: mpsc::Sender<AccountWork>,
) -> Result<(), SdkError> {
    if *context.cancel.borrow() {
        return Ok(());
    }
    let mut cancel = context.cancel.clone();
    let mut attempted = BTreeSet::new();
    tokio::select! {
        biased;
        _ = cancel.changed() => Ok(()),
        result = fetch_pass(&context, &writer, false, &mut attempted) => result.map(|_| ()),
    }
}
async fn fetch_pass(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
    periodic: bool,
    attempted: &mut BTreeSet<String>,
) -> Result<usize, SdkError> {
    let mut remaining = 0;
    for _ in 0..PASS_ROOTS {
        let (reply, response) = oneshot::channel();
        send(
            writer,
            Work::Prepare {
                fence: Fence {
                    generation: context.generation,
                    session_id: context.session_id.clone(),
                },
                periodic,
                attempted: attempted.clone(),
                reply,
            },
        )
        .await?;
        let Some(plan) = response.await.map_err(|_| stopped())?? else { return Ok(0) };
        let plan = Arc::new(plan);
        remaining = plan.remaining_passes;
        for root in &plan.roots {
            let fetched_after = Instant::now();
            let outcome = super::directory::fetch(&plan.config, root).await;
            attempted.insert(root.clone());
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
            let _ = response.await.map_err(|_| stopped())?;
        }
        // Release the pass lease and re-read demands before the next network fetch.
        drop(plan);
        if remaining == 0 {
            break;
        }
    }
    Ok(remaining)
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

/// The registered session child refreshes on connect, demand and the half-bound timer.
pub(crate) async fn run(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    run_with_triggers(context, writer, true, true).await;
}

async fn cycle(
    context: &SessionContext,
    writer: &mpsc::Sender<AccountWork>,
    periodic: bool,
) -> Result<(), SdkError> {
    let mut attempted = BTreeSet::new();
    for pass in 0..MAX_CYCLE_PASSES {
        if pass > 0 {
            tokio::time::sleep(PASS_PAUSE).await;
        }
        if fetch_pass(context, writer, periodic, &mut attempted).await? == 0 {
            break;
        }
    }
    Ok(())
}

async fn run_with_triggers(
    context: SessionContext,
    writer: mpsc::Sender<AccountWork>,
    connect: bool,
    periodic: bool,
) {
    let mut cancel = context.cancel.clone();
    if *cancel.borrow() {
        return;
    }
    let run = async {
        let (reply, response) = oneshot::channel();
        send(&writer, Work::Subscribe { reply }).await?;
        let wake = response.await.map_err(|_| stopped())?;
        let mut next_sweep = tokio::time::Instant::now() + REFRESH_INTERVAL;
        let mut timer = tokio::time::interval_at(next_sweep, REFRESH_INTERVAL);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        if connect && let Err(error) = cycle(&context, &writer, true).await {
            tracing::debug!(%error, "connect head refresh deferred");
        }
        loop {
            tokio::select! {
                biased;
                _ = timer.tick(), if periodic => {},
                () = wake.notified() => {},
            }
            // A queued wake cannot hide an elapsed deadline, even before the
            // timer driver's readiness notification has been delivered.
            let periodic = periodic && tokio::time::Instant::now() >= next_sweep;
            if periodic {
                next_sweep = tokio::time::Instant::now() + REFRESH_INTERVAL;
            }
            if let Err(error) = cycle(&context, &writer, periodic).await {
                tracing::debug!(%error, "head refresh cycle deferred");
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), SdkError>(())
    };
    tokio::select! { biased; _ = cancel.changed() => {}, result = run => {
        if let Err(error) = result { tracing::debug!(%error, "head refresh stopped"); }
    }}
}

#[cfg(test)]
pub(crate) async fn run_without_timer(context: SessionContext, writer: mpsc::Sender<AccountWork>) {
    run_with_triggers(context, writer, true, false).await;
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn test_apply(
    account: &mut LocalBusAccountState,
    root: &str,
    at: Instant,
    outcome: Result<SdkDeviceManifestResponse, SdkError>,
) -> Result<bool, SdkError> {
    let snapshot = account.connection.as_ref().ok_or(SdkError::NetworkingPending)?.snapshot();
    // This hook injects a completed fetch for Apply/admission tests. Scheduling
    // backoff is exercised through Prepare by the scheduler regressions.
    account.head_refresh.failures.remove(root);
    account.head_refresh.enqueue(root.to_owned());
    let plan = prepare(
        account,
        Fence {
            generation: snapshot.generation,
            session_id: snapshot.session_id.ok_or(SdkError::NetworkingPending)?,
        },
    )?
    .ok_or(SdkError::NetworkingPending)?;
    apply(account, &plan, root, at, outcome)
}
