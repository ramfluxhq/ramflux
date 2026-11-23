// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Autonomous home outbox reconciliation; timeouts never undo a committed operation.
use super::{
    AuthorityResponse, CheckpointError, DirectoryRequest, HomeDirectory, HomeIntent,
    LiveHomeRevalidation, MutationPhase, Result, fence::random_id,
};
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};
use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{sync::Notify, task::JoinSet};
use tokio_util::sync::CancellationToken;
mod attempt;
pub use attempt::{HomeAttempt, HomeAttemptOutcome};

pub type UsernameExchange<'a> =
    Pin<Box<dyn Future<Output = Result<AuthorityResponse>> + Send + 'a>>;

/// Every exchange authenticates the live reporting home/native account and provisioned centre.
/// Implementations must not return cached positive revalidations or issue generic sign grants.
pub trait UsernameCenterClient: Send + Sync {
    fn exchange<'a>(&'a self, root: &'a str, request: DirectoryRequest) -> UsernameExchange<'a>;
}

pub struct HomeCoordinator {
    home: Arc<HomeDirectory>,
    center: Arc<dyn UsernameCenterClient>,
    wake: Notify,
    attempts: attempt::Attempts,
}

impl HomeCoordinator {
    #[must_use]
    pub fn new(home: Arc<HomeDirectory>, center: Arc<dyn UsernameCenterClient>) -> Self {
        Self { home, center, wake: Notify::new(), attempts: attempt::Attempts::default() }
    }

    /// H1 callers notify after their durable commit; the worker also discovers work after restart.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Subscribe before H1 so the caller can observe this attempt's live result, never a cache.
    /// # Errors
    /// Refuses malformed correlation IDs, unavailable bookkeeping or bounded subscriber capacity.
    pub fn watch_attempt(&self, root: &str, operation_id: &str) -> Result<HomeAttempt> {
        self.attempts.watch(root, operation_id)
    }

    /// Runs independently of user/API polling. At most 16 owned reconciliation tasks, one/root.
    /// # Errors
    /// Returns corrupt/unavailable local queue state; network refusals retain durable work.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut active = BTreeSet::new();
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => self.schedule(&mut tasks, &mut active)?,
                () = self.wake.notified() => self.schedule(&mut tasks, &mut active)?,
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    let (root, operation_id, outcome) = joined.map_err(|_| CheckpointError::Refused("home_worker_stopped"))?;
                    active.remove(&root);
                    let code = match &outcome {
                        Ok(()) => None,
                        Err(CheckpointError::Directory(code)) => Some(*code),
                        Err(_) => Some(Code::DirectoryUnavailable),
                    };
                    self.attempts.complete(&root, &operation_id, code)?;
                    if let Err(error) = outcome {
                        tracing::warn!(%error, "username reconciliation retained for retry");
                        if self.home.intent(&root)?.is_some() {
                            let delay = match code {
                                Some(Code::RateLimited | Code::UsernameTaken | Code::UsernameHeld | Code::UsernameReserved) => 60,
                                _ => 5,
                            };
                            self.home.retry_later_for(&root, Some(&operation_id), crate::now_unix_seconds(), delay)?;
                        }
                    }
                }
            }
        }
        tasks.shutdown().await;
        Ok(())
    }

    fn schedule(
        self: &Arc<Self>,
        tasks: &mut JoinSet<(String, String, Result<()>)>,
        active: &mut BTreeSet<String>,
    ) -> Result<()> {
        let available = 16_usize.saturating_sub(active.len());
        if available == 0 {
            return Ok(());
        }
        let now = crate::now_unix_seconds();
        for root in self.home.due_roots(now, available)? {
            let Some(intent) = self.home.intent(&root)? else {
                continue;
            };
            if !active.insert(root.clone()) {
                continue;
            }
            // A crash leaves at most a 60-second indexed backoff, not an in-RAM-only claim.
            self.home.retry_later_for(&root, Some(&intent.operation.body.operation_id), now, 60)?;
            let owner = Arc::clone(self);
            tasks.spawn(async move {
                let operation_id = intent.operation.body.operation_id.clone();
                let outcome = owner.reconcile(&root, intent).await;
                (root, operation_id, outcome)
            });
        }
        Ok(())
    }

    async fn call(&self, root: &str, request: DirectoryRequest) -> Result<AuthorityResponse> {
        tokio::time::timeout(Duration::from_secs(10), self.center.exchange(root, request))
            .await
            .map_err(|_| CheckpointError::Directory(Code::DirectoryUnavailable))?
    }

    async fn revalidate(&self, root: &str, intent: &HomeIntent) -> Result<LiveHomeRevalidation> {
        let request = w::HomeRevalidateRequest {
            root: root.into(),
            known_directory_epoch: intent.operation.body.expected_epoch,
            operation_id: Some(intent.operation.body.operation_id.clone()),
            nonce: random_id()?,
        };
        match self.call(root, DirectoryRequest::Revalidate { request: request.clone() }).await? {
            AuthorityResponse::Revalidated { result } => {
                LiveHomeRevalidation::from_authenticated_reply(
                    self.home.center_pin(),
                    &request,
                    *result,
                    crate::now_unix_seconds(),
                )
            }
            AuthorityResponse::Refused { failure } => Err(CheckpointError::Directory(failure.code)),
            _ => Err(CheckpointError::Directory(Code::DirectoryUnavailable)),
        }
    }

    async fn reconcile(&self, root: &str, intent: HomeIntent) -> Result<()> {
        let status = self
            .call(
                root,
                DirectoryRequest::Status {
                    operation_id: Some(intent.operation.body.operation_id.clone()),
                },
            )
            .await?;
        let receipt = match status {
            AuthorityResponse::Receipt { receipt } => *receipt,
            AuthorityResponse::Refused { failure } if failure.code == Code::NotFound => {
                if crate::now_unix_seconds() >= intent.operation.body.expires_at {
                    let current = self.revalidate(root, &intent).await?;
                    return self.home.discard_aborted(
                        root,
                        None,
                        current,
                        crate::now_unix_seconds(),
                    );
                }
                match self
                    .call(
                        root,
                        DirectoryRequest::Mutate {
                            phase: MutationPhase::Reserve,
                            operation: Box::new(intent.operation.clone()),
                            profile: Some(Box::new(intent.profile.clone())),
                        },
                    )
                    .await?
                {
                    AuthorityResponse::Receipt { receipt } => *receipt,
                    AuthorityResponse::Refused { failure } => {
                        return Err(CheckpointError::Directory(failure.code));
                    }
                    _ => return Err(CheckpointError::Directory(Code::DirectoryUnavailable)),
                }
            }
            AuthorityResponse::Refused { failure } => {
                return Err(CheckpointError::Directory(failure.code));
            }
            _ => return Err(CheckpointError::Directory(Code::DirectoryUnavailable)),
        };
        match receipt.body.state {
            w::ReceiptState::Committed => {
                let current = self.revalidate(root, &intent).await?;
                self.home.finalize(root, current, crate::now_unix_seconds())?;
            }
            w::ReceiptState::Reserved => {
                self.home.prepare(root, receipt, crate::now_unix_seconds())?;
                match self
                    .call(
                        root,
                        DirectoryRequest::Mutate {
                            phase: MutationPhase::Commit,
                            operation: Box::new(intent.operation.clone()),
                            profile: Some(Box::new(intent.profile.clone())),
                        },
                    )
                    .await?
                {
                    AuthorityResponse::Receipt { receipt }
                        if receipt.body.state == w::ReceiptState::Committed =>
                    {
                        let current = self.revalidate(root, &intent).await?;
                        self.home.finalize(root, current, crate::now_unix_seconds())?;
                    }
                    AuthorityResponse::Refused { failure } => {
                        return Err(CheckpointError::Directory(failure.code));
                    }
                    _ => return Err(CheckpointError::Directory(Code::DirectoryUnavailable)),
                }
            }
            w::ReceiptState::Aborted => {
                let current = self.revalidate(root, &intent).await?;
                self.home.discard_aborted(
                    root,
                    Some(&receipt),
                    current,
                    crate::now_unix_seconds(),
                )?;
            }
        }
        Ok(())
    }
}
