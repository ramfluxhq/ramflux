// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-way command claims and absolute deadlines measured from mailbox admission.

use super::actor::ActorResponse;
use super::runtime_limits::RuntimeTimeouts;
use crate::SdkError;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};

const QUEUED: u8 = 0;
const CLAIMED: u8 = 1;
const EXPIRED: u8 = 2;

pub(super) struct CommandAdmission {
    pub admitted_at: Instant,
    pub command_deadline: Instant,
    residence_deadline: Instant,
    post_claim_deadline: Instant,
    state: AtomicU8,
    pub(super) retain_completion: bool,
    #[cfg(test)]
    pub expired_replies: Option<std::sync::Arc<ExpiredReplies>>,
}

impl CommandAdmission {
    pub(super) fn new(admitted_at: Instant, timeouts: &RuntimeTimeouts) -> Self {
        Self {
            admitted_at,
            command_deadline: admitted_at + timeouts.command,
            residence_deadline: admitted_at + timeouts.network_wait,
            post_claim_deadline: admitted_at + timeouts.post_claim,
            state: AtomicU8::new(QUEUED),
            retain_completion: RETAIN_COMPLETION.try_with(|()| ()).is_ok(),
            #[cfg(test)]
            expired_replies: None,
        }
    }

    pub(super) fn claim(&self) -> bool {
        if Instant::now() >= self.residence_deadline {
            let _ =
                self.state.compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        self.state.compare_exchange(QUEUED, CLAIMED, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    pub(super) async fn response(
        &self,
        mut response: oneshot::Receiver<Result<ActorResponse, SdkError>>,
        needs_network: bool,
        pending: impl Fn() -> SdkError,
    ) -> Result<ActorResponse, SdkError> {
        match timeout_at(self.residence_deadline, &mut response).await {
            Ok(result) => return result.map_err(|_| unavailable("account command cancelled"))?,
            Err(_)
                if self
                    .state
                    .compare_exchange(QUEUED, EXPIRED, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok() =>
            {
                #[cfg(test)]
                if let Some(retained) = &self.expired_replies {
                    retained.retain(response);
                }
                return Err(if needs_network {
                    pending()
                } else {
                    unavailable("account command queue wait expired")
                });
            }
            Err(_) => {}
        }
        // A supervisor-owned receipt must observe the actual result after claim.
        // The queue residence fence above still rejects work that never started.
        if self.retain_completion {
            return response.await.map_err(|_| unavailable("account command cancelled"))?;
        }
        timeout_at(self.post_claim_deadline, response)
            .await
            .map_err(|_| unavailable("account command deadline expired"))?
            .map_err(|_| unavailable("account command cancelled"))?
    }
}

pub(super) fn unavailable(message: &'static str) -> SdkError {
    ramflux_transport::TransportError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        message,
    ))
    .into()
}

tokio::task_local! {
    pub(super) static COMMAND_CONTEXT: Instant;
    pub(super) static RETAIN_COMPLETION: ();
}
pub(super) fn current_deadline() -> Option<Instant> {
    COMMAND_CONTEXT.try_with(|deadline| *deadline).ok()
}

#[cfg(test)]
type ExpiredReply = oneshot::Receiver<Result<ActorResponse, SdkError>>;

/// Retaining expired result receivers isolates the actor claim fence from receiver closure.
#[cfg(test)]
#[derive(Default)]
pub(super) struct ExpiredReplies(std::sync::Mutex<Vec<ExpiredReply>>);
#[cfg(test)]
impl ExpiredReplies {
    fn retain(&self, reply: ExpiredReply) {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(reply);
    }
    pub(super) fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }
    pub(super) fn all_closed(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter_mut()
            .all(|reply| matches!(reply.try_recv(), Err(oneshot::error::TryRecvError::Closed)))
    }
}
