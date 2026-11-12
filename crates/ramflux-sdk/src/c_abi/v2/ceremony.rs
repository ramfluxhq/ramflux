// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account creation for a C host: the recovery-phrase ceremony on its own connection.
//!
//! Creation is not an `execute` request. The supervisor refuses custody-setup methods on
//! the ordinary connection so that a phrase or a passphrase never shares a frame, a queue
//! or a task with ordinary requests. Each ceremony therefore owns one dedicated in-process
//! connection, driven by one task on the shim thread; dropping it cancels a pending setup.

use super::error::{Effect, V2Error, V2Result};
use super::super::{RamfluxErrorCode, sdk_error_code};
use crate::{LocalBusCreatedAccount, LocalBusCreationClient, LocalBusPendingCreation, SdkError};
use ramflux_protocol::PrincipalKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

/// OPEN-VALUE: longest wait for one ceremony step. Confirmation derives keys and registers
/// the account, so it is allowed far longer than an ordinary request.
pub(super) const STEP_DEADLINE: Duration = Duration::from_secs(120);

pub(super) enum Step {
    Begin {
        display_name: String,
        node_id: Option<String>,
        reply: SyncSender<Result<LocalBusPendingCreation, SdkError>>,
    },
    ShowOnce(SyncSender<Result<Zeroizing<String>, SdkError>>),
    Challenge(SyncSender<Result<[u8; 3], SdkError>>),
    Confirm {
        words: Box<[Zeroizing<String>; 3]>,
        passphrase: Zeroizing<String>,
        reply: SyncSender<Result<LocalBusCreatedAccount, SdkError>>,
    },
    Cancel(SyncSender<Result<(), SdkError>>),
}

/// Queued for the shim thread, which opens the connection and runs [`run`].
pub(super) struct CeremonyJob {
    pub(super) steps: mpsc::Receiver<Step>,
}

/// The host's side of one ceremony.
pub(super) struct Ceremony {
    steps: mpsc::Sender<Step>,
    /// The single confirmation attempt. It is spent when it is sent, not when it succeeds.
    confirmed: AtomicBool,
}

fn carrier_closed() -> SdkError {
    SdkError::LocalBus("account-creation connection is closed".to_owned())
}

/// One ceremony on the shim thread. It ends when the host frees the handle, or when the
/// supervisor is suspended or stopped; either way the connection is dropped, which cancels
/// a ceremony that was not confirmed.
pub(super) async fn run(
    client: Result<LocalBusCreationClient, SdkError>,
    mut steps: mpsc::Receiver<Step>,
    mut generation: watch::Receiver<u64>,
) {
    let mut client = client.ok();
    loop {
        let step = tokio::select! {
            changed = generation.changed() => {
                if changed.is_err() {
                    // The shim thread is ending.
                    return;
                }
                // Drop the connection now; later steps are answered with `closed`.
                client = None;
                continue;
            }
            step = steps.recv() => step,
        };
        let Some(step) = step else {
            return;
        };
        let Some(open) = client.as_mut() else {
            refuse(step);
            continue;
        };
        match step {
            Step::Begin { display_name, node_id, reply } => {
                let begun = match node_id.as_deref() {
                    Some(node) => {
                        open.begin_with_node(&display_name, PrincipalKind::Human, node).await
                    }
                    None => open.begin(&display_name, PrincipalKind::Human).await,
                };
                let _ignored = reply.try_send(begun);
            }
            Step::ShowOnce(reply) => {
                let _ignored = reply.try_send(open.show_once().await);
            }
            Step::Challenge(reply) => {
                let _ignored = reply.try_send(open.hidden_challenge().await);
            }
            Step::Confirm { words, passphrase, reply } => {
                let _ignored = reply.try_send(open.confirm(&words, &passphrase).await);
            }
            Step::Cancel(reply) => {
                let _ignored = reply.try_send(open.cancel().await);
            }
        }
    }
}

fn refuse(step: Step) {
    match step {
        Step::Begin { reply, .. } => {
            let _ignored = reply.try_send(Err(carrier_closed()));
        }
        Step::ShowOnce(reply) => {
            let _ignored = reply.try_send(Err(carrier_closed()));
        }
        Step::Challenge(reply) => {
            let _ignored = reply.try_send(Err(carrier_closed()));
        }
        Step::Confirm { reply, .. } => {
            let _ignored = reply.try_send(Err(carrier_closed()));
        }
        Step::Cancel(reply) => {
            let _ignored = reply.try_send(Err(carrier_closed()));
        }
    }
}

/// Stable number of a ceremony failure: the major-1 mapping, with a carrier failure
/// reported as the carrier.
fn step_error(error: &SdkError, effect: Effect) -> V2Error {
    let code = match error {
        SdkError::LocalBus(_) | SdkError::Io(_) => RamfluxErrorCode::TransportUnavailable,
        other => sdk_error_code(other),
    };
    V2Error::new(code, error.to_string()).with_effect(effect)
}

impl Ceremony {
    pub(super) fn new() -> (Self, CeremonyJob) {
        // One step at a time: the host drives the ceremony from a single flow.
        let (steps, receiver) = mpsc::channel(1);
        (Self { steps, confirmed: AtomicBool::new(false) }, CeremonyJob { steps: receiver })
    }

    fn step<T>(
        &self,
        build: impl FnOnce(SyncSender<Result<T, SdkError>>) -> Step,
        effect_when_lost: Effect,
    ) -> V2Result<T> {
        let (reply, answer): (_, Receiver<Result<T, SdkError>>) = sync_channel(1);
        self.steps.try_send(build(reply)).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                V2Error::new(RamfluxErrorCode::RateLimited, "a ceremony step is still running")
                    .with_reason("busy")
            }
            mpsc::error::TrySendError::Closed(_) => V2Error::closed(Effect::None),
        })?;
        match answer.recv_timeout(STEP_DEADLINE) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(step_error(&error, Effect::Refused)),
            // The step was handed over and no answer was seen.
            Err(_) => Err(V2Error::deadline(effect_when_lost)),
        }
    }

    pub(super) fn begin(
        &self,
        display_name: String,
        node_id: Option<String>,
    ) -> V2Result<LocalBusPendingCreation> {
        self.step(|reply| Step::Begin { display_name, node_id, reply }, Effect::Unknown)
    }

    pub(super) fn show_once(&self) -> V2Result<Zeroizing<String>> {
        self.step(Step::ShowOnce, Effect::Unknown)
    }

    pub(super) fn challenge(&self) -> V2Result<[u8; 3]> {
        self.step(Step::Challenge, Effect::Unknown)
    }

    pub(super) fn confirm(
        &self,
        words: Box<[Zeroizing<String>; 3]>,
        passphrase: Zeroizing<String>,
    ) -> V2Result<LocalBusCreatedAccount> {
        if self.confirmed.swap(true, Ordering::AcqRel) {
            return Err(V2Error::new(
                RamfluxErrorCode::InvalidArgument,
                "the single confirmation attempt was already used",
            )
            .with_reason("confirmation_used"));
        }
        // A lost answer here may be a created account: the host lists accounts to find out.
        self.step(|reply| Step::Confirm { words, passphrase, reply }, Effect::Unknown)
    }

    pub(super) fn cancel(&self) -> V2Result<()> {
        self.confirmed.store(true, Ordering::Release);
        self.step(Step::Cancel, Effect::Unknown)
    }
}
