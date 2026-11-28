// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed in-process control, routed to the existing account writer. Never serializes keys.

use super::actor::{AccountActor, PrivateCommand};
use crate::SdkError;
use crate::client::call::InProcessMediaStatus;
use crate::client::call::media_owner::TakeOutcome;
use ramflux_media::video::packet::AccessUnit;
use ramflux_media::{Capture, Playback};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

pub(crate) enum MediaCommand {
    Open {
        call_id: String,
        expected_seq: u64,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
    },
    Status {
        call_id: String,
    },
    AudioActive {
        call_id: String,
        active: bool,
    },
    Close {
        call_id: String,
    },
    SubmitVideo {
        call_id: String,
        au: Box<AccessUnit>,
    },
    TakeVideo {
        call_id: String,
        capacity: usize,
    },
}

pub(crate) enum MediaResult {
    Status(Box<InProcessMediaStatus>),
    Taken(TakeOutcome),
}

/// Trusted host-side control of the engine in this process; adapters see PCM only.
/// Obtain it from an immutable in-process [`crate::LocalBusConfig`] before starting its daemon.
#[derive(Clone, Default)]
pub struct InProcessMediaControl {
    actors: Arc<Mutex<BTreeMap<String, AccountActor>>>,
}

impl InProcessMediaControl {
    pub(super) fn register(&self, account: &str, actor: AccountActor) {
        self.actors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(account.to_owned(), actor);
    }

    /// Move the session once into the SDK engine, initially with host audio inactive.
    /// # Errors
    /// Returns account, sequence, ownership, authority or startup refusal without exporting keys.
    pub async fn open(
        &self,
        account: &str,
        call_id: &str,
        expected_seq: u64,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.status_request(
            account,
            MediaCommand::Open { call_id: call_id.to_owned(), expected_seq, capture, playback },
        )
        .await
    }

    /// Current SDK-fenced snapshot, without consuming another session.
    /// # Errors
    /// Returns the owning writer's typed refusal.
    pub async fn status(
        &self,
        account: &str,
        call_id: &str,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.status_request(account, MediaCommand::Status { call_id: call_id.to_owned() }).await
    }

    /// Report audio readiness. A host report cannot open an SDK authority gate.
    /// # Errors
    /// Returns the owning writer's typed refusal.
    pub async fn audio_active(
        &self,
        account: &str,
        call_id: &str,
        active: bool,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.status_request(
            account,
            MediaCommand::AudioActive { call_id: call_id.to_owned(), active },
        )
        .await
    }

    /// Close and drain. This does not hang up or allow a second take.
    /// # Errors
    /// Returns the owning writer's typed refusal.
    pub async fn close(
        &self,
        account: &str,
        call_id: &str,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.status_request(account, MediaCommand::Close { call_id: call_id.to_owned() }).await
    }

    /// Copy one encoded access unit onto the live in-process video track.
    ///
    /// # Errors
    /// Returns the owning writer's typed refusal. A unit that is not queued is refused.
    pub async fn submit_video(
        &self,
        account: &str,
        call_id: &str,
        au: AccessUnit,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.status_request(
            account,
            MediaCommand::SubmitVideo { call_id: call_id.to_owned(), au: Box::new(au) },
        )
        .await
    }

    /// Copy one complete access unit out when it fits in `capacity`.
    /// `Ok(None)` means the queue is empty. A unit larger than `capacity` stays queued.
    ///
    /// # Errors
    /// Returns the owning writer's typed refusal, including a unit that does not fit.
    pub async fn take_video(
        &self,
        account: &str,
        call_id: &str,
        capacity: usize,
    ) -> Result<Option<AccessUnit>, SdkError> {
        match self
            .request(account, MediaCommand::TakeVideo { call_id: call_id.to_owned(), capacity })
            .await?
        {
            MediaResult::Taken(TakeOutcome::Empty) => Ok(None),
            MediaResult::Taken(TakeOutcome::Unit(unit)) => Ok(Some(unit)),
            MediaResult::Taken(TakeOutcome::TooLarge) => {
                Err(SdkError::LocalBus("voice call: video frame does not fit".into()))
            }
            MediaResult::Status(_) => {
                Err(SdkError::LocalBus("voice call: media reply mismatch".into()))
            }
        }
    }

    async fn status_request(
        &self,
        account: &str,
        command: MediaCommand,
    ) -> Result<InProcessMediaStatus, SdkError> {
        match self.request(account, command).await? {
            MediaResult::Status(status) => Ok(*status),
            MediaResult::Taken(_) => {
                Err(SdkError::LocalBus("voice call: media reply mismatch".into()))
            }
        }
    }

    async fn request(&self, account: &str, command: MediaCommand) -> Result<MediaResult, SdkError> {
        let actor = self
            .actors
            .lock()
            .map_err(|_| SdkError::LocalBusPermissionDenied)?
            .get(account)
            .cloned()
            .ok_or_else(|| SdkError::AccountNotOpen(account.to_owned()))?;
        let (reply, response) = oneshot::channel();
        actor.send_private(PrivateCommand::Media { command, reply })?;
        tokio::time::timeout(std::time::Duration::from_secs(25), response)
            .await
            .map_err(|_| SdkError::LocalBus("voice call: engine control deadline exceeded".into()))?
            .map_err(|_| SdkError::AccountNotOpen(account.to_owned()))?
    }
}

pub(super) fn apply(
    account: &mut super::state::LocalBusAccountState,
    command: MediaCommand,
) -> Result<MediaResult, SdkError> {
    reconcile(account);
    let client = &mut account.client;
    match command {
        MediaCommand::Open { call_id, expected_seq, capture, playback } => client
            .start_in_process_media(&call_id, expected_seq, capture, playback)
            .map(|status| MediaResult::Status(Box::new(status))),
        MediaCommand::Status { call_id } => client
            .in_process_media_status(&call_id)
            .map(|status| MediaResult::Status(Box::new(status))),
        MediaCommand::AudioActive { call_id, active } => client
            .set_in_process_audio_active(&call_id, active)
            .map(|status| MediaResult::Status(Box::new(status))),
        MediaCommand::Close { call_id } => client
            .close_in_process_media(&call_id)
            .map(|status| MediaResult::Status(Box::new(status))),
        MediaCommand::SubmitVideo { call_id, au } => client
            .submit_in_process_video(&call_id, &au)
            .map(|status| MediaResult::Status(Box::new(status))),
        MediaCommand::TakeVideo { call_id, capacity } => {
            client.take_in_process_video(&call_id, capacity).map(MediaResult::Taken)
        }
    }
}

pub(crate) fn reconcile(account: &super::state::LocalBusAccountState) {
    let current = account.connection.as_ref().and_then(|handle| {
        let snapshot = handle.snapshot();
        // The home rejected this session's authority. A reconnect may establish
        // new authority, but it cannot revive the consumed media session.
        if matches!(snapshot.last_reason.as_deref(), Some("renewal_refused" | "branch_revoked")) {
            account
                .client
                .stop_in_process_media(ramflux_media::authorization::GateReason::Terminal);
            return None;
        }
        handle
            .metadata()
            .filter(|metadata| {
                snapshot.state == super::connection_manager::NetworkingState::Live
                    && metadata.generation == snapshot.generation
            })
            .and_then(|metadata| metadata.session.call_session_generation.clone())
    });
    *account.client.media_connection_generation.borrow_mut() = current;
    account.client.reconcile_in_process_media();
}
