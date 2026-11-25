// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed in-process control, routed to the existing account writer. Never serializes keys.

use super::actor::{AccountActor, PrivateCommand};
use crate::SdkError;
use crate::client::call::InProcessMediaStatus;
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
        self.request(
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
        self.request(account, MediaCommand::Status { call_id: call_id.to_owned() }).await
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
        self.request(account, MediaCommand::AudioActive { call_id: call_id.to_owned(), active })
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
        self.request(account, MediaCommand::Close { call_id: call_id.to_owned() }).await
    }

    async fn request(
        &self,
        account: &str,
        command: MediaCommand,
    ) -> Result<InProcessMediaStatus, SdkError> {
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
) -> Result<InProcessMediaStatus, SdkError> {
    account.client.reconcile_in_process_media()?;
    let client = &mut account.client;
    match command {
        MediaCommand::Open { call_id, expected_seq, capture, playback } => {
            client.start_in_process_media(&call_id, expected_seq, capture, playback)
        }
        MediaCommand::Status { call_id } => client.in_process_media_status(&call_id),
        MediaCommand::AudioActive { call_id, active } => {
            client.set_in_process_audio_active(&call_id, active)
        }
        MediaCommand::Close { call_id } => client.close_in_process_media(&call_id),
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
    // A failed journal append leaves the mark unchanged, so the next reconcile retries it.
    let _ = account.client.reconcile_in_process_media();
}
