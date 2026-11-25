// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One process-wide audio reservation and the account writer's engine lifetime.

use super::handoff::InProcessMediaReceipt;
use super::media_contract::{HostAudio, issue_media_token};
use super::pcm_bridge::{self, DRAIN_DEADLINE};
use crate::{SdkError, client::RamfluxClient};
use ramflux_media::authorization::{GateReason, GateSnapshot};
use ramflux_media::{Capture, Engine, EngineStats, MediaSession, Playback};
use std::cell::RefCell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static AUDIO_RESERVED: AtomicBool = AtomicBool::new(false);

pub(crate) struct Reservation(String);
impl Drop for Reservation {
    fn drop(&mut self) {
        AUDIO_RESERVED.store(false, Ordering::Release);
    }
}

/// Credential-free view of the private engine owner. No key-export path.
#[derive(Clone, Debug)]
pub struct InProcessMediaStatus {
    pub receipt: InProcessMediaReceipt,
    pub gate: GateSnapshot,
    pub stats: EngineStats,
    pub drained: bool,
}

pub(crate) struct OwnedMedia {
    pub receipt: InProcessMediaReceipt,
    /// Opaque public handle; process-lifetime, never reused.
    token: u64,
    pub session: Mutex<Option<MediaSession>>,
    binding: Binding,
    running: Mutex<Running>,
}

struct Binding {
    call_ref: Option<String>,
    caller: ramflux_protocol::CallEndpoint,
    callee: ramflux_protocol::CallEndpoint,
    generation: Option<String>,
}

struct Running {
    lease_expires_at: u64,
    engine: Option<Engine>,
    last: InProcessMediaStatus,
    host: HostAudio,
}

fn audio_busy() -> SdkError {
    SdkError::LocalBusRefused {
        code: "rate_limited".into(),
        message: "voice call: audio slot busy".into(),
        body: Box::new(serde_json::Value::Null),
    }
}
fn unavailable() -> SdkError {
    SdkError::LocalBus("voice call: media engine unavailable".into())
}
fn remaining(expires: u64) -> Duration {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(expires))
        .and_then(|expiry| expiry.duration_since(SystemTime::now()).ok())
        .unwrap_or(Duration::ZERO)
}

impl OwnedMedia {
    pub(crate) fn new(
        session: MediaSession,
        receipt: InProcessMediaReceipt,
        call: &super::state::LiveCall,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            token: issue_media_token()?,
            binding: Binding {
                call_ref: call.call_ref.clone(),
                caller: call.caller.clone(),
                callee: call.callee.clone(),
                generation: call.gateway_generation.clone(),
            },
            running: Mutex::new(Running {
                lease_expires_at: receipt.lease_expires_at,
                engine: None,
                last: InProcessMediaStatus {
                    receipt: receipt.clone(),
                    gate: GateSnapshot {
                        reason: Some(GateReason::AudioInactive),
                        generation: 1,
                        audio_active: false,
                        retired: false,
                    },
                    stats: EngineStats::default(),
                    drained: false,
                },
                host: HostAudio::default(),
            }),
            receipt,
            session: Mutex::new(Some(session)),
        })
    }

    /// Apply a host-state change under the owner lock and advance the public revision.
    pub(crate) fn update_host(&self, change: impl FnOnce(&mut HostAudio)) {
        let mut running = self.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        change(&mut running.host);
        running.host.status_revision = running.host.status_revision.saturating_add(1);
    }

    /// Mute or unmute the engine's capture path (checkpoint 3 adds the completion fence).
    pub(crate) fn set_engine_muted(&self, muted: bool) -> Result<(), SdkError> {
        let running = self.running.lock().map_err(|_| unavailable())?;
        let engine = running.engine.as_ref().ok_or_else(unavailable)?;
        engine.set_muted(muted);
        Ok(())
    }

    /// Opaque public handle of this session.
    pub(crate) fn token(&self) -> u64 {
        self.token
    }

    /// Copy of the host-reported state with the live PCM counters filled in.
    pub(crate) fn host_state(&self) -> HostAudio {
        let mut host = self.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner).host;
        let (captured, capture_drops, render_underruns) = pcm_bridge::counters();
        host.captured_frames = captured;
        host.capture_drops = capture_drops;
        host.render_underruns = render_underruns;
        host
    }

    fn start(
        &mut self,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
    ) -> Result<(), SdkError> {
        let session =
            self.session.lock().map_err(|_| unavailable())?.take().ok_or_else(unavailable)?;
        let result = Engine::start_authorized(
            session,
            capture,
            playback,
            remaining(self.receipt.lease_expires_at),
        );
        let mut running = self.running.lock().map_err(|_| unavailable())?;
        if let Ok(engine) = result {
            let generation = engine.gate().generation;
            pcm_bridge::publish(self.token, generation).map_err(|_| unavailable())?;
            running.engine = Some(engine);
            Ok(())
        } else {
            running.last.gate.reason = Some(GateReason::Terminal);
            running.last.gate.retired = true;
            running.last.drained = true;
            Err(unavailable())
        }
    }

    fn stop(&self, reason: GateReason) {
        self.session.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        // Unpublish first so no new callback passes; then join the engine workers; then drain.
        pcm_bridge::retire(self.token);
        let mut running = self.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = running.engine.take() {
            let mut gate = engine.fence(reason);
            running.last.stats = engine.stats();
            // stop joins every worker before releasing the process slot.
            running.last.stats = engine.stop_with_stats();
            gate.reason = Some(reason);
            gate.audio_active = false;
            gate.retired = true;
            running.last.gate = gate;
        }
        running.last.gate.reason = Some(reason);
        running.last.gate.retired = true;
        running.last.drained = pcm_bridge::drain(self.token, DRAIN_DEADLINE);
    }

    /// Mirror the engine's I/O generation into the callbacks, then open them only while the
    /// SDK authority and the OS audio gate both allow audio.
    fn sync_pcm(&self, running: &Running) {
        let Some(engine) = running.engine.as_ref() else {
            pcm_bridge::set_open(self.token, false);
            return;
        };
        let gate = engine.gate();
        let fenced = pcm_bridge::set_generation(self.token, gate.generation);
        pcm_bridge::set_open(self.token, fenced && gate.reason.is_none() && gate.audio_active);
    }

    /// Accepted route change: rotate the I/O generation so no old-generation audio survives.
    pub(crate) fn rotate_io(&self) {
        let running = self.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = &running.engine {
            engine.rotate_io();
        }
        self.sync_pcm(&running);
    }

    fn snapshot(&self) -> InProcessMediaStatus {
        let mut running = self.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = &running.engine {
            let gate = engine.gate();
            let stats = engine.stats();
            running.last.gate = gate;
            running.last.stats = stats;
        }
        running.last.clone()
    }
}

impl RamfluxClient {
    pub(crate) fn reserve_call_audio(&self, call_id: &str) -> Result<(), SdkError> {
        if self.media_ownership != crate::bus::protocol::MediaOwnership::InProcess {
            return Ok(());
        }
        let mut slot = self.media_reservation.borrow_mut();
        if let Some(held) = slot.as_ref() {
            return if held.0 == call_id { Ok(()) } else { Err(audio_busy()) };
        }
        AUDIO_RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| audio_busy())?;
        *slot = Some(Reservation(call_id.to_owned()));
        Ok(())
    }

    /// Start the private one-shot engine on the account writer. Host adapters carry PCM only.
    /// # Errors
    /// Refuses stale call sequence, wrong ownership, a second sender or invalid authority/lease.
    pub fn start_in_process_media(
        &mut self,
        call_id: &str,
        expected_seq: u64,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
    ) -> Result<InProcessMediaStatus, SdkError> {
        let call = self.voice_calls.get(call_id).ok_or_else(unavailable)?;
        if call.row.seq != expected_seq {
            return Err(SdkError::EditConflict {
                target: call_id.to_owned(),
                expected: expected_seq,
                received: call.row.seq,
            });
        }
        let _receipt = self.handoff_in_process_media(call_id, crate::time::now_unix_timestamp())?;
        let result =
            self.in_process_media.as_mut().ok_or_else(unavailable)?.start(capture, playback);
        if let Err(error) = result {
            self.media_reservation.borrow_mut().take();
            return Err(error);
        }
        self.in_process_media_status(call_id)
    }

    /// Reconcile an engine snapshot with current SDK truth, independent of host subscriptions.
    /// # Errors
    /// Refuses another call's binding or a missing engine.
    pub fn in_process_media_status(&self, call_id: &str) -> Result<InProcessMediaStatus, SdkError> {
        self.reconcile_in_process_media();
        let owned = self
            .in_process_media
            .as_ref()
            .filter(|owned| owned.receipt.call_id == call_id)
            .ok_or_else(unavailable)?;
        Ok(owned.snapshot())
    }

    /// Report OS audio readiness; this can never grant SDK authority.
    /// # Errors
    /// Refuses a missing call, a closed SDK gate or a retired engine.
    pub fn set_in_process_audio_active(
        &self,
        call_id: &str,
        active: bool,
    ) -> Result<InProcessMediaStatus, SdkError> {
        self.reconcile_in_process_media();
        let owned = self
            .in_process_media
            .as_ref()
            .filter(|owned| owned.receipt.call_id == call_id)
            .ok_or_else(unavailable)?;
        {
            let running = owned.running.lock().map_err(|_| unavailable())?;
            let engine = running.engine.as_ref().ok_or_else(unavailable)?;
            if !engine.audio_active(active) {
                return Err(SdkError::LocalBusPermissionDenied);
            }
            owned.sync_pcm(&running);
        }
        Ok(owned.snapshot())
    }

    /// Close and drain the private engine, without signalling hangup or permitting key reuse.
    /// # Errors
    /// Refuses a missing or foreign call binding.
    pub fn close_in_process_media(&self, call_id: &str) -> Result<InProcessMediaStatus, SdkError> {
        let owned = self
            .in_process_media
            .as_ref()
            .filter(|owned| owned.receipt.call_id == call_id)
            .ok_or_else(unavailable)?;
        owned.stop(GateReason::Terminal);
        self.media_reservation.borrow_mut().take();
        Ok(owned.snapshot())
    }

    /// Owned session bound to this public media token, if it is still held by this writer.
    pub(crate) fn media_by_token(&self, token: u64) -> Option<&OwnedMedia> {
        self.in_process_media.as_deref().filter(|owned| owned.token == token)
    }

    pub(crate) fn stop_in_process_media(&self, reason: GateReason) {
        if let Some(owned) = &self.in_process_media {
            owned.stop(reason);
        }
        self.media_reservation.borrow_mut().take();
    }

    pub(crate) fn reconcile_in_process_media(&self) {
        if let Some(owned) = &self.in_process_media {
            self.reconcile_owned_media(owned);
        }
        let release = self.media_reservation.borrow().as_ref().is_some_and(|reservation| {
            self.voice_calls.get(&reservation.0).is_none_or(|call| call.row.state == "ended")
        });
        if release {
            self.media_reservation.borrow_mut().take();
        }
    }

    pub(crate) fn current_call_media_authority(
        &self,
        call: &super::state::LiveCall,
    ) -> Result<(), SdkError> {
        if self.call_local_endpoint()? != call.local {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        let peer = if call.local == call.caller { &call.callee } else { &call.caller };
        let record = self.trusted_device(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            &self.call_device_identity(peer)?,
        )?;
        if !record
            .get("signing_public_key")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|key| call.peer_key_matches(peer, key))
        {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        Ok(())
    }

    fn reconcile_owned_media(&self, owned: &OwnedMedia) {
        let Some(call) = self.voice_calls.get(&owned.receipt.call_id) else {
            owned.stop(GateReason::Terminal);
            return;
        };
        if call.row.state == "ended" {
            owned.stop(GateReason::Terminal);
            return;
        }
        let authority_hold = match self.current_call_media_authority(call) {
            Ok(()) => None,
            Err(error) if crate::error_policy::approval_retryable(&error) => {
                Some(GateReason::ResyncRequired)
            }
            _ => {
                owned.stop(GateReason::Terminal);
                return;
            }
        };
        if call.media_lost() || call.allocation.is_none() {
            owned.stop(GateReason::LeaseUnavailable);
            return;
        }
        let Some(allocation) = &call.allocation else { return };
        let lease = remaining(allocation.expires_at.min(allocation.hard_expires_at));
        if lease.is_zero() {
            owned.stop(GateReason::LeaseUnavailable);
            return;
        }
        let changed_peer = owned.binding.caller != call.caller
            || owned.binding.callee != call.callee
            || owned.binding.call_ref != call.call_ref;
        if changed_peer {
            owned.stop(GateReason::ResyncRequired);
            return;
        }
        let reason = if authority_hold.is_some() {
            authority_hold
        } else if call.gateway_generation.is_none()
            || *self.media_connection_generation.borrow() != call.gateway_generation
        {
            Some(GateReason::ResyncRequired)
        } else if call.media_held {
            Some(if owned.binding.generation == call.gateway_generation {
                GateReason::GatewayHold
            } else {
                GateReason::ResyncRequired
            })
        } else if call.row.state != "active" {
            Some(GateReason::CallNotActive)
        } else {
            None
        };
        let mut running = owned.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(engine) = &running.engine {
            engine.authorize(reason, lease, allocation.expires_at > running.lease_expires_at);
        }
        running.lease_expires_at = allocation.expires_at;
        running.last.receipt.lease_expires_at = allocation.expires_at;
        if let Some(generation) = &call.gateway_generation {
            running.last.receipt.resolution_generation.clone_from(generation);
        }
        owned.sync_pcm(&running);
    }
}

pub(crate) type AudioReservation = RefCell<Option<Reservation>>;
