// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-shot move of a live call's media session into this account's in-process slot.
//! Credentials are wiped from the call record, never serialized, and never logged.

use crate::SdkError;
use crate::bus::protocol::MediaOwnership;
use crate::client::RamfluxClient;
use ramflux_media::sframe::{AES_256_GCM_SHA512_128, BaseKey};
use ramflux_media::{DirectionKey, MediaSession, Rebind};
use zeroize::{Zeroize, Zeroizing};

/// Non-secret result of a completed in-process handoff.
/// The session stays in the account writer and is not returned.
#[derive(Clone, Debug)]
#[must_use]
pub struct InProcessMediaReceipt {
    pub call_id: String,
    pub device_id: String,
    pub resolution_generation: String,
    pub lease_expires_at: u64,
}

struct MovedMedia {
    call_id: String,
    device_id: String,
    resolution_generation: String,
    lease_expires_at: u64,
    endpoint: String,
    token: Zeroizing<Vec<u8>>,
    lease_id: Zeroizing<[u8; 16]>,
    side: u8,
    rebind_key: Zeroizing<[u8; 32]>,
    send_kid: u64,
    send_key: Zeroizing<[u8; 32]>,
    receive_kid: u64,
    receive_key: Zeroizing<[u8; 32]>,
    /// Video send and receive keys, only when both exist (CALLS-VIDEO-V1). Video KIDs are audio KIDs + 2.
    video: Option<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)>,
}

fn unavailable(message: &str) -> SdkError {
    SdkError::LocalBus(format!("voice call: {message}"))
}

fn fresh_call() -> SdkError {
    unavailable("media session unavailable; start a fresh call before restarting the media engine")
}

fn decode_exact<const N: usize>(text: &str) -> Result<Zeroizing<[u8; N]>, SdkError> {
    let bytes = Zeroizing::new(
        ramflux_protocol::decode_base64url(text)
            .map_err(|_| unavailable("allocation unavailable"))?,
    );
    let array: [u8; N] =
        bytes.as_slice().try_into().map_err(|_| unavailable("allocation unavailable"))?;
    Ok(Zeroizing::new(array))
}

impl RamfluxClient {
    /// Fix this process to in-process media ownership before any account is open.
    /// Calling it again with the same mode, still before an account opens, is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::LocalBusPermissionDenied`] when an account is already open
    /// or ownership was already fixed to external.
    pub fn fix_in_process_media_ownership(&mut self) -> Result<(), SdkError> {
        if self.active_account_db.is_some()
            || self.born_v3_account.is_some()
            || self.identity_root.is_some()
        {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        if self.media_ownership_bound && self.media_ownership != MediaOwnership::InProcess {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        self.media_ownership = MediaOwnership::InProcess;
        self.media_ownership_bound = true;
        Ok(())
    }

    /// Inherit the process mode fixed on the daemon config. This is not a runtime switch.
    /// An account database may already be open: restore installs the client after opening it.
    pub(crate) fn bind_process_media_ownership(
        &mut self,
        ownership: MediaOwnership,
    ) -> Result<(), SdkError> {
        if self.media_ownership_bound && self.media_ownership != ownership {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        self.media_ownership = ownership;
        self.media_ownership_bound = true;
        Ok(())
    }

    /// Move one live call's media keys into this account's single in-process session.
    /// `now` is the caller's logical Unix time. The caller does not supply a device
    /// or a resolution generation.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::LocalBusPermissionDenied`] when ownership is not in-process,
    /// a session is already held, or the selected device is not this account.
    /// A missing, held, expired, or already-taken call is refused without copying keys.
    /// A failure after the keys are taken leaves the call consumed; start a fresh call.
    pub fn handoff_in_process_media(
        &mut self,
        call_id: &str,
        now: i64,
    ) -> Result<InProcessMediaReceipt, SdkError> {
        self.admit_in_process_handoff(call_id, now)?;
        self.reserve_call_audio(call_id)?;
        // extract consumes the keys. A later assembly failure must not put them back.
        let moved = self.extract_in_process_media(call_id)?;
        let (session, receipt) = assemble_session(moved)?;
        let call = self.voice_calls.get(call_id).ok_or_else(fresh_call)?;
        self.in_process_media =
            Some(Box::new(super::media_owner::OwnedMedia::new(session, receipt.clone(), call)));
        Ok(receipt)
    }

    fn admit_in_process_handoff(&self, call_id: &str, now: i64) -> Result<(), SdkError> {
        if self.media_ownership != MediaOwnership::InProcess {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        if self.in_process_media.as_ref().is_some_and(|owned| owned.receipt.call_id == call_id)
            || self.in_process_media.as_ref().is_some_and(|owned| {
                self.voice_calls
                    .get(&owned.receipt.call_id)
                    .is_some_and(|call| call.row.state != "ended")
            })
        {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        let (local, generation, expires_at, hard_expires_at, has_receive) = {
            let call = self
                .voice_calls
                .get(call_id)
                .ok_or_else(|| unavailable("media keys unavailable"))?;
            if call.row.call_id != call_id {
                return Err(unavailable("media keys unavailable"));
            }
            if call.media_taken {
                return Err(fresh_call());
            }
            if call.row.state != "active" || call.media_held {
                return Err(unavailable("call resolution missing"));
            }
            let allocation = call.allocation.as_ref();
            (
                call.local.clone(),
                call.gateway_generation.clone(),
                allocation.map(|item| item.expires_at),
                allocation.map(|item| item.hard_expires_at),
                call.receive_key.is_some(),
            )
        };
        let call = self.voice_calls.get(call_id).ok_or_else(fresh_call)?;
        self.current_call_media_authority(call)?;
        let verified = self.call_local_endpoint()?;
        if local != verified {
            return Err(SdkError::LocalBusPermissionDenied);
        }
        if generation.is_none() || generation != *self.media_connection_generation.borrow() {
            return Err(unavailable("call resolution missing"));
        }
        let (Some(expires_at), Some(hard_expires_at)) = (expires_at, hard_expires_at) else {
            return Err(unavailable("allocation unavailable"));
        };
        if !has_receive {
            return Err(unavailable("receive key unavailable"));
        }
        // A negative clock cannot satisfy the lease. Equality is already expired.
        let now_unix = u64::try_from(now).unwrap_or(u64::MAX);
        if expires_at <= now_unix || hard_expires_at < expires_at {
            return Err(unavailable("allocation unavailable"));
        }
        Ok(())
    }

    fn extract_in_process_media(&mut self, call_id: &str) -> Result<MovedMedia, SdkError> {
        let call = self
            .voice_calls
            .get_mut(call_id)
            .ok_or_else(|| unavailable("media keys unavailable"))?;
        if call.media_taken || call.row.state != "active" || call.media_held {
            return Err(fresh_call());
        }
        let generation = call
            .gateway_generation
            .clone()
            .ok_or_else(|| unavailable("call resolution missing"))?;
        let decoded = decode_allocation(call)?;
        let Some(receive_key) = call.receive_key.take() else {
            return Err(unavailable("receive key unavailable"));
        };
        let outgoing = call.local == call.caller;
        let device_id = call.local.device_id.clone();
        let call_id = call.row.call_id.clone();
        let send_key = std::mem::replace(&mut call.send_key, Zeroizing::new([0; 32]));
        let video = match (call.video_send_key.take(), call.video.take_key()) {
            (Some(send), Some(receive)) => {
                tracing::info!(
                    call_id = %call.row.call_id,
                    send_commit = %super::video_signaling::key_commit(&send),
                    receive_commit = %super::video_signaling::key_commit(&receive),
                    "video keys selected for the media session"
                );
                Some((send, receive))
            }
            _ => None,
        };
        if let Some(allocation) = call.allocation.as_mut() {
            call.allocation_credentials = Some(super::lease::credentials_commitment(allocation));
            allocation.token.zeroize();
            allocation.rebind_key.zeroize();
        }
        call.media_taken = true;
        Ok(MovedMedia {
            call_id,
            device_id,
            resolution_generation: generation,
            lease_expires_at: decoded.lease_expires_at,
            endpoint: decoded.endpoint,
            token: decoded.token,
            lease_id: decoded.lease_id,
            side: decoded.side,
            rebind_key: decoded.rebind_key,
            send_kid: u64::from(!outgoing),
            send_key,
            receive_kid: u64::from(outgoing),
            receive_key,
            video,
        })
    }
}

struct DecodedAllocation {
    endpoint: String,
    token: Zeroizing<Vec<u8>>,
    lease_id: Zeroizing<[u8; 16]>,
    side: u8,
    rebind_key: Zeroizing<[u8; 32]>,
    lease_expires_at: u64,
}

fn decode_allocation(
    call: &crate::client::call::state::LiveCall,
) -> Result<DecodedAllocation, SdkError> {
    let Some(allocation) = call.allocation.as_ref() else {
        return Err(unavailable("allocation unavailable"));
    };
    if allocation.endpoint.is_empty() || allocation.side > 1 {
        return Err(unavailable("allocation unavailable"));
    }
    let token = decode_exact::<32>(&allocation.token)?;
    let lease_id = decode_exact::<16>(&allocation.lease_id)?;
    let rebind_key = decode_exact::<32>(&allocation.rebind_key)?;
    Ok(DecodedAllocation {
        endpoint: allocation.endpoint.clone(),
        token: Zeroizing::new(token.to_vec()),
        lease_id,
        side: allocation.side,
        rebind_key,
        lease_expires_at: allocation.expires_at,
    })
}

fn assemble_session(
    mut moved: MovedMedia,
) -> Result<(MediaSession, InProcessMediaReceipt), SdkError> {
    let receipt = InProcessMediaReceipt {
        call_id: moved.call_id,
        device_id: moved.device_id,
        resolution_generation: moved.resolution_generation,
        lease_expires_at: moved.lease_expires_at,
    };
    let rebind = Rebind::new(*moved.lease_id, moved.side, &moved.rebind_key)
        .ok_or_else(|| unavailable("allocation unavailable"))?;
    let send = DirectionKey::new(
        moved.send_kid,
        BaseKey::new(std::mem::take(&mut *moved.send_key).to_vec()),
    );
    let receive = DirectionKey::new(
        moved.receive_kid,
        BaseKey::new(std::mem::take(&mut *moved.receive_key).to_vec()),
    );
    let token = std::mem::take(&mut *moved.token);
    let session = MediaSession::new(moved.endpoint, token, AES_256_GCM_SHA512_128, send, receive)
        .with_rebind(rebind);
    let session = match moved.video.take() {
        Some((video_send, video_receive)) => {
            tracing::info!(call_id = %receipt.call_id, "video keys fed to media session");
            session.with_video(
                DirectionKey::new(moved.send_kid + 2, BaseKey::new(video_send.to_vec())),
                DirectionKey::new(moved.receive_kid + 2, BaseKey::new(video_receive.to_vec())),
            )
        }
        None => session,
    };
    Ok((session, receipt))
}
