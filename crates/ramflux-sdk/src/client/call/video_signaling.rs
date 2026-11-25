// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video offer/selection and per-peer video track admission (CALLS-VIDEO-V1).
//! Signed controls are verified by the caller before they reach this module;
//! keys are admitted here only after every check passes.
use super::state::invalid;
use crate::SdkError;
use ramflux_protocol::{VideoOffer, VideoSelection};
use zeroize::Zeroizing;

pub(crate) const VIDEO_VERSION: u32 = 1;
pub(crate) const VIDEO_CODEC: &str = "h264";
pub(crate) const VIDEO_PROFILE: &str = "42e01f";
pub(crate) const VIDEO_PACKET_FORMAT: u32 = 1;
/// Highest ladder rung (1280x720 at 30 fps).
pub(crate) const VIDEO_MAX_RUNG: u32 = 3;
/// User video-state changes allowed per direction and call.
const MAX_VIDEO_STATE_CHANGES: u32 = 32;

/// The caller's video offer, attached to every Invite only when the caller asks for video.
pub(crate) fn offer(receive_enabled: bool) -> VideoOffer {
    VideoOffer {
        version: VIDEO_VERSION,
        codec: VIDEO_CODEC.to_owned(),
        profile: VIDEO_PROFILE.to_owned(),
        max_rung: VIDEO_MAX_RUNG,
        packet_format: VIDEO_PACKET_FORMAT,
        receive_enabled,
    }
}

/// Refuses an offer this build cannot honour.
pub(crate) fn check_offer(offer: &VideoOffer) -> Result<(), SdkError> {
    if offer.version != VIDEO_VERSION
        || offer.codec != VIDEO_CODEC
        || offer.profile != VIDEO_PROFILE
        || offer.packet_format != VIDEO_PACKET_FORMAT
        || offer.max_rung > VIDEO_MAX_RUNG
    {
        return Err(invalid("unsupported video offer"));
    }
    Ok(())
}

/// The callee's selection. `accept = false` is explicit audio-only consent.
pub(crate) fn selection(
    offer: &VideoOffer,
    accept: bool,
    receive_enabled: bool,
) -> Result<VideoSelection, SdkError> {
    check_offer(offer)?;
    Ok(VideoSelection {
        version: VIDEO_VERSION,
        accepted: accept,
        codec: VIDEO_CODEC.to_owned(),
        profile: VIDEO_PROFILE.to_owned(),
        max_rung: offer.max_rung,
        packet_format: VIDEO_PACKET_FORMAT,
        receive_enabled,
    })
}

/// The caller's check of a selection against its own offer; returns whether video was accepted.
pub(crate) fn check_selection(
    offer: &VideoOffer,
    selected: &VideoSelection,
) -> Result<bool, SdkError> {
    if selected.version != VIDEO_VERSION
        || selected.codec != VIDEO_CODEC
        || selected.profile != VIDEO_PROFILE
        || selected.packet_format != VIDEO_PACKET_FORMAT
        || (selected.accepted && selected.max_rung > offer.max_rung)
    {
        return Err(invalid("unsupported video selection"));
    }
    Ok(selected.accepted)
}

/// A fresh 32-byte video send key for one direction of the selected peer.
pub(crate) fn fresh_key() -> Result<Zeroizing<[u8; 32]>, SdkError> {
    Ok(Zeroizing::new(ramflux_crypto::random_32()?))
}

/// The first track control of a call: revision 1, the only control that carries the key.
pub(crate) fn initial_track(max_rung: u32, key: &[u8; 32]) -> ramflux_protocol::CallAction {
    ramflux_protocol::CallAction::VideoTrack {
        revision: 1,
        enabled: true,
        max_rung,
        base_key: Some(ramflux_protocol::encode_base64url(key)),
    }
}

/// Video state for one call's selected peer device.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct VideoTrackPeer {
    negotiated: bool,
    revision: u64,
    changes: u32,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl VideoTrackPeer {
    /// Records the selection outcome. A declined selection never admits a track.
    pub(crate) fn negotiate(&mut self, accepted: bool) {
        self.negotiated = accepted;
    }

    /// Whether the selected peer accepted video (a declined selection leaves this false).
    pub(crate) fn is_negotiated(&self) -> bool {
        self.negotiated
    }

    /// Moves the admitted peer receive key out for the media session, once.
    pub(crate) fn take_key(&mut self) -> Option<Zeroizing<[u8; 32]>> {
        self.key.take()
    }

    /// Admits one peer track control. The first control carries the key; later
    /// controls must carry none. Every refusal happens before any state changes.
    pub(crate) fn admit(
        &mut self,
        revision: u64,
        max_rung: u32,
        base_key: Option<&str>,
    ) -> Result<(), SdkError> {
        if !self.negotiated {
            return Err(invalid("video not negotiated"));
        }
        if max_rung > VIDEO_MAX_RUNG {
            return Err(invalid("unsupported video rung"));
        }
        if revision <= self.revision {
            return Err(invalid("stale video track revision"));
        }
        if self.changes >= MAX_VIDEO_STATE_CHANGES {
            return Err(invalid("video state change budget"));
        }
        let fresh = match (self.key.is_some(), base_key) {
            (false, Some(text)) => Some(decode_key(text)?),
            (false, None) => return Err(invalid("video key missing on first start")),
            (true, None) => None,
            (true, Some(_)) => return Err(invalid("video key repeated after first start")),
        };
        if let Some(key) = fresh {
            self.key = Some(key);
        }
        self.revision = revision;
        self.changes += 1;
        Ok(())
    }
}

fn decode_key(text: &str) -> Result<Zeroizing<[u8; 32]>, SdkError> {
    let bytes =
        Zeroizing::new(ramflux_protocol::decode_base64url(text).map_err(|_| invalid("video key"))?);
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid("video key"))?;
    Ok(Zeroizing::new(array))
}
