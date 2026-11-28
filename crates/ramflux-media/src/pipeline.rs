// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One frame's way out and one packet's way in, without I/O.
//!
//! Out: PCM frame → Opus → RTP header → `SFrame` (the RTP header is the
//! authenticated metadata) → relay framing.
//! In: datagram → RTP header → `SFrame` decryption (with that header as
//! metadata) → the Opus packet, for the jitter buffer.
//!
//! The packet on the wire is `rtp_header || sframe_header || ciphertext ||
//! tag`: the relay sees sequence numbers and timestamps, never audio.

use zeroize::Zeroizing;

use crate::codec::{CodecError, Encoder, FRAME_SAMPLES, Frame};
use crate::rebind::{self, Rebind};
use crate::relay;
use crate::rtp::{self, OPUS_PAYLOAD_TYPE, RtpHeader};
use crate::session::MediaSession;
use crate::sframe::{self, SframeError};
use crate::video::feedback::{self as video_feedback, FEEDBACK_PAYLOAD_TYPE, Feedback};
use crate::video::packet::{
    self as video_packet, FragmentHeader, METADATA_LEN, SequenceTracker, VIDEO_PAYLOAD_TYPE,
};

/// Why a frame or packet could not pass.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The codec failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// `SFrame` refused (unknown suite or key, failed authentication, replay).
    #[error(transparent)]
    Sframe(#[from] SframeError),
    /// Not a minimal RTP packet with the Opus payload type.
    #[error("not an RTP packet of this call")]
    NotRtp,
    /// The session's sending key was already taken by a sender: a key
    /// starts once, at counter zero.
    #[error("the session's sending key is in use; a fresh call brings fresh keys")]
    SendKeyUsed,
    /// A video packet arrived on a call that did not negotiate video keys.
    #[error("video is not negotiated on this call")]
    VideoNotNegotiated,
    /// A video packet failed its video framing (after authentication).
    #[error(transparent)]
    Video(#[from] video_packet::Error),
    /// A video feedback report is malformed or too large.
    #[error(transparent)]
    Feedback(#[from] video_feedback::Error),
    /// The `SFrame` KID does not belong to the packet's track: audio KIDs
    /// (0 and 1) ride PT111 only; video KIDs (2 and 3) ride PT112 and PT113
    /// only. Refused before any decryption and counted by the engine.
    #[error("SFrame KID does not belong to this track")]
    KidMismatch,
}

/// Largest audio `SFrame` KID (audio uses KIDs 0 and 1, one per direction).
pub const AUDIO_KID_MAX: u64 = 1;
/// Video `SFrame` KIDs (one per direction).
pub const VIDEO_KIDS: std::ops::RangeInclusive<u64> = 2..=3;

fn audio_kid_ok(kid: u64) -> bool {
    kid <= AUDIO_KID_MAX
}

pub(crate) fn video_kid_ok(kid: u64) -> bool {
    VIDEO_KIDS.contains(&kid)
}

/// The KID in the `SFrame` header at the start of `data`, read before any
/// decryption (the header is clear; the KID is not secret).
fn header_kid(data: &[u8]) -> Result<u64, PipelineError> {
    Ok(sframe::Header::decode(data)?.0.kid)
}

/// The sending half of a call.
#[derive(Debug)]
pub struct Outbound {
    encoder: Encoder,
    sframe: sframe::Sender,
    token: Vec<u8>,
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    marker: bool,
}

impl Outbound {
    /// The sending half for `session`, with this stream's `ssrc` and
    /// initial sequence number and timestamp (random in a real call, RFC
    /// 3550 §5.1). It takes the session's sending key: its `SFrame` counter
    /// starts at zero, and no other sender can ever use that key.
    ///
    /// # Errors
    ///
    /// An unknown suite or empty key, the sending key already taken, or
    /// libopus refused to start.
    pub fn new(
        session: &mut MediaSession,
        ssrc: u32,
        sequence: u16,
        timestamp: u32,
    ) -> Result<Self, PipelineError> {
        let suite = sframe::suite(session.suite())?;
        if !audio_kid_ok(session.send_kid()) {
            return Err(PipelineError::KidMismatch);
        }
        let key = session.take_send_key().ok_or(PipelineError::SendKeyUsed)?;
        Ok(Self {
            encoder: Encoder::new()?,
            sframe: sframe::Sender::new(suite, key.kid(), key.base_key().bytes())?,
            token: session.token().to_vec(),
            ssrc,
            sequence,
            timestamp,
            marker: true,
        })
    }

    /// The datagram carrying one frame.
    ///
    /// # Errors
    ///
    /// The codec or `SFrame` failed.
    pub fn packet(&mut self, frame: &Frame) -> Result<Vec<u8>, PipelineError> {
        let opus = self.encoder.encode(frame)?;
        let header = RtpHeader {
            marker: std::mem::take(&mut self.marker),
            payload_type: OPUS_PAYLOAD_TYPE,
            sequence: self.sequence,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
        }
        .encode();
        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp =
            self.timestamp.wrapping_add(u32::try_from(FRAME_SAMPLES).unwrap_or(u32::MAX));
        let protected = self.sframe.encrypt(&header, &opus)?;
        let mut packet = Vec::with_capacity(header.len() + protected.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&protected);
        Ok(relay::frame(&self.token, &packet))
    }

    /// A datagram that only keeps the relay binding alive (an empty
    /// packet: the peer drops it). `None` without a relay.
    #[must_use]
    pub fn keepalive(&self) -> Option<Vec<u8>> {
        (!self.token.is_empty()).then(|| relay::frame(&self.token, &[]))
    }
}

impl Drop for Outbound {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

/// Answers the relay's rebinding challenges (see [`crate::rebind`]).
#[derive(Debug)]
pub struct Rebinder {
    token: Zeroizing<Vec<u8>>,
    rebind: Option<Rebind>,
}

impl Rebinder {
    /// The answerer for `session`; it answers nothing without a relay
    /// token or a rebind credential.
    pub fn new(session: &mut MediaSession) -> Self {
        Self { token: Zeroizing::new(session.token().to_vec()), rebind: session.take_rebind() }
    }

    /// The datagram answering `datagram` when it is a rebinding challenge
    /// (to send back from the socket it arrived on); `None` otherwise.
    #[must_use]
    pub fn answer(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        let rebind = self.rebind.as_ref().filter(|_| !self.token.is_empty())?;
        let challenge = rebind::challenge(datagram)?;
        Some(relay::frame(&self.token, &rebind.response(&challenge)))
    }

    /// Whether `datagram` is shaped like a rebinding challenge (answered
    /// or not, it is never media).
    #[must_use]
    pub fn is_challenge(datagram: &[u8]) -> bool {
        rebind::challenge(datagram).is_some()
    }
}

/// One accepted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// Its RTP header.
    pub header: RtpHeader,
    /// The decrypted Opus packet.
    pub opus: Vec<u8>,
}

/// One authenticated video fragment, before reassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoReceived {
    /// Its RTP header.
    pub header: RtpHeader,
    /// Its video header (authenticated metadata).
    pub fragment: FragmentHeader,
    /// The RTP sequence extended to 64 bits, `None` before the stream origin.
    pub extended_sequence: Option<u64>,
    /// The decrypted fragment bytes.
    pub payload: Vec<u8>,
}

/// What one datagram carried after demultiplexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Demuxed {
    /// An audio packet (PT111), exactly as [`Inbound::open`] returns it.
    Audio(Received),
    /// A video fragment (PT112).
    Video(VideoReceived),
    /// A video feedback report (PT113).
    Feedback(Feedback),
}

/// The receiving half of a call: audio and, when negotiated, video.
#[derive(Debug)]
pub struct Inbound {
    sframe: sframe::Receiver,
    audio_kid: u64,
    video: Option<VideoRx>,
    video_sequence: SequenceTracker,
}

/// The peer's video receiving context: its KID and its decryption keys.
#[derive(Debug)]
struct VideoRx {
    kid: u64,
    receiver: sframe::Receiver,
}

impl Inbound {
    /// The receiving half for `session`.
    ///
    /// # Errors
    ///
    /// An unknown suite or empty key.
    pub fn new(session: &MediaSession) -> Result<Self, PipelineError> {
        let suite = sframe::suite(session.suite())?;
        let key = session.receive_key();
        if !audio_kid_ok(key.kid()) {
            return Err(PipelineError::KidMismatch);
        }
        let mut receiver = sframe::Receiver::new();
        receiver.add_key(suite, key.kid(), key.base_key().bytes())?;
        let video = match session.video_receive_key() {
            Some(video_key) => {
                if !video_kid_ok(video_key.kid()) {
                    return Err(PipelineError::KidMismatch);
                }
                let mut video_receiver = sframe::Receiver::new();
                video_receiver.add_key(suite, video_key.kid(), video_key.base_key().bytes())?;
                Some(VideoRx { kid: video_key.kid(), receiver: video_receiver })
            }
            None => None,
        };
        Ok(Self {
            sframe: receiver,
            audio_kid: key.kid(),
            video,
            video_sequence: SequenceTracker::default(),
        })
    }

    /// Whether `packet` is a video RTP packet (PT112), for the gate choice
    /// before any decryption.
    #[must_use]
    pub fn is_video(packet: &[u8]) -> bool {
        RtpHeader::decode(packet).is_some_and(|header| header.payload_type == VIDEO_PAYLOAD_TYPE)
    }

    /// Whether `packet` is a video feedback RTP packet (PT113).
    #[must_use]
    pub fn is_feedback(packet: &[u8]) -> bool {
        RtpHeader::decode(packet).is_some_and(|header| header.payload_type == FEEDBACK_PAYLOAD_TYPE)
    }

    /// Opens one feedback packet: authenticates its RTP header with the video
    /// key (the same counter stream as video), then reads the 64-byte report.
    ///
    /// # Errors
    ///
    /// [`PipelineError::Feedback`] for an oversized or malformed report,
    /// [`PipelineError::KidMismatch`] for a foreign KID,
    /// [`PipelineError::VideoNotNegotiated`] without a video key, or
    /// [`PipelineError::Sframe`] when authentication or replay refuses it.
    pub fn open_feedback(&mut self, packet: &[u8]) -> Result<Feedback, PipelineError> {
        if packet.len() > video_feedback::MAX_FEEDBACK_DATAGRAM {
            return Err(video_feedback::Error::Length.into());
        }
        let header = RtpHeader::decode(packet).ok_or(PipelineError::NotRtp)?;
        if header.payload_type != FEEDBACK_PAYLOAD_TYPE {
            return Err(PipelineError::NotRtp);
        }
        let track = self.video.as_mut().ok_or(PipelineError::VideoNotNegotiated)?;
        let body = packet.get(rtp::HEADER_LEN..).ok_or(PipelineError::NotRtp)?;
        if header_kid(body)? != track.kid {
            return Err(PipelineError::KidMismatch);
        }
        let payload = track.receiver.decrypt(&packet[..rtp::HEADER_LEN], body)?;
        Ok(Feedback::decode(&payload)?)
    }

    /// Demultiplexes one datagram: PT111 audio through [`Self::open`], PT112
    /// video through [`Self::open_video`].
    ///
    /// # Errors
    ///
    /// As [`Self::open`] or [`Self::open_video`].
    pub fn demux(&mut self, packet: &[u8]) -> Result<Demuxed, PipelineError> {
        if Self::is_feedback(packet) {
            return self.open_feedback(packet).map(Demuxed::Feedback);
        }
        if Self::is_video(packet) {
            self.open_video(packet).map(Demuxed::Video)
        } else {
            self.open(packet).map(Demuxed::Audio)
        }
    }

    /// Opens one video packet: authenticates the RTP and video headers with
    /// the video key, then reads the fragment. Authentication precedes any
    /// parsing of the video header beyond the packet shape.
    ///
    /// # Errors
    ///
    /// [`PipelineError::NotRtp`] for a packet that is not PT112,
    /// [`PipelineError::VideoNotNegotiated`] without a video key,
    /// [`PipelineError::Sframe`] when authentication or replay refuses it, or
    /// [`PipelineError::Video`] for a malformed video header or fragment.
    pub fn open_video(&mut self, packet: &[u8]) -> Result<VideoReceived, PipelineError> {
        let header = RtpHeader::decode(packet).ok_or(PipelineError::NotRtp)?;
        if header.payload_type != VIDEO_PAYLOAD_TYPE || packet.len() < METADATA_LEN {
            return Err(PipelineError::NotRtp);
        }
        let track = self.video.as_mut().ok_or(PipelineError::VideoNotNegotiated)?;
        let body = packet.get(METADATA_LEN..).ok_or(PipelineError::NotRtp)?;
        if header_kid(body)? != track.kid {
            return Err(PipelineError::KidMismatch);
        }
        let payload = track.receiver.decrypt(&packet[..METADATA_LEN], body)?;
        let fragment =
            video_packet::decode_fragment(&packet[rtp::HEADER_LEN..METADATA_LEN], &payload)?;
        let extended_sequence = self.video_sequence.extend(header.sequence);
        Ok(VideoReceived { header, fragment, extended_sequence, payload })
    }

    /// Opens one packet (as the relay delivers it: no framing).
    ///
    /// # Errors
    ///
    /// Not RTP of this call, or `SFrame` refused it (forged, altered,
    /// replayed or under an unknown key).
    pub fn open(&mut self, packet: &[u8]) -> Result<Received, PipelineError> {
        let header = RtpHeader::decode(packet).ok_or(PipelineError::NotRtp)?;
        if header.payload_type != OPUS_PAYLOAD_TYPE {
            return Err(PipelineError::NotRtp);
        }
        let body = packet.get(rtp::HEADER_LEN..).ok_or(PipelineError::NotRtp)?;
        if header_kid(body)? != self.audio_kid {
            return Err(PipelineError::KidMismatch);
        }
        let opus = self.sframe.decrypt(&packet[..rtp::HEADER_LEN], body)?;
        Ok(Received { header, opus })
    }
}
