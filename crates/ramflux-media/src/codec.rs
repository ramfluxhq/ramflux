// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opus (RFC 6716) at 48 kHz, mono, 20 ms frames, through the reference
//! libopus.
//!
//! The encoder runs in `VoIP` mode with in-band forward error correction, so
//! a lost packet can be rebuilt from the next one; the decoder conceals a
//! loss with no packet at all.

use opus::{Application, Bitrate, Channels};
use thiserror::Error;

/// Sample rate of the call (RFC 7587 §4.1: the RTP clock is always 48 kHz).
pub const SAMPLE_RATE: u32 = 48_000;
/// Samples per 20 ms frame (mono).
pub const FRAME_SAMPLES: usize = 960;
/// Frame duration in milliseconds.
pub const FRAME_MS: u64 = 20;
/// Largest Opus packet (RFC 6716 §3.2.1: 1275 bytes per frame).
pub const MAX_PACKET: usize = 1275;
/// Target bitrate: wideband speech with room for FEC.
pub const BITRATE: i32 = 32_000;

/// One 20 ms frame of mono 16-bit PCM.
pub type Frame = [i16; FRAME_SAMPLES];

/// Why the codec failed.
#[derive(Debug, Error)]
#[error("opus: {0}")]
pub struct CodecError(#[from] opus::Error);

/// The Opus encoder of a call.
pub struct Encoder {
    inner: opus::Encoder,
    out: Vec<u8>,
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Encoder")
    }
}

impl Encoder {
    /// A `VoIP` encoder with in-band FEC.
    ///
    /// # Errors
    ///
    /// libopus refused the configuration.
    pub fn new() -> Result<Self, CodecError> {
        let mut inner = opus::Encoder::new(SAMPLE_RATE, Channels::Mono, Application::Voip)?;
        inner.set_bitrate(Bitrate::Bits(BITRATE))?;
        inner.set_inband_fec(true)?;
        inner.set_packet_loss_perc(10)?;
        Ok(Self { inner, out: vec![0; MAX_PACKET] })
    }

    /// Encodes one frame into an Opus packet.
    ///
    /// # Errors
    ///
    /// libopus failed.
    pub fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, CodecError> {
        let len = self.inner.encode(frame, &mut self.out)?;
        Ok(self.out[..len].to_vec())
    }
}

/// The Opus decoder of a call.
pub struct Decoder {
    inner: opus::Decoder,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Decoder")
    }
}

impl Decoder {
    /// A mono 48 kHz decoder.
    ///
    /// # Errors
    ///
    /// libopus refused the configuration.
    pub fn new() -> Result<Self, CodecError> {
        Ok(Self { inner: opus::Decoder::new(SAMPLE_RATE, Channels::Mono)? })
    }

    /// Decodes one packet into a frame.
    ///
    /// # Errors
    ///
    /// The packet is not valid Opus.
    pub fn decode(&mut self, packet: &[u8]) -> Result<Frame, CodecError> {
        let mut frame = [0_i16; FRAME_SAMPLES];
        self.inner.decode(packet, &mut frame, false)?;
        Ok(frame)
    }

    /// Rebuilds a lost frame from the FEC data in the packet after it.
    ///
    /// # Errors
    ///
    /// The packet is not valid Opus.
    pub fn recover(&mut self, next: &[u8]) -> Result<Frame, CodecError> {
        let mut frame = [0_i16; FRAME_SAMPLES];
        self.inner.decode(next, &mut frame, true)?;
        Ok(frame)
    }

    /// Conceals a lost frame (no packet to rebuild it from).
    ///
    /// # Errors
    ///
    /// libopus failed.
    pub fn conceal(&mut self) -> Result<Frame, CodecError> {
        let mut frame = [0_i16; FRAME_SAMPLES];
        self.inner.decode(&[], &mut frame, false)?;
        Ok(frame)
    }
}
