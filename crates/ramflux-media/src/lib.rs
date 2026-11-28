// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The one-to-one voice media engine.
//!
//! One call: the host supplies 20 ms PCM frames ([`codec::Frame`]), the
//! engine encodes them with Opus (48 kHz mono), puts them in a minimal RTP
//! packet whose payload is end-to-end encrypted with `SFrame`, and sends that
//! over UDP to the relay allocation the daemon hands out. The peer's packets
//! come back the same way into an adaptive jitter buffer and out as PCM
//! through the host's sink. The relay sees sequence numbers, timestamps and
//! ciphertext, never audio or keys. Microphone and speaker I/O stay in the
//! host: it implements [`engine::Capture`] and [`engine::Playback`].
//!
//! - [`sframe`]: RFC 9605 (header, cipher suites, sender and receiver with
//!   replay protection).
//! - [`rtp`]: the minimal RTP header (RFC 3550).
//! - [`codec`]: Opus through the reference libopus (RFC 6716, RFC 7587).
//! - [`jitter`]: the adaptive jitter buffer.
//! - [`relay`]: datagram framing towards the relay allocation.
//! - [`rebind`]: answering the relay when this side's address changes.
//! - [`session`]: what one call needs (endpoint, token, rebind credential,
//!   keys), used once.
//! - [`pipeline`]: one frame out, one packet in, without I/O.
//! - [`engine`]: the send, receive and playout threads.
//! - [`video`]: video packetization, bounded reassembly, feedback and rate
//!   (V2.1; the engine demuxes PT112 onto the same socket).
//!
//! No UI toolkit and no async runtime. The host hands a
//! [`session::MediaSession`] in and reads [`engine::Engine::stats`] back.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod codec;
pub mod engine;
pub mod jitter;
pub mod pipeline;
pub mod rebind;
pub mod relay;
pub mod rtp;
pub mod session;
pub mod sframe;
pub mod video;

pub use engine::{Capture, Engine, EngineError, EngineStats, Playback, Quality};
pub use rebind::Rebind;
pub use session::{DirectionKey, MediaSession};
pub use sframe::BaseKey;
