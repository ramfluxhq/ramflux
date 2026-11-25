// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Video track (V2.1): packetization, bounded reassembly, feedback and rate.
//!
//! Video shares the one socket and demux of the call engine (PT111 audio,
//! PT112 video) but has its own gate, crypto context and queues.

pub mod control;
pub mod feedback;
pub mod packet;
pub mod rate;
pub mod reassembly;
pub mod send;
