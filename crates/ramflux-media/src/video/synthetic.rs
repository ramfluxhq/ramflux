// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Itest-only synthetic video source (CALLS-VIDEO V2.2b). It produces fixed-size AVCC access
//! units on a 30 fps clock with an IDR every [`IDR_EVERY`] frames. It is not an encoder and
//! it carries no picture: it exists so a real run drives PT112 end to end through the send
//! loop. Compiled only with the `itest-synthetic-video` feature; the public frame ABI is V3.

use super::packet::AccessUnit;
use std::time::Duration;

/// One frame interval at 30 fps.
pub const FRAME_INTERVAL: Duration = Duration::from_millis(33);
/// An IDR access unit every this many submitted frames.
pub const IDR_EVERY: u64 = 30;
const IDR_BYTES: usize = 12_000;
const P_BYTES: usize = 3_000;
const MICROS_PER_FRAME: u64 = 33_333;
const TRACK_REVISION: u32 = 1;
const CONFIG_REVISION: u32 = 1;
const FILL: u8 = 0x5a;

/// The synthetic access unit for submitted frame `index`. `idr` forces a keyframe.
#[must_use]
pub fn access_unit(index: u64, idr: bool) -> AccessUnit {
    let target = if idr { IDR_BYTES } else { P_BYTES };
    let mut data = Vec::with_capacity(target);
    if idr {
        push_nal(&mut data, 7, 15); // SPS
        push_nal(&mut data, 8, 4); // PPS
    }
    let slice = if idr { 5 } else { 1 };
    // The slice takes the rest of the frame: its 4-byte prefix and 1-byte header come out of it.
    let body = target.saturating_sub(data.len() + 5);
    push_nal(&mut data, slice, body);
    AccessUnit {
        frame_id: index,
        pts_us: index.saturating_mul(MICROS_PER_FRAME),
        idr,
        config: idr,
        rotation: 0,
        track_revision: TRACK_REVISION,
        config_revision: CONFIG_REVISION,
        data,
    }
}

fn push_nal(data: &mut Vec<u8>, nal_type: u8, body_len: usize) {
    let len = u32::try_from(body_len + 1).unwrap_or(u32::MAX);
    data.extend_from_slice(&len.to_be_bytes());
    data.push(0x60 | nal_type);
    data.resize(data.len() + body_len, FILL);
}
