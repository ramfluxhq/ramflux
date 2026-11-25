// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host PCM callbacks of the in-process voice bridge (C0 lines 35-48).
//! Both entry points validate the buffer, then call `client::call::pcm_bridge`. They allocate
//! nothing, take no lock, register no lookup, log nothing, do no I/O and never wait.

use crate::client::call::media_contract::PCM_FRAME_SAMPLES;
use crate::client::call::pcm_bridge::{PcmError, bind_client, capture_frame, render_frame};

/// Negotiation 2.1 `voice_media` capability. Absent from a 2.0 negotiation means unavailable.
pub(super) fn voice_media_capability() -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "ownership": "in_process",
        "pcm": {
            "sample_format": "s16_native",
            "sample_rate_hz": 48000,
            "channels": 1,
            "frame_samples": PCM_FRAME_SAMPLES,
        },
        "max_sessions": 1,
    })
}

/// Bind the PCM callbacks to the client that completed a `call.media.open` successfully. The
/// host learns the token only from this completion, so no callback can precede the binding.
pub(super) fn bind_open(handle: u64, completion: &[u8]) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(completion) else { return };
    if value.get("code").and_then(serde_json::Value::as_i64) != Some(0) {
        return;
    }
    let token = value
        .pointer("/response/media_token")
        .and_then(serde_json::Value::as_str)
        .and_then(|text| text.parse::<u64>().ok());
    if let Some(token) = token {
        bind_client(token, handle);
    }
}

/// Lend `samples` host PCM values for the duration of one call. Null, misaligned or wrong-size
/// buffers are refused before any pointer is turned into a slice.
fn lend<'a>(pcm: *const i16, samples: usize) -> Option<&'a [i16]> {
    if pcm.is_null()
        || samples != PCM_FRAME_SAMPLES
        || !(pcm as usize).is_multiple_of(align_of::<i16>())
    {
        return None;
    }
    // SAFETY: the host lends `samples` readable, aligned i16 values until this call returns;
    // the slice is used only inside this call and is never retained.
    Some(unsafe { std::slice::from_raw_parts(pcm, samples) })
}

/// Same contract as [`lend`], writable.
fn lend_mut<'a>(pcm: *mut i16, samples: usize) -> Option<&'a mut [i16]> {
    if pcm.is_null()
        || samples != PCM_FRAME_SAMPLES
        || !(pcm as usize).is_multiple_of(align_of::<i16>())
    {
        return None;
    }
    // SAFETY: the host lends `samples` writable, aligned i16 values until this call returns;
    // the slice is used only inside this call and is never retained.
    Some(unsafe { std::slice::from_raw_parts_mut(pcm, samples) })
}

/// Capture one 20 ms frame of host PCM. Input is never altered.
/// Callback touches: slot atomics, capture ring atomics and counters. No allocation, lock,
/// registry, log, I/O, codec or wait.
/// Returns 0, or 1 (shape/token/generation), 12 (closed gate), 15 (capture ring full), 26 (closed).
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_media_capture(
    client: u64,
    media_token: u64,
    io_generation: u64,
    pcm: *const i16,
    samples: usize,
) -> i32 {
    let Some(frame) = lend(pcm, samples) else {
        return PcmError::InvalidArgument as i32;
    };
    match capture_frame(client, media_token, io_generation, frame) {
        Ok(()) => 0,
        Err(error) => error as i32,
    }
}

/// Render one 20 ms frame into host memory. Underrun is zero-filled success (0).
/// Callback touches: slot atomics, render ring atomics and counters, and the lent buffer only.
/// No allocation, lock, registry, log, I/O, codec or wait. Every failure with a valid buffer
/// zero-fills it; an invalid buffer is left untouched.
#[unsafe(no_mangle)]
#[must_use]
pub extern "C" fn ramflux_v2_media_render(
    client: u64,
    media_token: u64,
    io_generation: u64,
    pcm: *mut i16,
    samples: usize,
) -> i32 {
    let Some(out) = lend_mut(pcm, samples) else {
        return PcmError::InvalidArgument as i32;
    };
    match render_frame(client, media_token, io_generation, out) {
        Ok(()) => 0,
        Err(error) => error as i32,
    }
}
