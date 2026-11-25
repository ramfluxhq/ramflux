// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed request, result and token schemas of the public `call.media.*` methods (C0 contract).
//! Decimal-string u64 fields, closed route/AEC/permission enums and the whole `M` row live here.
//! Nothing in this module grants authority: the account writer and engine decide every gate.

use crate::SdkError;
use crate::client::call::media_owner::InProcessMediaStatus;
use ramflux_media::authorization::GateReason;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

/// Negotiated PCM shape: signed native-endian 16-bit mono, 48 kHz, 20 ms blocks.
pub(crate) const PCM_FRAME_SAMPLES: usize = 960;

static NEXT_MEDIA_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Opaque nonzero process-lifetime token. It is never reused; exhausting the space refuses
/// admission instead of wrapping.
pub(crate) fn issue_media_token() -> Result<u64, SdkError> {
    NEXT_MEDIA_TOKEN
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
        .map_err(|_| SdkError::LocalBus("voice call: media token space exhausted".into()))
}

/// Parse a decimal string holding an unsigned 64-bit integer. JSON numbers are refused.
pub(crate) fn decimal<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(de::Error::custom("decimal u64 string required"));
    }
    text.parse::<u64>().map_err(|_| de::Error::custom("decimal u64 out of range"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenBody {
    pub call_id: String,
    #[serde(deserialize_with = "decimal")]
    pub expected_seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenBody {
    #[serde(deserialize_with = "decimal")]
    pub media_token: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutedBody {
    #[serde(deserialize_with = "decimal")]
    pub media_token: u64,
    #[serde(deserialize_with = "decimal")]
    pub io_generation: u64,
    pub muted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveBody {
    #[serde(deserialize_with = "decimal")]
    pub media_token: u64,
    #[serde(deserialize_with = "decimal")]
    pub io_generation: u64,
    pub active: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteBody {
    #[serde(deserialize_with = "decimal")]
    pub media_token: u64,
    #[serde(deserialize_with = "decimal")]
    pub io_generation: u64,
    #[serde(deserialize_with = "decimal")]
    pub route_generation: u64,
    pub route: Route,
    pub aec: Aec,
    pub microphone_permission: Permission,
}

/// Applied OS route. The SDK reports it and never selects hardware.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Route {
    #[default]
    Unavailable,
    Receiver,
    Speaker,
    Wired,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Aec {
    #[default]
    Unavailable,
    Enabled,
    Bypassed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Permission {
    #[default]
    Unknown,
    Granted,
    Denied,
}

/// Host-reported audio state kept beside the engine. Reports never open an SDK gate.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HostAudio {
    pub route_generation: u64,
    pub route: Route,
    pub aec: Aec,
    pub permission: Permission,
    pub muted: bool,
    pub status_revision: u64,
    /// PCM bridge counters, filled by the callback rings (checkpoint 2); zero until then.
    pub captured_frames: u64,
    pub capture_drops: u64,
    pub render_underruns: u64,
}

fn gate_name(reason: GateReason) -> &'static str {
    match reason {
        GateReason::AudioInactive => "audio_inactive",
        GateReason::CallNotActive => "call_not_active",
        GateReason::GatewayHold => "gateway_hold",
        GateReason::LeaseUnavailable => "lease_unavailable",
        GateReason::Locked => "locked",
        GateReason::Terminal => "terminal",
        GateReason::ResyncRequired => "resync_required",
    }
}

/// Public `gate_reason`: the engine's authority reason first, then host-side refusals.
fn public_gate(status: &InProcessMediaStatus, host: HostAudio) -> Value {
    if let Some(reason) = status.gate.reason {
        return json!(gate_name(reason));
    }
    if host.permission == Permission::Denied {
        return json!("permission_denied");
    }
    if host.route == Route::Unavailable {
        return json!("route_unavailable");
    }
    Value::Null
}

/// The public `phase` of a session.
fn phase(status: &InProcessMediaStatus) -> &'static str {
    match (status.gate.retired, status.drained) {
        (true, true) => "closed",
        (true, false) => "failed",
        (false, _) => "ready",
    }
}

fn counter(value: u64) -> Value {
    json!(value.to_string())
}

/// Whole `M` row returned by every `call.media.*` control and by `call.media.changed`.
pub(crate) fn media_view(
    status: &InProcessMediaStatus,
    media_token: u64,
    call_seq: u64,
    host: HostAudio,
) -> Value {
    let authorized = matches!(status.gate.reason, None | Some(GateReason::AudioInactive));
    let stats = &status.stats;
    json!({
        "call_id": status.receipt.call_id,
        "call_seq": counter(call_seq),
        "media_token": counter(media_token),
        "io_generation": counter(status.gate.generation),
        "status_revision": counter(host.status_revision),
        "phase": phase(status),
        "authorized": authorized,
        "gate_reason": public_gate(status, host),
        "audio_active": status.gate.audio_active,
        "muted": host.muted,
        "route_generation": counter(host.route_generation),
        "route": host.route,
        "aec": host.aec,
        "microphone_permission": host.permission,
        "pcm": {
            "sample_format": "s16_native",
            "sample_rate_hz": 48000,
            "channels": 1,
            "frame_samples": PCM_FRAME_SAMPLES,
        },
        "stats": {
            "captured_frames": counter(host.captured_frames),
            "sent_packets": counter(stats.sent),
            "authenticated_frames": counter(stats.authenticated),
            "decoded_frames": counter(stats.played),
            "concealed_frames": counter(stats.concealed),
            "capture_drops": counter(host.capture_drops),
            "render_underruns": counter(host.render_underruns),
            "send_errors": counter(stats.send_errors),
            "rebinds": counter(stats.rebinds_answered),
            "since_last_packet_ms": stats.since_last_packet_ms.map(counter),
        },
    })
}
