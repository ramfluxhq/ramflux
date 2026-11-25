// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-side push policy (CENTRAL P2b, K9-K12): device class, mute, hold, clear and
//! hourly stats. Pure types and rules; the redb state lives in `policy_store`.

use serde::{Deserialize, Serialize};

/// `n_s` of the centre's version-0 policy (seconds a peer counts as active).
pub const POLICY_DEFAULT_N_S: u64 = 120;
/// `t_s` of the centre's version-0 policy (seconds a message wake is held).
pub const POLICY_DEFAULT_T_S: u64 = 10;
pub const POLICY_N_S_MIN: u64 = 60;
pub const POLICY_N_S_MAX: u64 = 900;
pub const POLICY_T_S_MAX: u64 = 60;
/// Lifetime of an internal clear (wire class `x`), seconds.
pub const POLICY_CLEAR_TTL_S: u64 = 3_600;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Phone,
    Tablet,
    Desktop,
    Terminal,
}

/// Push policy as set by the centre (`dir.policy`). `version` 0 means "none received yet".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PushPolicy {
    pub version: u64,
    pub n_s: u64,
    pub t_s: u64,
}

impl PushPolicy {
    /// Before the first `ok` reply of a process the node holds nothing (`t_s` 0) and sends
    /// `policy_version` 0. Not persisted: re-learned on the first reply.
    #[must_use]
    pub const fn before_first_reply() -> Self {
        Self { version: 0, n_s: POLICY_DEFAULT_N_S, t_s: 0 }
    }

    /// True when `n_s` and `t_s` are inside the bounds of NN-PUSH 11.4.
    #[must_use]
    pub const fn in_bounds(&self) -> bool {
        self.n_s >= POLICY_N_S_MIN
            && self.n_s <= POLICY_N_S_MAX
            && self.t_s <= POLICY_T_S_MAX
    }
}

/// Device policy record kept at the home node. Never sent to the centre (NN-PUSH 11.2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DevicePolicyRecord {
    pub account_group: String,
    pub device_class: DeviceClass,
    pub muted: bool,
    pub updated_ms: u64,
}

/// One UTC hour of policy counters. `from_ms`/`to_ms` bound the hour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyStatsHour {
    pub from_ms: u64,
    pub to_ms: u64,
    pub held_sent: u64,
    pub held_dropped: u64,
    pub muted: u64,
    pub clears_conn: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldDecision {
    SendNow,
    Hold { not_before_ms: u64 },
    Muted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldState {
    /// Held until `not_before_ms`; sent then, or dropped by a clear.
    Held,
    /// Released after the hold and handed to the normal send path.
    Sent,
    /// Removed by a clear from another device of the account.
    Dropped,
    /// Dropped because the target device is muted.
    Muted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyHoldRow {
    pub device_delivery_id: String,
    pub account_group: String,
    pub state: HoldState,
    pub not_before_ms: u64,
    pub expires_at_s: u64,
}

/// Pure decision for one offline wake (frozen K9-K12, overnight plan section 2). `target` is
/// the policy record of the device the wake is for; `peer_active` is true when another device
/// of the same account was active within `n_s`. Calls are never held and never muted: calls
/// ring every device. Mute withholds only message wakes (`m`) and clears (`x`).
#[must_use]
pub fn decide_wake(
    target: Option<&DevicePolicyRecord>,
    is_call: bool,
    peer_active: bool,
    policy: PushPolicy,
    now_ms: u64,
) -> HoldDecision {
    if is_call {
        return HoldDecision::SendNow;
    }
    let Some(record) = target else {
        return HoldDecision::SendNow;
    };
    if record.muted {
        return HoldDecision::Muted;
    }
    if peer_active && policy.t_s > 0 {
        return HoldDecision::Hold { not_before_ms: now_ms.saturating_add(policy.t_s * 1_000) };
    }
    HoldDecision::SendNow
}

/// Start of the UTC hour that contains `now_ms`.
#[must_use]
pub const fn utc_hour_start_ms(now_ms: u64) -> u64 {
    now_ms - now_ms % 3_600_000
}

/// Wire class of a wake, for the call rule.
#[must_use]
pub const fn is_call_class(class: &ramflux_protocol::NotificationDeliveryClass) -> bool {
    matches!(
        class,
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
            | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification
    )
}
