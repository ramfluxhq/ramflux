// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live roster selection. Card devices are never passed in.

use super::codes::{
    CODE_LAYOUT_INVALID, CODE_PEER_UPGRADE, CODE_RECIPIENT_EMPTY, CODE_RECIPIENT_LIMIT, Refusal,
};
use super::meta::MAX_ENTRIES;

/// One device that can hold an entry. `own` marks another device of this account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MediaDevice {
    pub account_anchor: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub signing_public: [u8; 32],
    pub home_node_id: String,
    pub hpke_public: [u8; 32],
    pub layer: u32,
    pub own: bool,
}

/// Direct messages keep caption delivery for peers below layer 4.
/// A group with any member below layer 4 does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaScope {
    Dm,
    Group,
}

/// # Errors
/// Returns `recipient_empty`, `peer_upgrade_required`, `recipient_limit`, or `layout_invalid`.
pub(crate) fn choose_targets(
    scope: MediaScope,
    devices: &[MediaDevice],
) -> Result<Vec<MediaDevice>, Refusal> {
    if devices.is_empty() {
        return Err(Refusal::new(CODE_RECIPIENT_EMPTY));
    }
    let fresh: Vec<MediaDevice> =
        devices.iter().filter(|device| device.layer >= 4).cloned().collect();
    match scope {
        MediaScope::Dm => {
            if !fresh.iter().any(|device| !device.own) {
                return Err(Refusal::new(CODE_PEER_UPGRADE));
            }
        }
        MediaScope::Group => {
            if fresh.len() != devices.len() {
                return Err(Refusal::new(CODE_PEER_UPGRADE));
            }
        }
    }
    if fresh.len() > MAX_ENTRIES {
        return Err(Refusal::new(CODE_RECIPIENT_LIMIT));
    }
    require_distinct(&fresh)?;
    Ok(fresh)
}

/// # Errors
/// Returns `layout_invalid` when two entries share a `TargetKey`.
pub(crate) fn require_distinct(devices: &[MediaDevice]) -> Result<(), Refusal> {
    unique(devices)
}

fn unique(devices: &[MediaDevice]) -> Result<(), Refusal> {
    for (index, device) in devices.iter().enumerate() {
        let mut later = devices.iter().skip(index + 1);
        if later.any(|other| same_target(device, other)) {
            return Err(Refusal::new(CODE_LAYOUT_INVALID));
        }
    }
    Ok(())
}

fn same_target(left: &MediaDevice, right: &MediaDevice) -> bool {
    left.account_anchor == right.account_anchor
        && left.device_id == right.device_id
        && left.device_epoch == right.device_epoch
}
