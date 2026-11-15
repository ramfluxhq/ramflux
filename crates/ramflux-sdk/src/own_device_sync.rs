// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceGroupSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) shared_state: Option<ramflux_protocol::group_state::GroupStateSnapshot>,
    pub(crate) group_id: String,
    pub(crate) group_epoch: u64,
    pub(crate) max_members: u32,
    pub(crate) new_member_history: String,
    pub(crate) local_role: String,
    pub(crate) local_joined_epoch: u64,
    pub(crate) members: Vec<SdkOwnDeviceGroupMemberSnapshot>,
    pub(crate) routes: Vec<LocalBusGroupMemberRoute>,
}

/// Existing pins attested by the authenticated same-root history source, never a distribution.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SdkOwnDeviceGroupMemberPin {
    pub(crate) group_id: String,
    pub(crate) device_id: String,
    pub(crate) signing_public_key: String,
    pub(crate) principal_id: Option<String>,
    pub(crate) principal_commitment: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SdkOwnDeviceGroupMemberSnapshot {
    pub(crate) member_id: String,
    pub(crate) role: String,
    pub(crate) joined_epoch: u64,
}
