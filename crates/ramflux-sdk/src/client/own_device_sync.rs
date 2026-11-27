// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

mod pairing;
pub(crate) use pairing::PairingHistoryProgress;
impl RamfluxClient {
    /// Own-device group snapshots are unavailable until the MLS group track.
    #[allow(clippy::unused_self)]
    pub(crate) fn own_device_group_snapshots(
        &self,
        _source_device_id: &str,
    ) -> Result<Vec<SdkOwnDeviceGroupSnapshot>, SdkError> {
        Ok(Vec::new())
    }
    /// Callers read `None` as "own-device group access unavailable" and refuse.
    #[allow(clippy::unused_self)]
    #[allow(dead_code, reason = "MLS: allowance removed in P1-g")]
    pub(crate) fn own_device_group_snapshot(
        &self,
        _id: &str,
        _source_device_id: &str,
    ) -> Result<Option<SdkOwnDeviceGroupSnapshot>, SdkError> {
        Ok(None)
    }
}
