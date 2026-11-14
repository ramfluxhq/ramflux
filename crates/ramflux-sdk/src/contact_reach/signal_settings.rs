// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private per-device optional-signal filters; phone-signed admission remains required.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::contact_reach::Permissions;

const KEY: &str = "reach/local-signal-settings";

impl RamfluxClient {
    /// Read this device's private filters for delivered/read receipts and typing.
    /// Accepted defaults apply; the separately verified admission controls each peer's permission.
    /// # Errors
    /// Returns locked-account, malformed local state or database errors.
    pub fn reach_signal_settings(&self) -> Result<Permissions, SdkError> {
        Ok(self.account_db()?.load_actor_state(KEY)?.unwrap_or(Permissions::ACCEPTED))
    }

    /// Set this device's private filters without modifying any signed admission or peer state.
    /// # Errors
    /// Returns locked-account, serialization or database errors.
    pub fn set_reach_signal_settings(&self, settings: Permissions) -> Result<(), SdkError> {
        Ok(self.account_db()?.persist_actor_state(KEY, &settings)?)
    }
}
