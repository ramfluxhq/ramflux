// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Config that is complete enough to sign an envelope.
//!
//! The field is private. There is no `From<GatewaySessionConfig>` and no public
//! constructor. An account mints it through [`SealingConfig::from_account`]
//! (what [`crate::bus::state::LocalBusAccountState::sealing_config`] calls).
//! Session metadata and the live session mint it through the session paths,
//! which refuse a missing device branch or source identity and do not refill
//! from the account.

use crate::SdkError;
use crate::bus::connection_manager::SessionMetadata;
use crate::bus::state::LocalBusAccountState;
use crate::gateway::protocol::GatewaySessionConfig;

/// Signing context for an outbound envelope.
///
/// Couriers obtain this from the account. A connected session obtains it from
/// session metadata or from the live session that metadata publishes.
#[derive(Clone)]
#[must_use]
pub(crate) struct SealingConfig {
    config: GatewaySessionConfig,
}

impl SealingConfig {
    /// The gateway coordinates and the branch this value was minted with.
    #[must_use]
    pub(crate) fn config(&self) -> &GatewaySessionConfig {
        &self.config
    }

    /// Account path. Fills a missing branch and source identity from the
    /// client, then refuses a config that is still incomplete.
    ///
    /// # Errors
    /// The account has no owned device identity, or the branch is still missing
    /// after the refill.
    pub(crate) fn from_account(account: &LocalBusAccountState) -> Result<Self, SdkError> {
        let mut config = account.gateway_config.clone();
        if config.device_branch.is_none() {
            config.device_branch = account.client.device_branch.clone().map(std::sync::Arc::new);
        }
        if config.source_identity.is_none() {
            config.source_identity = Some(account.client.owned_device_identity()?);
        }
        Self::require(config)
    }

    /// Authenticated session metadata. Does not refill from the account.
    ///
    /// # Errors
    /// The published session config has no device branch or no source identity.
    pub(crate) fn from_session(metadata: &SessionMetadata) -> Result<Self, SdkError> {
        Self::require(metadata.config.clone())
    }

    /// Live session config, the value session metadata stores after authentication.
    /// Mints through [`SessionMetadata::sealing_config`]. Does not refill from the
    /// account. `GatewaySessionAccess::sealing_config` is the caller; a stored
    /// account config must use [`Self::from_account`].
    ///
    /// # Errors
    /// The session config has no device branch or no source identity.
    pub(crate) fn from_live_session(config: &GatewaySessionConfig) -> Result<Self, SdkError> {
        SessionMetadata::for_sealing(config.clone()).sealing_config()
    }

    fn require(config: GatewaySessionConfig) -> Result<Self, SdkError> {
        if config.device_branch.is_none() || config.source_identity.is_none() {
            return Err(SdkError::GatewaySessionRejected("sealing config incomplete".into()));
        }
        Ok(Self { config })
    }
}

impl std::ops::Deref for SealingConfig {
    type Target = GatewaySessionConfig;

    fn deref(&self) -> &GatewaySessionConfig {
        &self.config
    }
}
