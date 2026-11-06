// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned retention for content; transient controls keep separate deadlines.
use crate::{RamfluxClient, SdkError};
use serde::{Deserialize, Serialize};

pub const DEFAULT_OFFLINE_RETENTION_SECS: u32 = 604_800;
pub const MIN_OFFLINE_RETENTION_SECS: u32 = 3_600;
// Call state is useful only while the live call can still be negotiated.
pub(crate) const CALL_SIGNAL_TTL_SECS: u32 = 3_600;
// Receipts are best-effort hints; missing one does not discard message content.
pub(crate) const RECEIPT_TTL_SECS: u32 = 600;
// Direct receipt controls retain their original five-minute best-effort window.
pub(crate) const DIRECT_RECEIPT_TTL_SECS: u32 = 300;
// Pair resets authenticate a short-lived handshake, never retained chat content.
pub(crate) const RESET_TTL_SECS: u32 = 300;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    #[serde(default = "default_retention", deserialize_with = "decode_retention")]
    pub offline_retention_secs: u32,
}
const fn default_retention() -> u32 {
    DEFAULT_OFFLINE_RETENTION_SECS
}
impl Default for AccountConfig {
    fn default() -> Self {
        Self { offline_retention_secs: default_retention() }
    }
}
fn validate(value: u32) -> Result<(), SdkError> {
    if !(MIN_OFFLINE_RETENTION_SECS..=DEFAULT_OFFLINE_RETENTION_SECS).contains(&value) {
        return Err(SdkError::InvalidOfflineRetention(value));
    }
    Ok(())
}
fn decode_retention<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(decoder)?;
    validate(value).map_err(serde::de::Error::custom)?;
    Ok(value)
}
pub(crate) const fn content_ttl(config: &AccountConfig) -> u32 {
    config.offline_retention_secs
}
pub(crate) fn decode_config(value: serde_json::Value) -> Result<AccountConfig, SdkError> {
    if let Some(value) = value["offline_retention_secs"].as_u64()
        && let Ok(value) = u32::try_from(value)
    {
        validate(value)?;
    }
    Ok(serde_json::from_value(value)?)
}
impl RamfluxClient {
    /// Reads the unlocked account's configuration; older accounts use the default.
    /// # Errors
    /// Returns storage or invalid configuration errors.
    pub fn account_config(&self) -> Result<AccountConfig, SdkError> {
        let Some(value) = self.account_db()?.client_record("settings", "offline_retention")? else {
            return Ok(AccountConfig::default());
        };
        decode_config(value)
    }
    /// Returns the retention applied to newly sent content, in seconds.
    /// # Errors
    /// Returns storage or configuration errors.
    pub fn offline_retention_secs(&self) -> Result<u32, SdkError> {
        Ok(content_ttl(&self.account_config()?))
    }
    /// Persists the retention for newly sent content; existing envelopes are unchanged.
    /// # Errors
    /// Rejects values outside 3600..=604800 and returns storage errors.
    pub fn set_offline_retention_secs(&self, value: u32) -> Result<(), SdkError> {
        validate(value)?;
        self.account_db()?.persist_client_record(
            "settings",
            "offline_retention",
            &serde_json::to_value(AccountConfig { offline_retention_secs: value })?,
        )?;
        Ok(())
    }
    pub(crate) fn content_ttl(&self) -> Result<u32, SdkError> {
        Ok(content_ttl(&self.account_config()?))
    }
}

#[cfg(test)]
mod tests;
