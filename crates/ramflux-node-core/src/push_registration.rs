// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-session push registration; delivery identity and expiry are assigned by the server.
use crate::{DeviceAuthKeyResponse, NodeCoreError, PushProviderKind};
use serde::{Deserialize, Serialize};
pub const PUSH_ROUTE_PATH: &str = "/notify/v1/push-route";
pub const PUSH_ROUTE_TTL_SECONDS: u64 = 86_400;
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteRegistration {
    pub provider: PushProviderKind,
    pub token: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub webpush_p256dh: Option<String>,
    #[serde(default)]
    pub webpush_auth: Option<String>,
}
impl std::fmt::Debug for PushRouteRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRouteRegistration")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteRegistrationFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: PushRouteRegistration,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteControlBody {
    pub authority: DeviceAuthKeyResponse,
    pub registration: PushRouteRegistration,
    pub issued_at: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteControl {
    pub body: PushRouteControlBody,
    pub signature: String,
}
impl PushRouteControl {
    /// # Errors
    /// Rejects expired, future-dated, forged or non-current device authority.
    pub fn verify(
        &self,
        key: &crate::NodeServiceSigningKey,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if self.body.issued_at > now || now.saturating_sub(self.body.issued_at) > 30 {
            return Err(NodeCoreError::Unauthorized("push route control expired".into()));
        }
        let bytes = ramflux_protocol::canonical_json_bytes(&self.body)
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        key.verify_push_route_control(&bytes, &self.signature)?;
        self.body.authority.authenticated_device_identity()?;
        self.body.registration.validate()
    }
}
impl PushRouteRegistration {
    /// # Errors
    /// Rejects oversized or malformed credentials before provider or storage access.
    pub fn validate(&self) -> Result<(), NodeCoreError> {
        let token_valid = !self.token.is_empty()
            && self.token.len() <= 4096
            && !self.token.chars().any(char::is_control);
        let keys_valid =
            [&self.webpush_auth, &self.webpush_p256dh, &self.endpoint].into_iter().all(|value| {
                value
                    .as_ref()
                    .is_none_or(|value| value.len() <= 4096 && !value.chars().any(char::is_control))
            });
        if !token_valid || !keys_valid {
            return Err(NodeCoreError::Unauthorized("push route credential rejected".into()));
        }
        Ok(())
    }
}
