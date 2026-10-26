// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-session push registration; delivery identity and expiry are assigned by the server.
use crate::{DeviceAuthKeyResponse, NodeCoreError, PushProviderKind};
use serde::{Deserialize, Serialize};
pub const PUSH_ROUTE_PATH: &str = "/notify/v1/push-route";
/// Notify mesh path that deletes a device's routes on explicit deregistration.
pub const PUSH_ROUTE_DELETE_PATH: &str = "/notify/v1/push-route/delete";
/// Router mesh path answering many current device-authority lookups in one request.
pub const DEVICE_AUTH_KEYS_PATH: &str = "/mvp1/device-auth-keys";
/// Maximum devices per batched authority lookup.
pub const DEVICE_AUTH_KEY_BATCH_LIMIT: usize = 256;
/// Sliding route lifetime: every authenticated (re)registration restarts it. Long enough that a
/// device left in the background keeps receiving wakes; revocation deletes routes earlier.
pub const PUSH_ROUTE_TTL_SECONDS: u64 = 30 * 86_400;
/// Clients re-register when less than this much route lifetime remains.
pub const PUSH_ROUTE_RENEW_BEFORE_SECONDS: u64 = 15 * 86_400;
/// Cross-host clock tolerance for a gateway-issued control.
pub const PUSH_ROUTE_CONTROL_SKEW_SECONDS: u64 = 5;
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
/// Explicit deregistration: removes the session device's route for one provider, or all.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteDeregistration {
    #[serde(default)]
    pub provider: Option<PushProviderKind>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteDeregistrationFrame {
    pub signed_request: ramflux_protocol::SignedRequest,
    pub body: PushRouteDeregistration,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteDeleteBody {
    pub authority: DeviceAuthKeyResponse,
    pub provider: Option<PushProviderKind>,
    pub issued_at: u64,
    /// The client's control sequence; raises the device's deregistration fence.
    #[serde(default)]
    pub client_seq: Option<u64>,
}
/// Gateway-signed deletion request; its signature domain differs from registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteDeleteControl {
    pub body: PushRouteDeleteBody,
    pub signature: String,
}
impl PushRouteDeleteControl {
    /// # Errors
    /// Rejects expired, future-dated or forged controls and malformed authority.
    pub fn verify(
        &self,
        key: &crate::NodeServiceSigningKey,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if self.body.issued_at > now.saturating_add(PUSH_ROUTE_CONTROL_SKEW_SECONDS)
            || now.saturating_sub(self.body.issued_at) > 30
        {
            return Err(NodeCoreError::Unauthorized("push route control expired".into()));
        }
        let bytes = ramflux_protocol::canonical_json_bytes(&self.body)
            .map_err(|error| NodeCoreError::ItestJson(error.to_string()))?;
        key.verify_push_route_delete(&bytes, &self.signature)?;
        self.body.authority.authenticated_device_identity().map(|_| ())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRouteControlBody {
    pub authority: DeviceAuthKeyResponse,
    pub registration: PushRouteRegistration,
    pub issued_at: u64,
    /// The client's control sequence; must be newer than the device's deregistration fence.
    #[serde(default)]
    pub client_seq: Option<u64>,
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
        if self.body.issued_at > now.saturating_add(PUSH_ROUTE_CONTROL_SKEW_SECONDS)
            || now.saturating_sub(self.body.issued_at) > 30
        {
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

/// Batched lookup of current device authority by root-qualified device id.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthKeyBatchRequest {
    pub devices: Vec<String>,
}
/// One entry per requested device, in request order; unknown or invalid selectors are `None`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthKeyBatchResponse {
    pub keys: Vec<Option<DeviceAuthKeyResponse>>,
}
/// Whether `current` (from the router) still authorizes the stored route owner.
#[must_use]
pub fn push_route_owner_is_current(
    owner: &DeviceAuthKeyResponse,
    current: Option<&DeviceAuthKeyResponse>,
) -> bool {
    let Ok(identity) = owner.authenticated_device_identity() else {
        return false;
    };
    // The router keeps revoked records (with `revoked: true` and unchanged keys) so that
    // revocation stays visible; a revoked device is never a current route owner.
    current.is_some_and(|current| {
        !current.revoked
            && current.authenticated_device_identity().is_ok_and(|source| source == identity)
            && current.branch_public_key == owner.branch_public_key
            && current.device_epoch == owner.device_epoch
            && current.target_delivery_id == owner.target_delivery_id
    })
}

/// Why push route control was refused; clients choose their retry policy from it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRouteRefusal {
    /// The node has no credential for the requested provider. Retry after a token or
    /// configuration change, or after a long interval.
    ProviderUnavailable,
    /// The request itself was refused (credential format, binding, authority).
    #[default]
    Rejected,
    /// Router or notify did not answer in time; retry with backoff.
    Unavailable,
    /// A newer control from the same session replaced this one before it ran, or a newer
    /// deregistration was already confirmed.
    Superseded,
    /// A code from a newer peer; treated as transient.
    #[serde(other)]
    Unknown,
}
/// Notify's answer to a registration control.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PushRouteRegisterAnswer {
    Registered { expires_at: u64 },
    Refused { code: PushRouteRefusal },
}
