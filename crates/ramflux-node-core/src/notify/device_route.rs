// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One stored provider route, admitted from the device's registration.
//!
//! The device chooses the provider, the APNs environment, the route tag and the
//! wake capability. The node chooses the credential and the provider host.

use super::{ProviderCredential, PushProviderKind};
use crate::{
    DeviceAuthKeyResponse, NodeCoreError, PUSH_ROUTE_TTL_SECONDS, PushRouteCapability,
    PushRouteEnvironment, PushRouteRefusal, PushRouteRegistration,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevicePushRoute {
    pub device_delivery_id: String,
    pub provider: PushProviderKind,
    #[serde(default)]
    pub credential_id: Option<String>,
    pub token: String,
    pub endpoint: String,
    #[serde(default)]
    pub webpush_p256dh: Option<String>,
    #[serde(default)]
    pub webpush_auth: Option<String>,
    pub registered_at_ms: u64,
    pub expires_at: u64,
    /// The route's `st` is a sealed central token (central mode). Raw tokens are never stored
    /// for central routes.
    #[serde(default)]
    pub sealed: bool,
    /// A `reseal` answer from the centre: the route is skipped until the device re-registers.
    #[serde(default)]
    pub needs_reseal: bool,
    /// An `unserved` answer pauses the route until this Unix ms time (3600 s).
    #[serde(default)]
    pub unserved_until_ms: u64,
    /// Server-allocated id. It is never reused. Zero was not admitted here.
    #[serde(default)]
    pub route_generation: u64,
    /// Canonical unpadded base64url of 16 bytes, chosen by the device, echoed in each wake.
    pub route_tag: String,
    pub environment: PushRouteEnvironment,
    pub capability: PushRouteCapability,
}

impl std::fmt::Debug for DevicePushRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePushRoute")
            .field("device_delivery_id", &self.device_delivery_id)
            .field("provider", &self.provider)
            .field("credential_id", &self.credential_id)
            .field("environment", &self.environment)
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at)
            .field("route_generation", &self.route_generation)
            .finish_non_exhaustive()
    }
}

impl DevicePushRoute {
    /// Capability that belongs on `provider`. `VoIP` is only the `PushKit` route.
    #[must_use]
    pub fn capability_for(provider: &PushProviderKind) -> PushRouteCapability {
        match provider {
            PushProviderKind::ApnsVoip => PushRouteCapability::Voip,
            PushProviderKind::Apns | PushProviderKind::Fcm | PushProviderKind::WebPush => {
                PushRouteCapability::Alert
            }
        }
    }
}

/// Unix time in milliseconds on this node's clock. Route registration and `invalid_route` times
/// are compared in this unit (A5).
#[must_use]
pub(crate) fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

fn rejected() -> NodeCoreError {
    NodeCoreError::Unauthorized("push route registration rejected".into())
}

fn environment_matches(credential: &ProviderCredential, environment: PushRouteEnvironment) -> bool {
    let sandbox = environment == PushRouteEnvironment::Sandbox;
    match credential {
        ProviderCredential::Apns(credential) => credential.sandbox == sandbox,
        ProviderCredential::Fcm(_) | ProviderCredential::WebPush(_) => !sandbox,
    }
}

/// Build the stored route from the registration and the node's credentials.
///
/// The caller still binds the route to current device authority. A missing
/// provider or environment is [`PushRouteRefusal::ProviderUnavailable`]. A
/// malformed credential is [`PushRouteRefusal::Rejected`].
///
/// # Errors
/// Returns a refusal. This function does not touch storage.
pub fn admit_push_registration(
    credentials: &[ProviderCredential],
    authority: &DeviceAuthKeyResponse,
    registration: &PushRouteRegistration,
    now: u64,
) -> Result<DevicePushRoute, PushRouteRefusal> {
    registration.validate().map_err(|_| PushRouteRefusal::Rejected)?;
    if registration.sealed {
        // Direct mode never accepts a sealed token (A2.4, no plaintext or sealed fallback).
        return Err(PushRouteRefusal::Rejected);
    }
    let credential = credentials
        .iter()
        .find(|credential| {
            credential.provider_kind() == registration.provider
                && environment_matches(credential, registration.environment)
        })
        .ok_or(PushRouteRefusal::ProviderUnavailable)?;
    let endpoint =
        push_provider_endpoint(credential, registration).map_err(|_| PushRouteRefusal::Rejected)?;
    Ok(DevicePushRoute {
        device_delivery_id: authority.target_delivery_id.clone(),
        provider: registration.provider.clone(),
        credential_id: Some(credential.credential_id().to_owned()),
        token: registration.token.clone(),
        endpoint,
        webpush_p256dh: registration.webpush_p256dh.clone(),
        webpush_auth: registration.webpush_auth.clone(),
        registered_at_ms: now_unix_millis(),
        sealed: false,
        needs_reseal: false,
        unserved_until_ms: 0,
        expires_at: now.saturating_add(PUSH_ROUTE_TTL_SECONDS),
        route_generation: 0,
        route_tag: registration.route_tag.clone(),
        environment: registration.environment,
        capability: registration.capability,
    })
}

/// Build the stored route for a sealed central registration (A2.3). The node stores the sealed
/// token `st` byte for byte, has no local provider credential, and uses the fixed endpoint
/// `rfc-push`; the provider host and credential are the centre's.
///
/// # Errors
/// Refuses a registration that is not sealed or fails validation.
pub fn admit_sealed_push_registration(
    authority: &DeviceAuthKeyResponse,
    registration: &PushRouteRegistration,
    now: u64,
) -> Result<DevicePushRoute, PushRouteRefusal> {
    registration.validate().map_err(|_| PushRouteRefusal::Rejected)?;
    if !registration.sealed {
        return Err(PushRouteRefusal::Rejected);
    }
    Ok(DevicePushRoute {
        device_delivery_id: authority.target_delivery_id.clone(),
        provider: registration.provider.clone(),
        credential_id: None,
        token: registration.token.clone(),
        endpoint: "rfc-push".to_owned(),
        webpush_p256dh: None,
        webpush_auth: None,
        registered_at_ms: now_unix_millis(),
        sealed: true,
        needs_reseal: false,
        unserved_until_ms: 0,
        expires_at: now.saturating_add(PUSH_ROUTE_TTL_SECONDS),
        route_generation: 0,
        route_tag: registration.route_tag.clone(),
        environment: registration.environment,
        capability: registration.capability,
    })
}

/// Provider URL for this credential. The client cannot supply an APNs or FCM host.
///
/// # Errors
/// Rejects a credential that does not serve the registration's environment, a
/// substituted endpoint, or a malformed APNs token.
pub fn push_provider_endpoint(
    credential: &ProviderCredential,
    registration: &PushRouteRegistration,
) -> Result<String, NodeCoreError> {
    if !environment_matches(credential, registration.environment) {
        return Err(rejected());
    }
    match credential {
        ProviderCredential::Apns(credential) => apns_endpoint(credential, registration),
        ProviderCredential::Fcm(credential) => fcm_endpoint(credential, registration),
        ProviderCredential::WebPush(_) => webpush_endpoint(registration),
    }
}

fn apns_endpoint(
    credential: &super::ApnsProviderCredential,
    registration: &PushRouteRegistration,
) -> Result<String, NodeCoreError> {
    if !registration.token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !(64..=400).contains(&registration.token.len())
        || !registration.token.len().is_multiple_of(2)
        || registration.endpoint.is_some()
    {
        return Err(rejected());
    }
    let host = if credential.sandbox { "api.sandbox.push.apple.com" } else { "api.push.apple.com" };
    Ok(format!("https://{host}:443/"))
}

fn fcm_endpoint(
    credential: &super::FcmProviderCredential,
    registration: &PushRouteRegistration,
) -> Result<String, NodeCoreError> {
    if registration.endpoint.is_some()
        || !credential.project_id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(rejected());
    }
    Ok(format!(
        "https://fcm.googleapis.com:443/v1/projects/{}/messages:send",
        credential.project_id
    ))
}

fn webpush_endpoint(registration: &PushRouteRegistration) -> Result<String, NodeCoreError> {
    let endpoint = registration.endpoint.as_ref().ok_or_else(rejected)?;
    let rest = endpoint.strip_prefix("https://").ok_or_else(rejected)?;
    let (authority, path) = rest.split_once('/').ok_or_else(rejected)?;
    if authority.is_empty()
        || !authority.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
        || path.contains('#')
        || registration.webpush_p256dh.as_ref().is_none_or(String::is_empty)
        || registration.webpush_auth.as_ref().is_none_or(String::is_empty)
    {
        return Err(rejected());
    }
    let allowed = crate::environment::var("RAMFLUX_NOTIFY_WEBPUSH_ORIGINS").unwrap_or_default();
    if !allowed.split(',').any(|origin| origin == format!("https://{authority}")) {
        return Err(rejected());
    }
    let authority =
        if authority.contains(':') { authority.to_owned() } else { format!("{authority}:443") };
    Ok(format!("https://{authority}/{path}"))
}
