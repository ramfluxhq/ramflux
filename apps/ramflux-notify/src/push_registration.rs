// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node-owned provider configuration and current device authority protect production routes.
use ramflux_node_core::{NodeCoreError, NotifyRedbStore};
fn rejected() -> NodeCoreError {
    NodeCoreError::Unauthorized("push route registration rejected".into())
}
pub(crate) fn configure(
    store: &mut NotifyRedbStore,
    config: &ramflux_node_core::NodeServiceConfig,
) -> Result<(), NodeCoreError> {
    let endpoint = config.mesh.endpoints.get("router").cloned().ok_or_else(rejected)?;
    let tls = super::notify_mesh_tls_config(config);
    let client = ramflux_transport::MeshHttpClient::new();
    // Batched so the revocation sweep makes one router request per 256 owners.
    store.set_push_route_batch_authorizer(move |owners| {
        let mut verdicts = Vec::with_capacity(owners.len());
        for batch in owners.chunks(ramflux_node_core::DEVICE_AUTH_KEY_BATCH_LIMIT) {
            let devices = batch
                .iter()
                .map(|owner| {
                    let identity = owner.authenticated_device_identity()?;
                    ramflux_protocol::qualified_device_id(
                        identity.root_commitment(),
                        identity.device_id(),
                    )
                    .map_err(|_| rejected())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let response: ramflux_node_core::DeviceAuthKeyBatchResponse = client
                .post_json(
                    &endpoint,
                    ramflux_node_core::DEVICE_AUTH_KEYS_PATH,
                    &tls,
                    "ramflux-router",
                    &ramflux_node_core::DeviceAuthKeyBatchRequest { devices },
                )
                .map_err(|_| {
                    NodeCoreError::ItestHttp("push authority lookup unavailable".into())
                })?;
            if response.keys.len() != batch.len() {
                return Err(NodeCoreError::ItestHttp("push authority lookup mismatched".into()));
            }
            verdicts.extend(batch.iter().zip(&response.keys).map(|(owner, current)| {
                ramflux_node_core::push_route_owner_is_current(owner, current.as_ref())
            }));
        }
        Ok(verdicts)
    });
    #[cfg(feature = "itest-http")]
    if std::env::var("RAMFLUX_ITEST_HTTP").ok().as_deref() == Some("1") {
        store.allow_itest_unbound_push_routes();
    }
    for credential in credentials()? {
        store.update_provider_credential(credential)?;
    }
    Ok(())
}
fn credentials() -> Result<Vec<ramflux_node_core::ProviderCredential>, NodeCoreError> {
    // An empty value means "not configured", so compose files can pass the variable through.
    let Some(path) = std::env::var_os("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE")
        .filter(|path| !path.is_empty())
    else {
        return Ok(Vec::new());
    };
    let bytes = std::fs::read(path).map_err(|_| rejected())?;
    if bytes.len() > 65_536 {
        return Err(rejected());
    }
    serde_json::from_slice(&bytes).map_err(|_| rejected())
}
/// Configuration and request refusals are answered as typed refusals; only transient failures
/// (authority lookup, storage) surface as errors.
pub(crate) fn register(
    ingress: &super::NotifyIngressState,
    value: serde_json::Value,
) -> Result<ramflux_node_core::PushRouteRegisterAnswer, NodeCoreError> {
    use ramflux_node_core::{PushRouteRefusal, PushRouteRegisterAnswer as Answer};
    let control: ramflux_node_core::PushRouteControl =
        serde_json::from_value(value).map_err(|_| rejected())?;
    let now = ramflux_node_core::now_unix_seconds();
    control.verify(ingress.wake_auth.key.as_ref().ok_or_else(rejected)?, now)?;
    let registration = &control.body.registration;
    let configured = credentials()?;
    let Some(credential) =
        configured.iter().find(|credential| credential.provider_kind() == registration.provider)
    else {
        return Ok(Answer::Refused { code: PushRouteRefusal::ProviderUnavailable });
    };
    let Ok(endpoint) = endpoint(credential, registration) else {
        return Ok(Answer::Refused { code: PushRouteRefusal::Rejected });
    };
    // Lifetimes start from this node's clock, so a skewed gateway cannot shorten or extend them.
    let registered_at = now;
    let expires_at = now.saturating_add(ramflux_node_core::PUSH_ROUTE_TTL_SECONDS);
    let stored = ingress.store.register_authenticated_push_route(
        &control.body.authority,
        &ramflux_node_core::DevicePushRoute {
            device_delivery_id: control.body.authority.target_delivery_id.clone(),
            provider: registration.provider.clone(),
            credential_id: Some(credential.credential_id().into()),
            token: registration.token.clone(),
            endpoint,
            webpush_p256dh: registration.webpush_p256dh.clone(),
            webpush_auth: registration.webpush_auth.clone(),
            registered_at,
            expires_at,
        },
    );
    match stored {
        Ok(()) => Ok(Answer::Registered { expires_at }),
        Err(NodeCoreError::Unauthorized(_)) => {
            Ok(Answer::Refused { code: PushRouteRefusal::Rejected })
        }
        Err(error) => Err(error),
    }
}
/// Explicit deregistration from the device's own authenticated session.
pub(crate) fn deregister(
    ingress: &super::NotifyIngressState,
    value: serde_json::Value,
) -> Result<u64, NodeCoreError> {
    let control: ramflux_node_core::PushRouteDeleteControl =
        serde_json::from_value(value).map_err(|_| rejected())?;
    let now = ramflux_node_core::now_unix_seconds();
    control.verify(ingress.wake_auth.key.as_ref().ok_or_else(rejected)?, now)?;
    let removed = ingress.store.delete_authenticated_push_routes(
        &control.body.authority,
        control.body.provider.as_ref(),
    )?;
    Ok(u64::try_from(removed).unwrap_or(u64::MAX))
}
fn endpoint(
    credential: &ramflux_node_core::ProviderCredential,
    registration: &ramflux_node_core::PushRouteRegistration,
) -> Result<String, NodeCoreError> {
    use ramflux_node_core::ProviderCredential;
    match credential {
        ProviderCredential::Apns(credential) => {
            // Apple does not promise a fixed token length: accept bounded even-length hex.
            if !registration.token.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !(64..=400).contains(&registration.token.len())
                || !registration.token.len().is_multiple_of(2)
                || registration.endpoint.is_some()
            {
                return Err(rejected());
            }
            Ok(format!(
                "https://{}:443/",
                if credential.sandbox {
                    "api.sandbox.push.apple.com"
                } else {
                    "api.push.apple.com"
                }
            ))
        }
        ProviderCredential::Fcm(credential) => {
            if registration.endpoint.is_some()
                || !credential
                    .project_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(rejected());
            }
            Ok(format!(
                "https://fcm.googleapis.com:443/v1/projects/{}/messages:send",
                credential.project_id
            ))
        }
        ProviderCredential::WebPush(_) => webpush_endpoint(registration),
    }
}
fn webpush_endpoint(
    registration: &ramflux_node_core::PushRouteRegistration,
) -> Result<String, NodeCoreError> {
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
    let allowed = std::env::var("RAMFLUX_NOTIFY_WEBPUSH_ORIGINS").unwrap_or_default();
    if !allowed.split(',').any(|origin| origin == format!("https://{authority}")) {
        return Err(rejected());
    }
    let authority =
        if authority.contains(':') { authority.to_owned() } else { format!("{authority}:443") };
    Ok(format!("https://{authority}/{path}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_endpoints_are_node_owned_and_cannot_be_substituted()
    -> Result<(), Box<dyn std::error::Error>> {
        use ramflux_node_core::{
            FcmProviderCredential, ProviderCredential, PushProviderKind, PushRouteRegistration,
        };
        let credential = ProviderCredential::Fcm(FcmProviderCredential {
            credential_id: "node-fcm".into(),
            project_id: "project-123".into(),
            service_account_json_ref: "file:/run/secrets/google.json".into(),
            oauth_scope: "scope".into(),
            oauth_token_url: None,
            provider_ca_pem_ref: None,
        });
        let mut registration = PushRouteRegistration {
            provider: PushProviderKind::Fcm,
            token: "token".into(),
            endpoint: None,
            webpush_auth: None,
            webpush_p256dh: None,
        };
        assert_eq!(
            super::endpoint(&credential, &registration)?,
            "https://fcm.googleapis.com:443/v1/projects/project-123/messages:send"
        );
        registration.endpoint = Some("https://127.0.0.1:443/internal".into());
        assert!(super::endpoint(&credential, &registration).is_err());
        registration.provider = PushProviderKind::WebPush;
        assert!(super::webpush_endpoint(&registration).is_err());
        Ok(())
    }
}
