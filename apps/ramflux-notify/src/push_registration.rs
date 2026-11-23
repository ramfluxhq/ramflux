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
    if ramflux_node_core::environment::var("RAMFLUX_ITEST_HTTP").ok().as_deref() == Some("1") {
        store.allow_itest_unbound_push_routes();
    }
    for credential in credentials()? {
        store.update_provider_credential(&credential)?;
    }
    Ok(())
}
fn credentials() -> Result<Vec<ramflux_node_core::ProviderCredential>, NodeCoreError> {
    // An empty value means "not configured", so compose files can pass the variable through.
    let Some(path) =
        ramflux_node_core::environment::var_os("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE")
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
    control.verify(&ingress.wake_auth.key, now)?;
    let configured = credentials()?;
    let route = match ramflux_node_core::admit_push_registration(
        &configured,
        &control.body.authority,
        &control.body.registration,
        now,
    ) {
        Ok(route) => route,
        Err(code) => return Ok(Answer::Refused { code }),
    };
    let expires_at = route.expires_at;
    match ingress.store.register_authenticated_push_route_at(
        &control.body.authority,
        &route,
        control.body.client_seq,
    ) {
        Ok(true) => Ok(Answer::Registered { expires_at }),
        // A newer deregistration, or a persisted registration sequence, already won.
        Ok(false) => Ok(Answer::Refused { code: PushRouteRefusal::Superseded }),
        Err(NodeCoreError::PushRouteOwnerMismatch) => {
            Ok(Answer::Refused { code: PushRouteRefusal::RejectedOwner })
        }
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
    control.verify(&ingress.wake_auth.key, now)?;
    let removed = ingress.store.delete_authenticated_push_routes_at(
        &control.body.authority,
        control.body.provider.as_ref(),
        control.body.client_seq,
    )?;
    Ok(u64::try_from(removed).unwrap_or(u64::MAX))
}
#[cfg(test)]
mod tests {
    #[test]
    fn provider_endpoints_are_node_owned_and_cannot_be_substituted()
    -> Result<(), Box<dyn std::error::Error>> {
        use ramflux_node_core::{
            FcmProviderCredential, ProviderCredential, PushProviderKind, PushRouteCapability,
            PushRouteEnvironment, PushRouteRegistration, WebPushProviderCredential,
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
            route_tag: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            environment: PushRouteEnvironment::Production,
            capability: PushRouteCapability::Alert,
            endpoint: None,
            webpush_auth: None,
            webpush_p256dh: None,
        };
        assert_eq!(
            ramflux_node_core::push_provider_endpoint(&credential, &registration)?,
            "https://fcm.googleapis.com:443/v1/projects/project-123/messages:send"
        );
        registration.endpoint = Some("https://127.0.0.1:443/internal".into());
        assert!(ramflux_node_core::push_provider_endpoint(&credential, &registration).is_err());
        let web = ProviderCredential::WebPush(WebPushProviderCredential {
            credential_id: "node-web".into(),
            vapid_public_key_ref: "file:/run/secrets/vapid.pub".into(),
            vapid_private_key_ref: "file:/run/secrets/vapid.key".into(),
            subject: "mailto:ops@example.test".into(),
            provider_ca_pem_ref: None,
        });
        registration.provider = PushProviderKind::WebPush;
        registration.capability = PushRouteCapability::Alert;
        assert!(ramflux_node_core::push_provider_endpoint(&web, &registration).is_err());
        Ok(())
    }
}
