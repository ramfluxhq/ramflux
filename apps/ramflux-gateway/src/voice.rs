// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Voice leases require current caller registration and a signed request on the live session.
use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};
use ramflux_protocol::{
    VoiceAllocation, VoiceCallFailureReason, VoiceLeaseFrame, VoiceLeaseRequest,
    VoiceLeaseResponse, VoiceLeaseStatus,
};
#[derive(Debug)]
struct VoiceIssueError {
    reason: VoiceCallFailureReason,
    source: anyhow::Error,
}
impl std::fmt::Display for VoiceIssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}
impl std::error::Error for VoiceIssueError {}
fn refused(reason: VoiceCallFailureReason, source: impl Into<anyhow::Error>) -> VoiceIssueError {
    VoiceIssueError { reason, source: source.into() }
}
pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &VoiceLeaseFrame,
) -> anyhow::Result<()> {
    let result = issue(context, runtime, request).await;
    let response = match result {
        Ok(response) => {
            ramflux_node_core::GatewayServerFrame::VoiceLease { response: Box::new(response) }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                failure_reason = ?error.reason,
                principal_id = %runtime.principal_id,
                device_id = %runtime.device_id,
                "voice lease rejected"
            );
            ramflux_node_core::GatewayServerFrame::VoiceLease {
                response: Box::new(VoiceLeaseResponse::Refused { reason: error.reason }),
            }
        }
    };
    let mut send = send.lock().await;
    ramflux_transport::write_gateway_session_json(&mut **send, &response).await?;
    Ok(())
}
async fn issue(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &VoiceLeaseFrame,
) -> Result<VoiceLeaseResponse, VoiceIssueError> {
    crate::session::validate_gateway_session_signed_request(
        context,
        runtime,
        &request.signed_request,
        "POST",
        "/voice/v1/lease",
        &request.body,
    )
    .map_err(|error| refused(VoiceCallFailureReason::AuthorityRefused, error))?;
    let scope = scope(&request.body);
    ramflux_node_core::validate_voice_scope(scope)
        .map_err(|error| refused(VoiceCallFailureReason::AuthorityRefused, error))?;
    let caller = manifest(context, runtime, &scope.caller.principal_id)
        .await
        .map_err(|error| refused(VoiceCallFailureReason::AuthorityUnavailable, error))?;
    let recipient = manifest(context, runtime, &scope.callee.principal_id)
        .await
        .map_err(|error| refused(VoiceCallFailureReason::AuthorityUnavailable, error))?;
    validate_authority(
        &request.body,
        runtime,
        &caller,
        &recipient,
        ramflux_node_core::now_unix_seconds(),
    )
    .map_err(|error| refused(VoiceCallFailureReason::AuthorityRefused, error))?;
    let endpoint = ramflux_node_core::environment::var("RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT")
        .map_err(|error| refused(VoiceCallFailureReason::RelayUnavailable, error))?;
    let tls = context.peers.tls().clone();
    let body = request.body.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<VoiceLeaseResponse> {
        let client = ramflux_transport::MeshHttpClient::new();
        if matches!(&body, VoiceLeaseRequest::Allocate { .. } | VoiceLeaseRequest::Accept { .. }) {
            let allocation: VoiceAllocation =
                client.post_json(&endpoint, "/voice/v1/lease", &tls, "ramflux-relay", &body)?;
            Ok(VoiceLeaseResponse::Allocation { allocation })
        } else {
            let status: VoiceLeaseStatus =
                client.post_json(&endpoint, "/voice/v1/lease", &tls, "ramflux-relay", &body)?;
            Ok(VoiceLeaseResponse::Status { status })
        }
    })
    .await
    .map_err(|error| refused(VoiceCallFailureReason::RelayUnavailable, error))?
    .map_err(|error| refused(VoiceCallFailureReason::RelayUnavailable, error))
}

fn scope(request: &VoiceLeaseRequest) -> &ramflux_protocol::VoiceAllocationRequest {
    match request {
        VoiceLeaseRequest::Allocate { scope } | VoiceLeaseRequest::Release { scope } => scope,
        VoiceLeaseRequest::Accept { consent } | VoiceLeaseRequest::Renew { consent } => {
            &consent.scope
        }
    }
}
async fn manifest(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    principal: &str,
) -> anyhow::Result<ramflux_node_core::DeviceManifestResponse> {
    let lookup = ramflux_node_core::PrincipalLookupRequest {
        principal_id: principal.into(),
        session_id: runtime.session_id.clone(),
        requester_device_id: runtime.device_id.clone(),
        target_delivery_id: runtime.target_delivery_id.clone(),
        gateway_id: context.gateway_id.clone(),
        source: context.remote_addr.ip(),
    };
    let response: ramflux_protocol::PrincipalLookupResponse<
        ramflux_node_core::DeviceManifestResponse,
    > = crate::router_post_json_async(&context.router, "/mvp1/principal-lookup", &lookup).await?;
    response.manifest.ok_or_else(|| anyhow::anyhow!("voice endpoint authority unavailable"))
}
struct VoiceDeviceAuthority {
    branch_public_key: String,
    device_epoch: u64,
}
fn branch(
    endpoint: &ramflux_protocol::CallEndpoint,
    manifest: &ramflux_node_core::DeviceManifestResponse,
    now: u64,
) -> anyhow::Result<VoiceDeviceAuthority> {
    anyhow::ensure!(
        manifest.principal_id == endpoint.principal_id
            && manifest.root_public_key == endpoint.root_public_key,
        "voice endpoint root changed"
    );
    if let Some(custody) = &manifest.custody {
        anyhow::ensure!(
            manifest.signed_device_set.is_none() && manifest.devices.is_empty(),
            "voice endpoint mixes native and legacy authority"
        );
        let authority = ramflux_protocol::custody::CustodyAuthority {
            publication: custody.publication.clone(),
            custodian_publication: custody.custodian_publication.clone(),
        };
        let verified = ramflux_crypto::custody::verify_publication(&authority, now)?;
        let body = &verified.envelope().body;
        anyhow::ensure!(
            body.principal_kind == ramflux_protocol::PrincipalKind::Human
                && body.principal_id == endpoint.principal_id
                && body.account_anchor == manifest.principal_commitment
                && body.master_certificate.body.master_public_key == endpoint.root_public_key,
            "voice native root identity or kind mismatch"
        );
        let device = body
            .devices
            .iter()
            .find(|device| device.device_id == endpoint.device_id)
            .ok_or_else(|| anyhow::anyhow!("voice native endpoint device revoked"))?;
        let reference = ramflux_protocol::custody::DeviceRef {
            account_anchor: body.account_anchor.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        };
        let certificate = verified.authorize(&reference, "call", now)?;
        return Ok(VoiceDeviceAuthority {
            branch_public_key: certificate.branch_signing_public_key.clone(),
            device_epoch: device.device_epoch,
        });
    }
    let public = ramflux_crypto::verifying_key_from_base64url(&manifest.root_public_key)?;
    let set = manifest
        .signed_device_set
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("voice root-signed device set unavailable"))?;
    ramflux_crypto::verify_signed_device_set(&public, set)?;
    anyhow::ensure!(
        set.principal_id == endpoint.principal_id
            && set.principal_commitment == manifest.principal_commitment
            && set.principal_kind == ramflux_protocol::PrincipalKind::Human,
        "voice root identity or kind mismatch"
    );
    let device = manifest
        .devices
        .iter()
        .find(|d| d.device_id == endpoint.device_id && d.principal_id == endpoint.principal_id)
        .ok_or_else(|| anyhow::anyhow!("voice endpoint device revoked"))?;
    let commitments = ramflux_crypto::device_key_commitments(
        &device.branch_public_key,
        &ramflux_protocol::encode_base64url(device.prekey_bundle.identity_key),
    )?;
    anyhow::ensure!(
        set.devices.iter().any(|d| d.device_id == device.device_id
            && d.device_epoch == device.device_epoch
            && d.status == ramflux_protocol::DeviceSetStatus::Active
            && d.signing_key_commitment == commitments.0
            && d.agreement_key_commitment == commitments.1),
        "voice device keys revoked or substituted"
    );
    Ok(VoiceDeviceAuthority {
        branch_public_key: device.branch_public_key.clone(),
        device_epoch: device.device_epoch,
    })
}
fn validate_authority(
    request: &VoiceLeaseRequest,
    runtime: &GatewaySessionRuntime,
    caller: &ramflux_node_core::DeviceManifestResponse,
    recipient: &ramflux_node_core::DeviceManifestResponse,
    now: u64,
) -> anyhow::Result<()> {
    let scope = scope(request);
    let caller_entry = branch(&scope.caller, caller, now)?;
    let caller_key = caller_entry.branch_public_key.as_str();
    let recipient_entry = branch(&scope.callee, recipient, now)?;
    let recipient_key = recipient_entry.branch_public_key.as_str();
    let actor = match request {
        VoiceLeaseRequest::Accept { .. } => &scope.callee,
        VoiceLeaseRequest::Release { .. }
            if runtime.device_id == scope.callee.device_id
                && runtime.principal_id == scope.callee.principal_id =>
        {
            &scope.callee
        }
        _ => &scope.caller,
    };
    let key = if actor == &scope.caller { caller_key } else { recipient_key };
    let epoch = if actor == &scope.caller {
        caller_entry.device_epoch
    } else {
        recipient_entry.device_epoch
    };
    anyhow::ensure!(epoch == runtime.device_epoch, "voice session epoch changed");
    let actor_root = ramflux_crypto::verifying_key_from_base64url(&actor.root_public_key)?;
    anyhow::ensure!(
        runtime.source_identity.root_commitment()
            == ramflux_crypto::identity_root_commitment(&actor_root)
            && runtime.source_identity.device_id() == actor.device_id,
        "voice session root mismatch"
    );
    anyhow::ensure!(
        actor.device_id == runtime.device_id
            && actor.principal_id == runtime.principal_id
            && key == runtime.branch_public_key,
        "voice session actor mismatch"
    );
    if let VoiceLeaseRequest::Accept { consent } | VoiceLeaseRequest::Renew { consent } = request {
        anyhow::ensure!(
            consent.expires_at > now
                && consent.expires_at <= now.saturating_add(4 * 60 * 60)
                && ramflux_protocol::decode_base64url(&consent.lease_id)
                    .is_ok_and(|id| id.len() == 16),
            "voice consent deadline or lease id invalid"
        );
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::voice_lease_consent_bytes(consent)?,
            &consent.signature,
            recipient_key,
        )?;
    }
    Ok(())
}
#[cfg(test)]
#[path = "voice_tests.rs"]
mod tests;
