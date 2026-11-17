// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native attachment calls. The requester is taken only from the authenticated session and
//! forwarded to the home relay over the gateway-only mesh surface. A client never names it.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ramflux_node_core::{
    ATTACHMENT_CALL_BODY_MAX, ATTACHMENT_MESH_PATH, AttachmentCall, AttachmentFrame,
    AttachmentMeshReply, AttachmentMeshRequest, AttachmentReplyFrame, GatewayServerFrame,
    RequesterWire, WireBytes,
};
use tokio::sync::Semaphore;

use crate::{GatewayQuicContext, GatewaySendHandle, GatewaySessionRuntime};

const ENDPOINT_ENV: &str = "RAMFLUX_RELAY_ATTACHMENT_ENDPOINT";
const CODE_UNAVAILABLE: &str = "authority_unavailable";
const CODE_LAYOUT: &str = "layout_invalid";
const CALL_BUDGET: Duration = Duration::from_secs(25);
/// Calls in flight across the process. One session handles one frame at a time already.
const PROCESS_CALLS: usize = 64;

fn permits() -> &'static Semaphore {
    static PERMITS: OnceLock<Semaphore> = OnceLock::new();
    PERMITS.get_or_init(|| Semaphore::new(PROCESS_CALLS))
}

pub(crate) async fn handle(
    send: &GatewaySendHandle,
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &AttachmentFrame,
) -> anyhow::Result<()> {
    let reply = serve(context, runtime, request).await;
    let frame = GatewayServerFrame::Attachment { response: Box::new(reply) };
    let mut send = send.lock().await;
    ramflux_transport::write_gateway_session_json(&mut **send, &frame).await?;
    Ok(())
}

fn refused(request_id: &str, code: &str) -> AttachmentReplyFrame {
    AttachmentReplyFrame {
        request_id: request_id.to_owned(),
        code: Some(code.to_owned()),
        body: WireBytes::default(),
    }
}

/// The requester the session proved. The account anchor is the root commitment of the
/// authenticated source identity; the key is the session's registered branch key.
pub(crate) fn requester_of(runtime: &GatewaySessionRuntime, node: &str) -> Option<RequesterWire> {
    let key = ramflux_protocol::decode_base64url(&runtime.branch_public_key).ok()?;
    Some(RequesterWire {
        account_anchor: runtime.source_identity.root_commitment().to_owned(),
        device_id: runtime.source_identity.device_id().to_owned(),
        device_epoch: runtime.device_epoch,
        signing_public_key: key.try_into().ok()?,
        home_node_id: node.to_owned(),
    })
}

fn oversize(call: &AttachmentCall) -> bool {
    match call {
        AttachmentCall::Owner { body, operation, proof, signature } => {
            body.0.len() > ATTACHMENT_CALL_BODY_MAX
                || operation.0.len() > 4096
                || proof.0.len() > 4096
                || signature.0.len() != 64
        }
        AttachmentCall::Register { manifest, grant, upload_id } => {
            manifest.0.len() > 1_048_576 || grant.0.len() > 16_384 || upload_id.0.len() != 32
        }
        AttachmentCall::Read { capability, object_id, manifest_hash, .. } => {
            capability.0.len() > 8192 || object_id.0.len() != 32 || manifest_hash.0.len() != 32
        }
        AttachmentCall::Retire { retirement, signature } => {
            retirement.0.len() > 512 || signature.0.len() != 64
        }
        AttachmentCall::Authority => false,
    }
}

async fn serve(
    context: &GatewayQuicContext,
    runtime: &GatewaySessionRuntime,
    request: &AttachmentFrame,
) -> AttachmentReplyFrame {
    let id = request.request_id.as_str();
    if id.is_empty() || id.len() > 128 || oversize(&request.call) {
        return refused(id, CODE_LAYOUT);
    }
    let Some(requester) = requester_of(runtime, &context.node_id) else {
        return refused(id, CODE_UNAVAILABLE);
    };
    let Ok(endpoint) = ramflux_node_core::environment::var(ENDPOINT_ENV) else {
        return refused(id, CODE_UNAVAILABLE);
    };
    let Ok(_permit) = permits().try_acquire() else {
        return refused(id, CODE_UNAVAILABLE);
    };
    let tls = context.peers.tls().clone();
    let body = AttachmentMeshRequest { requester, call: request.call.clone() };
    let deadline = Instant::now() + CALL_BUDGET;
    let forwarded = tokio::task::spawn_blocking(move || {
        ramflux_transport::MeshHttpClient::new().post_json_with_deadline::<_, AttachmentMeshReply>(
            &endpoint,
            ATTACHMENT_MESH_PATH,
            &tls,
            "ramflux-relay",
            &body,
            deadline,
        )
    })
    .await;
    match forwarded {
        Ok(Ok(reply)) => {
            AttachmentReplyFrame { request_id: id.to_owned(), code: reply.code, body: reply.body }
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "attachment relay call failed");
            refused(id, CODE_UNAVAILABLE)
        }
        Err(error) => {
            tracing::warn!(%error, "attachment relay call aborted");
            refused(id, CODE_UNAVAILABLE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(principal: &str) -> anyhow::Result<GatewaySessionRuntime> {
        let root = ramflux_crypto::create_identity_root(principal, [0x91; 32]);
        let branch = ramflux_crypto::create_device_branch(principal, "device-a", 1, [0x92; 32]);
        Ok(GatewaySessionRuntime {
            call_session_generation: None,
            session_push: None,
            ephemeral: false,
            push_limit: 256,
            source_identity: ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
                &root, &branch,
            )?,
            session_id: "session".into(),
            resume_token: "resume".into(),
            principal_id: principal.into(),
            device_id: branch.device_id.clone(),
            target_delivery_id: "target".into(),
            device_epoch: 3,
            branch_public_key: ramflux_protocol::encode_base64url(
                branch.signing_key.verifying_key().to_bytes(),
            ),
            supports_forward_ack: false,
            ephemeral_rate: std::sync::Arc::default(),
        })
    }

    #[test]
    fn the_requester_is_the_authenticated_session_and_never_a_client_field() -> anyhow::Result<()> {
        let session = runtime("principal-x")?;
        let wire = requester_of(&session, "node-x").ok_or_else(|| anyhow::anyhow!("requester"))?;
        let root = ramflux_crypto::create_identity_root("principal-x", [0x91; 32]);
        assert_eq!(
            wire.account_anchor,
            ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key()),
            "the account anchor is the root commitment of the authenticated source identity"
        );
        assert_eq!(wire.device_id, "device-a");
        assert_eq!(wire.device_epoch, 3);
        assert_eq!(wire.home_node_id, "node-x");
        let mut broken = session;
        broken.branch_public_key = "not-a-key".into();
        assert!(requester_of(&broken, "node-x").is_none(), "a malformed key yields no requester");
        Ok(())
    }

    #[test]
    fn oversize_or_malformed_calls_are_refused_before_forwarding() {
        let big = AttachmentCall::Owner {
            operation: vec![0; 8].into(),
            body: vec![0; ATTACHMENT_CALL_BODY_MAX + 1].into(),
            proof: vec![0; 8].into(),
            signature: vec![0; 64].into(),
        };
        assert!(oversize(&big), "a body above one chunk is refused");
        let short = AttachmentCall::Retire {
            retirement: vec![0; 10].into(),
            signature: vec![0; 63].into(),
        };
        assert!(oversize(&short), "a short signature is refused");
        assert!(!oversize(&AttachmentCall::Authority));
    }
}
