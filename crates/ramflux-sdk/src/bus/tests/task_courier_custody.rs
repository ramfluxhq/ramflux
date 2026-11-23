// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native custody admission and exporter-bound gateway proofs for courier fixtures.
use super::Case as Result;
use ramflux_crypto::custody::{
    VerifiedNodeRecord, sign_node_identity_record, sign_proxy_acceptance,
};
use ramflux_protocol::custody::*;
use std::{path::Path, sync::Arc};
pub(super) struct NativeGateway {
    router: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    service: ramflux_node_core::CustodyService,
    node: VerifiedNodeRecord,
}
impl NativeGateway {
    pub(super) fn new(root: &Path) -> Result<Self> {
        let now = crate::custody::network_now()?;
        let original = crate::custody::network_tests::node(
            now,
            ramflux_transport::custody_certificate_file_hash(&root.join("ca.pem"))?,
        )
        .map_err(|error| error.to_string())?;
        let node = node(&original, now)?;
        let router = Arc::new(ramflux_node_core::RouterCore::new());
        let store =
            Arc::new(ramflux_node_core::RouterRedbStore::open(root.join("custody-router.redb"))?);
        store.save_router(&router)?;
        let service = ramflux_node_core::CustodyService::new(node.clone(), false, &store, now)?;
        Ok(Self { router, store, service, node })
    }
    pub(super) fn dispatch(
        &self,
        stream: &ramflux_transport::GatewayTcpTlsStream,
        connection: &str,
        frame: CustodyClientFrame,
    ) -> Result<CustodyServerFrame> {
        dispatch(self, stream, connection, frame)
    }
    /// Answers a live-session `GrantRenew` the way the gateway does: the router re-admits the
    /// lease through `RenewNativeSession`; any refusal is `None` (the gateway then closes).
    pub(super) fn renew(&self, connection: &str, session_id: &str) -> Result<Option<u64>> {
        let now = crate::custody::network_now()?;
        let frame = self.service.mesh(
            &self.router,
            &self.store,
            CustodyMeshRequest::RenewNativeSession {
                session_id: session_id.into(),
                connection_id: connection.into(),
            },
            "ramflux-gateway",
            now,
        );
        Ok(match frame {
            CustodyServerFrame::SessionEstablished { session }
                if session.session_id == session_id =>
            {
                Some(session.expires_at)
            }
            _ => None,
        })
    }
    pub(super) fn disconnect(&self, connection: &str) {
        self.service.disconnect("ramflux-gateway", connection);
    }
}
fn node(original: &VerifiedNodeRecord, now: u64) -> Result<VerifiedNodeRecord> {
    let proxy = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let mut body = original.envelope().body.clone();
    body.channel_binding_modes = vec![BindingMode::HomeRelayReceipt];
    body.proxy_keys = vec![ProxyKey {
        key_id: ramflux_protocol::encode_base64url([79; 32]),
        public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
        not_before: now - 1,
        sign_until: now + 600,
        overlap_until: now + 605_400,
        status: ReceiptKeyStatus::Active,
        proxy_id: "ramflux-gateway".into(),
        audiences: vec!["node".into()],
    }];
    let record = sign_node_identity_record(&ramflux_crypto::fixture_signing_key(), body)?;
    Ok(ramflux_crypto::custody::verify_node_identity_record(
        &record,
        "node",
        &ramflux_crypto::fixture_public_key_base64url(),
        now,
    )?)
}

fn dispatch(
    context: &NativeGateway,
    stream: &ramflux_transport::GatewayTcpTlsStream,
    connection: &str,
    frame: CustodyClientFrame,
) -> Result<CustodyServerFrame> {
    let now = crate::custody::network_now()?;
    let request = match frame {
        CustodyClientFrame::CustodyOpen { binding_mode } => {
            assert_eq!(binding_mode, BindingMode::HomeRelayReceipt);
            let CustodyServerFrame::NodeIdentity { record, audience, .. } = context.service.mesh(
                &context.router,
                &context.store,
                CustodyMeshRequest::NodeIdentity { record_hash: None },
                "ramflux-gateway",
                now,
            ) else {
                return Err("missing node identity".into());
            };
            return Ok(CustodyServerFrame::NodeIdentity {
                record,
                audience,
                binding_mode,
                proxy_key_custody: Some("software".into()),
            });
        }
        CustodyClientFrame::Challenge { device_ref, action } => CustodyMeshRequest::Challenge {
            device_ref,
            action,
            binding_mode: BindingMode::HomeRelayReceipt,
            client_source: "127.0.0.1".into(),
            connection_id: connection.into(),
        },
        CustodyClientFrame::Prove { action, proof } => {
            let nonce = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| "nonce")?;
            let material = ramflux_transport::custody_tcp_exporter(stream, &nonce)?;
            let observed = ramflux_crypto::custody::branch_exporter_hash(&material);
            assert_eq!(proof.body.transport_binding, observed);
            let receipt = sign_proxy_acceptance(
                &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                &context.node,
                &proof,
                &observed,
                ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                now,
            )?;
            CustodyMeshRequest::Prove {
                action,
                proof,
                receipt: Some(Box::new(receipt)),
                connection_id: connection.into(),
            }
        }
        _ => return Err("unexpected native frame".into()),
    };
    Ok(context.service.mesh(&context.router, &context.store, request, "ramflux-gateway", now))
}

pub(super) struct Connection<'a>(pub(super) &'a NativeGateway, pub(super) String);
impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.0.disconnect(&self.1);
    }
}
