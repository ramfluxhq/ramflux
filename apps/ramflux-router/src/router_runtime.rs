// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::sync::Arc;
use std::time::Instant;

pub(crate) struct TokioRouterRuntime {
    state: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
}

impl TokioRouterRuntime {
    pub(crate) fn new(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> Self {
        Self { state, store }
    }
}

pub(crate) enum RouterHandle {
    Tokio(Arc<TokioRouterRuntime>),
}

impl RouterHandle {
    pub(crate) fn tokio(
        state: Arc<ramflux_node_core::RouterCore>,
        store: Arc<ramflux_node_core::RouterRedbStore>,
    ) -> Self {
        Self::Tokio(Arc::new(TokioRouterRuntime::new(state, store)))
    }

    pub(crate) fn state(&self) -> &ramflux_node_core::RouterCore {
        match self {
            Self::Tokio(runtime) => runtime.state.as_ref(),
        }
    }

    pub(crate) fn store(&self) -> &ramflux_node_core::RouterRedbStore {
        match self {
            Self::Tokio(runtime) => runtime.store.as_ref(),
        }
    }

    pub(crate) fn submit_envelope(
        &self,
        envelope: ramflux_protocol::Envelope,
        total_started: Instant,
    ) -> anyhow::Result<ramflux_node_core::EnvelopeSubmitResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::submit_envelope(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                envelope,
                total_started,
            ),
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_ack(
        &self,
        ack: &ramflux_protocol::Ack,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => {
                crate::router_engine::apply_ack(runtime.state.as_ref(), runtime.store.as_ref(), ack)
            }
        }
    }

    pub(crate) fn apply_bound_ack(
        &self,
        request: &ramflux_node_core::TargetAckRequest,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_ack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }

    #[cfg(feature = "itest-http")]
    pub(crate) fn apply_nack(
        &self,
        nack: &ramflux_protocol::Nack,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                nack,
            ),
        }
    }

    pub(crate) fn apply_bound_nack(
        &self,
        request: &ramflux_node_core::TargetNackRequest,
    ) -> anyhow::Result<ramflux_node_core::InboxCursorResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::apply_bound_nack(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }

    pub(crate) fn own_device_fanout(
        &self,
        request: &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest,
    ) -> anyhow::Result<ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse> {
        match self {
            Self::Tokio(runtime) => crate::router_engine::own_device_fanout(
                runtime.state.as_ref(),
                runtime.store.as_ref(),
                request,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use ramflux_protocol::{DeliveryClass, Ext, Priority, SignatureAlg, SignedFields};

    use super::*;

    #[test]
    fn tokio_handle_matches_submit_and_replay_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_submit", "target_runtime_submit");
        let (oracle_state, oracle_store, _oracle_path) = test_router("submit_oracle")?;
        let oracle = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            envelope.clone(),
            Instant::now(),
        )?;

        let (handle, _handle_path) = test_handle("submit_handle")?;
        let via_handle = handle.submit_envelope(envelope.clone(), Instant::now())?;
        assert_eq!(via_handle, oracle);

        let replay = handle.submit_envelope(envelope, Instant::now())?;
        assert!(replay.outcome.starts_with("rejected_security:"));
        assert!(replay.outcome.contains("replay:"));
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_bound_ack_and_nack_oracle() -> anyhow::Result<()> {
        let envelope = current_envelope("env_runtime_ack", "target_runtime_ack");

        let (oracle_state, oracle_store, _oracle_path) = test_router("ack_oracle")?;
        let _submitted = crate::router_engine::submit_envelope(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            envelope.clone(),
            Instant::now(),
        )?;
        let ack = ack("env_runtime_ack");
        let ack_request = ramflux_node_core::TargetAckRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            ack: ack.clone(),
        };
        let oracle_ack = crate::router_engine::apply_bound_ack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &ack_request,
        )?;

        let (handle, _handle_path) = test_handle("ack_handle")?;
        let _submitted = handle.submit_envelope(envelope, Instant::now())?;
        let handle_ack = handle.apply_bound_ack(&ack_request)?;
        assert_eq!(handle_ack, oracle_ack);

        let nack = nack("env_runtime_ack");
        let nack_request = ramflux_node_core::TargetNackRequest {
            target_delivery_id: "target_runtime_ack".to_owned(),
            nack,
        };
        let oracle_nack_response = crate::router_engine::apply_bound_nack(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &nack_request,
        )?;
        let handle_nack_response = handle.apply_bound_nack(&nack_request)?;
        assert_eq!(handle_nack_response, oracle_nack_response);
        Ok(())
    }

    #[test]
    fn tokio_handle_matches_fanout_oracle() -> anyhow::Result<()> {
        let request = fanout_request("env_runtime_fanout");

        let (oracle_state, oracle_store, _oracle_path) = test_router("fanout_oracle")?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(oracle_state.as_ref(), "alice", "alice_laptop", "target_laptop", 2)?;
        let oracle = crate::router_engine::own_device_fanout(
            oracle_state.as_ref(),
            oracle_store.as_ref(),
            &request,
        )?;

        let (handle, _handle_path) = test_handle("fanout_handle")?;
        register_test_device(handle.state(), "alice", "alice_phone", "target_phone", 1)?;
        register_test_device(handle.state(), "alice", "alice_laptop", "target_laptop", 2)?;
        let via_handle = handle.own_device_fanout(&request)?;

        assert_eq!(via_handle, oracle);
        assert_eq!(via_handle.delivered.len(), 1);
        assert_eq!(via_handle.delivered[0].device_id, "alice_laptop");
        Ok(())
    }

    fn test_handle(name: &str) -> anyhow::Result<(RouterHandle, PathBuf)> {
        let (state, store, path) = test_router(name)?;
        Ok((RouterHandle::tokio(state, store), path))
    }

    fn test_router(
        name: &str,
    ) -> anyhow::Result<(
        Arc<ramflux_node_core::RouterCore>,
        Arc<ramflux_node_core::RouterRedbStore>,
        PathBuf,
    )> {
        let path = temp_store_path(name)?;
        let store = Arc::new(ramflux_node_core::RouterRedbStore::open(&path)?);
        let state = Arc::new(ramflux_node_core::RouterCore::new());
        Ok((state, store, path))
    }

    fn current_envelope(envelope_id: &str, target_delivery_id: &str) -> ramflux_protocol::Envelope {
        let mut envelope = envelope(envelope_id, target_delivery_id, DeliveryClass::OpaqueEvent);
        envelope.created_at =
            i64::try_from(ramflux_node_core::now_unix_seconds()).unwrap_or(i64::MAX - 3_600);
        envelope
    }

    fn fanout_request(envelope_id: &str) -> ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
        ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
            principal_id: "alice".to_owned(),
            source_device_id: "alice_phone".to_owned(),
            envelope: current_envelope(envelope_id, "target_unused"),
        }
    }

    fn envelope(
        envelope_id: &str,
        target_delivery_id: &str,
        delivery_class: DeliveryClass,
    ) -> ramflux_protocol::Envelope {
        ramflux_protocol::Envelope {
            schema: "ramflux.envelope.v1".to_owned(),
            version: 1,
            domain: "ramflux.envelope.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            envelope_id: envelope_id.to_owned(),
            source_principal_id: "alice".to_owned(),
            source_device_id: "alice_device".to_owned(),
            target_delivery_id: target_delivery_id.to_owned(),
            routing_set_id: None,
            delivery_class,
            priority: Priority::Normal,
            ttl: 3_600,
            created_at: 1_760_000_000,
            encrypted_payload: "ciphertext".to_owned(),
            payload_hash: "payload_hash".to_owned(),
        }
    }

    fn ack(envelope_id: &str) -> ramflux_protocol::Ack {
        ramflux_protocol::Ack {
            schema: "ramflux.ack.v1".to_owned(),
            version: 1,
            domain: "ramflux.ack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            ack_id: format!("ack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            received_at: 1_760_000_010,
            cursor_after: None,
        }
    }

    fn nack(envelope_id: &str) -> ramflux_protocol::Nack {
        ramflux_protocol::Nack {
            schema: "ramflux.nack.v1".to_owned(),
            version: 1,
            domain: "ramflux.nack.v1".to_owned(),
            ext: Ext::default(),
            signed: signed_fields(),
            nack_id: format!("nack_{envelope_id}"),
            envelope_id: envelope_id.to_owned(),
            receiver_device_id: "device_a".to_owned(),
            reason: ramflux_protocol::NackReason::MissingDependency,
            received_at: 1_760_000_010,
            retry_after: Some(30),
            proof_hash: None,
            new_home_node_hint: None,
        }
    }

    fn signed_fields() -> SignedFields {
        SignedFields {
            signing_key_id: "test_key".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: "test_signature".to_owned(),
        }
    }

    fn register_test_device(
        state: &ramflux_node_core::RouterCore,
        principal_id: &str,
        device_id: &str,
        target_delivery_id: &str,
        nonce: u64,
    ) -> anyhow::Result<()> {
        let root_seed = seed_from_nonce(0x31, nonce);
        let device_seed = seed_from_nonce(0x41, nonce);
        let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
        let device = ramflux_crypto::create_device_branch(principal_id, device_id, 1, device_seed);
        let proof = ramflux_crypto::authorize_device_branch(
            &root,
            &device,
            ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.to_owned()],
            1_760_000_000 + i64::try_from(nonce)?,
            1_760_003_600 + i64::try_from(nonce)?,
        )?;
        let root_public_key =
            ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
        let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
        let request = ramflux_node_core::IdentityRegisterRequest {
            principal_commitment: ramflux_crypto::blake3_256_base64url(
                "ramflux.identity.root_public_key.commitment.v1",
                &root_public_key_bytes,
            ),
            root_public_key,
            branch_public_key: ramflux_protocol::encode_base64url(
                device.signing_key.verifying_key().to_bytes(),
            ),
            proof,
            target_delivery_id: target_delivery_id.to_owned(),
            gateway_id: "ramflux-gateway".to_owned(),
            session_id: format!("session_{device_id}"),
            push_alias_hash: Some(format!("push_{device_id}")),
            now: 1_760_000_010 + i64::try_from(nonce)?,
            registration_pow: None,
            source_ip_hash: Some("source_ip_hash".to_owned()),
        };
        state.mvp1_register_identity(&request)?;
        Ok(())
    }

    fn seed_from_nonce(prefix: u8, nonce: u64) -> [u8; 32] {
        let mut seed = [prefix; 32];
        seed[24..].copy_from_slice(&nonce.to_be_bytes());
        seed
    }

    fn temp_store_path(test_name: &str) -> anyhow::Result<PathBuf> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(std::env::temp_dir().join(format!(
            "ramflux-router-{test_name}-{}-{}.redb",
            std::process::id(),
            elapsed.as_nanos()
        )))
    }
}
