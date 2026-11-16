// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The explicit-root SDK send authorizes against the CURRENT authority: a cached pair never stands
//! in for a fetch. Real accounts, a real pair, a real directory over TLS.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use std::collections::BTreeMap;

#[tokio::test]
async fn explicit_root_send_with_a_cached_pair_still_fetches_the_current_authority() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        let alice = Fixture::new("fresh-send-alice").await?;
        let bob = Fixture::new("fresh-send-bob").await?;
        alice.client.persist_fetched_identity_directory(&bob.manifest)?;
        let local = alice.client.owned_device_identity()?;
        let remote = bob.client.owned_device_identity()?;
        let bundle = bob.client.load_x3dh_private_state(&remote)?.bundle;
        let hash = crate::dm::prekey_bundle_hash(&bundle)?;
        let message = GatewayDirectMessage {
            conversation_id: "dm".into(),
            message_id: "fresh-send".into(),
            envelope_id: "fresh-send".into(),
            source_principal_id: alice.manifest.principal_id.clone(),
            sender_id: local.device_id().into(),
            recipient_device_id: Some(remote.device_id().into()),
            recipient_principal_commitment: Some(remote.root_commitment().into()),
            target_delivery_id: remote.storage_key().into(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 60,
        };
        let (session, _) = alice.client.create_send_dm_session_from_bundle(
            &message,
            remote.device_id(),
            bundle,
            local.device_id(),
        )?;
        alice.client.persist_pair(&local, &remote, &hash, &session)?;
        let root = bob.manifest.principal_commitment.clone();
        let (address, server) = crate::bus::dispatch::surface_transport::fixture::directory(
            &alice.root.0,
            BTreeMap::from([(root.clone(), serde_json::to_value(&bob.manifest)?)]),
        )
        .await?;
        let mut config = alice.config.clone();
        config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = address;
        config.tcp_gateway_addr = Some(address);
        config.server_name = "test-gateway".into();
        config.ca_cert = alice.root.0.join("ca.pem");
        let (recorder, _sealed) = crate::bus::test_gateway::Recorder::new(None);
        let mut engine =
            crate::GatewaySessionEngine::with_test_transport(config, Box::new(recorder));
        assert!(
            alice.client.sendable_pair(&local, &remote)?.is_some(),
            "test: the cached pair must be sendable, or the case proves nothing"
        );
        alice.client.scaffold_seal_without_fetch.set(false);
        let began = std::time::Instant::now();
        alice.client.send_pair_session(&mut engine, &message).await?;
        assert!(
            alice.client.native_head_freshness.borrow().observed_since(&root, began),
            "a send that holds a cached pair must still fetch the current authority"
        );
        server.abort();
        Ok(())
    })
    .await
    .map_err(|_| "test: deadline exceeded")?
}
