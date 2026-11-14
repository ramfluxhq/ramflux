// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Accepted native revocation erases real generated pair traffic and fences stale caches.
use super::native_pair_tests::{entry, text};
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture, TestResult, peer_control_send, watchdog};
use crate::{GatewayDirectMessage, RamfluxClient};

fn revoke(local: &Fixture, owner: &Fixture, retain_bad_prekey: bool) -> TestResult {
    let mut native = owner.manifest.custody.as_ref().ok_or("native publication")?.clone();
    let primary = owner.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let current = local
        .client
        .current_custody_authority(&owner.client.own_account_anchor()?, now)?
        .ok_or("native authority")?;
    native.publication.record = primary.revoke_device(&current, &owner.config.device_id, now)?;
    if retain_bad_prekey {
        assert!(
            local
                .client
                .observe_custody_manifest(&native, &owner.client.own_account_anchor()?, now)
                .is_err(),
            "revoked prekey advertisement was accepted"
        );
    } else {
        native.devices.clear();
        local.client.observe_custody_manifest(&native, &owner.client.own_account_anchor()?, now)?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_peer_revocation_erases_pair_work_and_rejects_stale_cache() -> TestResult {
    watchdog::within(async {
        let mut local = Fixture::new("revoke-local").await?;
        let peer = Fixture::new("revoke-peer").await?;
        let other = Fixture::new("revoke-other").await?;
        local.accept_peer(&peer)?;
        peer.accept_peer(&local)?;
        local.accept_peer(&other)?;
        other.accept_peer(&local)?;
        let packet = entry(&peer, &local, &text(&peer, &local, "valid before revocation")?)?;
        local.receive(packet.envelope, 1).await?;
        entry(&local, &other, &text(&local, &other, "independent root")?)?;
        let own = local.client.owned_device_identity()?;
        let remote = peer.client.owned_device_identity()?;
        let unaffected = other.client.owned_device_identity()?;
        let other_before = local.client.persisted_pair_snapshot(&own, &unaffected)?;
        assert!(local.client.begin_pair_recovery(
            &own,
            &remote,
            crate::time::now_unix_timestamp()
        )?);
        let work = RamfluxClient::reset_work_key(&own, &remote)?;
        assert!(local.client.account_db()?.actor_state_exists(&work)?);
        revoke(&local, &peer, true)?;
        assert!(!local.client.account_db()?.actor_state_exists(&work)?);
        assert!(local.client.active_pair(&own, &remote)?.is_none());
        assert_eq!(local.client.persisted_pair_snapshot(&own, &unaffected)?, other_before);
        assert!(
            local.client.persist_fetched_identity_directory(&peer.manifest).is_err(),
            "old native authority replaced a revocation"
        );
        assert!(local.client.trusted_device(HeadUse::NewAuthorization, &remote).is_err());
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn native_local_revocation_clears_pairs_and_fences_valid_pair_traffic_before_io() -> TestResult
{
    watchdog::within(async {
        let mut local = Fixture::new("revoke-current").await?;
        let peer = Fixture::new("revoke-current-peer").await?;
        local.accept_peer(&peer)?;
        peer.accept_peer(&local)?;
        let first = entry(&peer, &local, &text(&peer, &local, "initial")?)?;
        local.receive(first.envelope, 1).await?;
        let incoming = entry(&peer, &local, &text(&peer, &local, "pending valid Message")?)?;
        assert!(
            local.client.open_routed(&incoming, &local.config.device_id).is_ok(),
            "the pending packet was invalid before revocation"
        );
        let own = local.client.owned_device_identity()?;
        let remote = peer.client.owned_device_identity()?;
        assert!(local.client.begin_pair_recovery(
            &own,
            &remote,
            crate::time::now_unix_timestamp()
        )?);
        let (mut engine, captured) = peer_control_send::engine_capture(&local, &peer, false)?;
        revoke(&local, &local, false)?;
        assert!(local.client.active_pair(&own, &remote)?.is_none());
        assert_eq!(local.client.account_db()?.actor_state_keys("dm-pair/reset-work/")?.len(), 0);
        assert_eq!(local.client.account_db()?.actor_state_keys("dm-pair/session/")?.len(), 0);
        assert!(local.client.require_current_device_authorization(&own).is_err());
        assert!(local.receive(incoming.envelope, 2).await.is_err());
        let message = GatewayDirectMessage {
            conversation_id: ramflux_protocol::message::dm_scope::derive(
                own.root_commitment(),
                remote.root_commitment(),
            )?,
            message_id: "revoked-send".into(),
            envelope_id: "revoked-send-wire".into(),
            source_principal_id: local.config.principal_id.clone(),
            sender_id: local.config.device_id.clone(),
            recipient_device_id: Some(peer.config.device_id.clone()),
            recipient_principal_commitment: Some(peer.client.own_account_anchor()?),
            target_delivery_id: peer.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 300,
        };
        assert!(
            local
                .client
                .send_plaintext_direct_message_via_gateway(&mut engine, message, b"do not send")
                .await
                .is_err()
        );
        local
            .client
            .retry_pair_resets(&mut engine, crate::time::now_unix_timestamp() + 86400)
            .await?;
        assert!(captured.lock().map_err(|_| "capture poisoned")?.is_empty());
        assert_eq!(local.client.account_db()?.actor_state_keys("dm-pair/session/")?.len(), 0);
        Ok(())
    })
    .await?
}
