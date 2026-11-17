// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native device.revoke retires real private pairs and fences stale authority.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture, TestResult};
#[path = "device_revocation_support.rs"]
mod support;
use super::native_pair_tests::{entry, text};
use support::*;

#[tokio::test]
async fn revoking_an_own_device_via_the_production_method_erases_pair_work_and_rejects_stale_cache()
-> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let mut bob = Fixture::with_device("owner", "bob").await?;
        let alice = bob.enroll_sibling("sibling", "alice").await?;
        let local = bob.client.owned_device_identity()?;
        let remote = alice.client.owned_device_identity()?;
        seed_pair(&bob, &alice)?;
        let stale = alice.manifest.clone();
        revoke(&mut bob, "alice").await?;
        let work = format!("dm-pair/reset-work/{}", RamfluxClient::pair_key(&local, &remote)?);
        assert!(
            bob.client.account_db()?.load_actor_state::<serde_json::Value>(&work)?.is_none(),
            "test: native revoke retained pair reset work"
        );
        assert!(
            bob.client.active_pair(&local, &remote)?.is_none(),
            "test: native revoke retained an active pair"
        );
        assert_eq!(
            bob.client
                .account_db()?
                .list_actor_states::<serde_json::Value>("dm-pair/session/")?
                .len(),
            0,
            "test: native revoke retained private pair sessions"
        );
        assert!(
            bob.client.persist_observed_identity_directory_now(&stale).is_err(),
            "test: replayed pre-revocation directory was accepted"
        );
        assert!(
            matches!(
                bob.client.trusted_device(HeadUse::NewAuthorization, &remote),
                Err(SdkError::InboundRejected(_))
            ),
            "test: stale cached device still authorizes new work"
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn revoking_the_current_device_clears_all_pairs_and_fences_pair_traffic() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        // A different primary issues this denial. Native primaries cannot revoke themselves.
        let mut alice = Fixture::with_device("owner", "alice").await?;
        let mut bob = alice.enroll_sibling("sibling", "bob").await?;
        // Pair traffic runs between different roots: siblings share a root and have no DM scope.
        let carol = Fixture::new("revoke-local-peer").await?;
        bob.accept_peer(&carol)?;
        carol.accept_peer(&bob)?;
        let first = entry(&carol, &bob, &text(&carol, &bob, "established before revocation")?)?;
        bob.receive(first.envelope, 1).await?;
        let incoming = entry(&carol, &bob, &text(&carol, &bob, "revoked-local-incoming")?)?;
        assert!(
            bob.client.open_routed(&incoming, &bob.config.device_id).is_ok(),
            "test: the pending packet was invalid before revocation"
        );
        let own = bob.client.owned_device_identity()?;
        let remote = carol.client.owned_device_identity()?;
        assert!(
            bob.client.begin_pair_recovery(&own, &remote, now_unix_timestamp())?,
            "test: reset work was never created"
        );
        let mut outgoing = outgoing(&bob, &carol, "revoked-local-outgoing");
        outgoing.conversation_id = ramflux_protocol::message::dm_scope::derive(
            own.root_commitment(),
            remote.root_commitment(),
        )?;
        let (mut engine, sent) = engine(&bob);
        revoke(&mut alice, "bob").await?;
        let account = alice.client.born_v3_account.as_ref().ok_or("test: native publisher")?;
        bob.client.observe_custody_manifest(
            &ramflux_protocol::custody::CustodyManifest {
                publication: ramflux_protocol::custody::Publication {
                    record: account.record().clone(),
                    compacted_ids: None,
                },
                custodian_publication: None,
                devices: Vec::new(),
            },
            &alice.manifest.principal_commitment,
            crate::custody::network_now()?,
        )?;
        assert_eq!(
            bob.client
                .account_db()?
                .list_actor_states::<serde_json::Value>("dm-pair/reset-work/")?
                .len(),
            0,
            "test: local denial retained reset work"
        );
        assert_eq!(
            bob.client
                .account_db()?
                .list_actor_states::<serde_json::Value>("dm-pair/session/")?
                .len(),
            0,
            "test: local denial retained private sessions"
        );
        assert_local_denial(
            bob.client.apply_routed_entry(&mut engine, &super::review::pool()?, &incoming).await,
        );
        assert_local_denial(
            bob.client
                .send_plaintext_direct_message_via_gateway(&mut engine, outgoing, b"do not send")
                .await,
        );
        bob.client.retry_pair_resets(&mut engine, now_unix_timestamp() + 86400).await?;
        assert_eq!(
            sent.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "test: revoked local device emitted recovery traffic"
        );
        assert_eq!(
            bob.client
                .account_db()?
                .list_actor_states::<serde_json::Value>("dm-pair/session/")?
                .len(),
            0,
            "test: denied traffic recreated private sessions"
        );
        Ok(())
    }))
    .await
}

#[tokio::test]
async fn externally_custodied_revoke_refuses_non_primary_before_publication() -> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let mut owner = Fixture::externally_custodied("external-agent").await?;
        let peer = Fixture::new("external-peer").await?;
        owner.client.persist_observed_identity_directory_now(&peer.manifest)?;
        seed_pair(&owner, &peer)?;
        let before =
            owner.client.born_v3_account.as_ref().ok_or("test: external account")?.record().clone();
        assert_eq!(
            before.body.master_certificate.body.custody_kind,
            ramflux_protocol::custody::CustodyKind::ExternalHuman,
            "test: fixture is self-custodied"
        );
        assert!(
            owner
                .manifest
                .custody
                .as_ref()
                .and_then(|native| native.custodian_publication.as_ref())
                .is_some(),
            "test: fixture lost human custodian authority"
        );
        let error = revoke(&mut owner, "other")
            .await
            .err()
            .ok_or("test: external non-primary published a revoke")?;
        assert!(
            matches!(
                error.downcast_ref::<SdkError>(),
                Some(SdkError::PairingCode("PrimaryRequired"))
            ),
            "test: external revoke refused for another reason: {error}"
        );
        assert!(
            owner.client.account_db()?.pairing_head()?.is_none(),
            "test: refused external revoke journaled a candidate"
        );
        assert!(
            !owner
                .client
                .account_db()?
                .list_actor_states::<serde_json::Value>("dm-pair/session/")?
                .is_empty(),
            "test: refused external revoke erased private pairs"
        );
        assert_eq!(
            crate::custody::load_account(
                &owner.root.0,
                "external-agent",
                crate::custody::network_now()?
            )?
            .record(),
            &before,
            "test: refused external revoke installed an acknowledged head"
        );
        Ok(())
    }))
    .await
}

/// Peer-revocation and local-revocation regressions carried over from the generation-1 branch:
/// they additionally prove an unrelated root's pair is untouched and that a revoked
/// prekey advertisement is refused.
mod published_authority {
    use super::super::native_pair_tests::{entry, text};
    use crate::client::identity_authority::HeadUse;
    use crate::client::native_test_support::{Fixture, TestResult, peer_control_send, watchdog};
    use crate::{GatewayDirectMessage, RamfluxClient};

    fn revoke_published(local: &Fixture, owner: &Fixture, retain_bad_prekey: bool) -> TestResult {
        let mut native = owner.manifest.custody.as_ref().ok_or("native publication")?.clone();
        let primary = owner.vault.primary_for_public_key(
            &native.publication.record.body.master_certificate.body.self_signing_public_key,
        )?;
        let now = crate::custody::network_now()?;
        let current = local
            .client
            .current_custody_authority(&owner.client.own_account_anchor()?, now)?
            .ok_or("native authority")?;
        native.publication.record =
            primary.revoke_device(&current, &owner.config.device_id, now)?;
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
            local.client.observe_custody_manifest(
                &native,
                &owner.client.own_account_anchor()?,
                now,
            )?;
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
            revoke_published(&local, &peer, true)?;
            assert!(!local.client.account_db()?.actor_state_exists(&work)?);
            assert!(local.client.active_pair(&own, &remote)?.is_none());
            assert_eq!(local.client.persisted_pair_snapshot(&own, &unaffected)?, other_before);
            assert!(
                local.client.persist_observed_identity_directory_now(&peer.manifest).is_err(),
                "old native authority replaced a revocation"
            );
            assert!(local.client.trusted_device(HeadUse::NewAuthorization, &remote).is_err());
            Ok(())
        })
        .await?
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_local_revocation_clears_pairs_and_fences_valid_pair_traffic_before_io()
    -> TestResult {
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
            revoke_published(&local, &local, false)?;
            assert!(local.client.active_pair(&own, &remote)?.is_none());
            assert_eq!(
                local.client.account_db()?.actor_state_keys("dm-pair/reset-work/")?.len(),
                0
            );
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
}
