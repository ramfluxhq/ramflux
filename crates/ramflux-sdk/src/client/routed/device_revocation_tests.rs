// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native device.revoke retires real private pairs and fences stale authority.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{Fixture, TestResult};
#[path = "device_revocation_support.rs"]
mod support;
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
            bob.client.persist_fetched_identity_directory(&stale).is_err(),
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
        seed_pair(&bob, &alice)?;
        let incoming = packet(&alice, &bob, "revoked-local-incoming")?;
        let outgoing = outgoing(&bob, &alice, "revoked-local-outgoing");
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
            bob.client
                .apply_routed_entry(&mut engine, &super::review::pool()?, &incoming, false)
                .await,
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
        owner.client.persist_fetched_identity_directory(&peer.manifest)?;
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
