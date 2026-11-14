// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Post-ack observer preserves external human authority while retiring private pairs.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn externally_custodied_published_revoke_observer_retires_pairs_and_fences_local_device()
-> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let owner = Fixture::externally_custodied("external-observer").await?;
        let peer = Fixture::new("observer-peer").await?;
        owner.client.persist_fetched_identity_directory(&peer.manifest)?;
        let local = owner.client.owned_device_identity()?;
        let remote = peer.client.owned_device_identity()?;
        let bundle = peer.client.load_x3dh_private_state(&remote)?.bundle;
        let hash = crate::dm::prekey_bundle_hash(&bundle)?;
        let message = crate::GatewayDirectMessage {
            conversation_id: "external-retirement".into(),
            message_id: "before".into(),
            envelope_id: "before".into(),
            source_principal_id: owner.manifest.principal_id.clone(),
            sender_id: local.device_id().into(),
            recipient_device_id: Some(remote.device_id().into()),
            recipient_principal_commitment: Some(remote.root_commitment().into()),
            target_delivery_id: remote.storage_key().into(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 3600,
        };
        let (session, _) = owner.client.create_send_dm_session_from_bundle(
            &message,
            remote.device_id(),
            bundle,
            local.device_id(),
        )?;
        owner.client.persist_pair(&local, &remote, &hash, &session)?;
        let private = format!("dm-pair/session/{}", session.session_id);
        assert!(
            owner.client.account_db()?.actor_state_exists(&private)?,
            "test: no private pair to retire"
        );
        let native =
            owner.client.born_v3_account.as_ref().ok_or("test: external native account")?;
        let primary = owner.vault.primary_for_public_key(
            &native.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let now = custody::network_now()?;
        let record = primary.revoke_device(native.verified(), local.device_id(), now)?;
        let published = custody::pairing::PublishedHead {
            record_hash: object_hash(&record)?,
            epoch: record.body.device_set_epoch,
            record,
        };
        let state = LocalBusAccountState::disconnected(
            owner.client,
            owner.config,
            owner.manifest.principal_commitment.clone(),
        );
        // This is the exact production post-ack observer, not a simulated network ACK.
        // External local dispatch is independently tested to refuse PrimaryRequired.
        observe_published(&state, &owner.root.0, &published)?;
        assert!(
            !state.client.account_db()?.actor_state_exists(&private)?,
            "test: external denial retained private pair"
        );
        assert!(
            matches!(
                state.client.require_native_pair_device_not_revoked(),
                Err(SdkError::InboundRejected(_))
            ),
            "test: external denial did not fence current device"
        );
        assert!(
            state.client.current_custody_authority(local.root_commitment(), now)?.is_some(),
            "test: observer lost external human authority"
        );
        Ok(())
    }))
    .await
}
