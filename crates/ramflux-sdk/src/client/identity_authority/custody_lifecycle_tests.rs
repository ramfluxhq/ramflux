// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native ratchets retire under signed denials, even when optional prekeys are stale.
use crate::client::native_test_support::{Fixture, TestResult};

fn pair(local: &Fixture, remote: &Fixture) -> TestResult<String> {
    let local_ref = local.client.owned_device_identity()?;
    let remote_ref = remote.client.owned_device_identity()?;
    let bundle = remote.client.load_x3dh_private_state(&remote_ref)?.bundle;
    let hash = crate::dm::prekey_bundle_hash(&bundle)?;
    let message = crate::GatewayDirectMessage {
        conversation_id: "native-retirement".into(),
        message_id: "native-retirement".into(),
        envelope_id: "native-retirement".into(),
        source_principal_id: local.manifest.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(remote.manifest.principal_commitment.clone()),
        target_delivery_id: remote_ref.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let (session, _) =
        local.client.create_send_dm_session_from_bundle(&message, "primary", bundle, "primary")?;
    local.client.persist_pair(&local_ref, &remote_ref, &hash, &session)?;
    Ok(format!("dm-pair/session/{}", session.session_id))
}

#[tokio::test]
async fn native_revocation_retires_real_pairs_before_bad_prekeys_and_preserves_other_roots()
-> TestResult {
    let local = Fixture::new("native-retirement-local").await?;
    let target = Fixture::new("native-retirement-peer").await?;
    let other = Fixture::new("native-retirement-other").await?;
    local.client.persist_identity_directory(&target.manifest)?;
    local.client.persist_identity_directory(&other.manifest)?;
    local.client.establish_friend_link(
        "native-retirement-link",
        &local.manifest.principal_commitment,
        &target.manifest.principal_commitment,
    )?;
    local.client.mark_contact_safety_verified(&target.manifest.principal_commitment, "primary")?;
    let affected = pair(&local, &target)?;
    let unaffected = pair(&local, &other)?;
    let db = local.client.account_db()?;
    let snapshot = db.load_actor_state::<serde_json::Value>(&affected)?.ok_or("private pair")?;
    let pair_key = crate::RamfluxClient::pair_key(
        &local.client.owned_device_identity()?,
        &target.client.owned_device_identity()?,
    )?;
    let floor = format!("{pair_key}/bootstrap-high-water/retirement-owner");
    db.persist_actor_state(&floor, &101_u64)?;
    let mut native = target.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = target.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let current = local
        .client
        .current_custody_authority(
            &target.manifest.principal_commitment,
            crate::custody::network_now()?,
        )?
        .ok_or("authority")?;
    native.publication.record =
        primary.revoke_device(&current, "primary", crate::custody::network_now()?)?;
    // Deliberately keep an advertisement for the now-revoked branch. Its rejection must
    // not prevent the independently authenticated denial from retiring private state.
    assert!(
        local
            .client
            .observe_custody_manifest(
                &native,
                &target.manifest.principal_commitment,
                crate::custody::network_now()?
            )
            .is_err()
    );
    assert!(!db.actor_state_exists(&affected)?);
    assert!(db.actor_state_exists(&unaffected)?);
    assert_eq!(db.load_actor_state::<u64>(&floor)?, Some(101));
    assert_eq!(
        local
            .client
            .contact_safety_number(&target.manifest.principal_commitment)?
            .verification_state,
        "verification_stale"
    );
    let row =
        crate::bus::read_model::row(&local.client, "identity", &target.manifest.principal_id)?;
    assert_eq!(row["safety_state"], "verification_stale");
    native.devices.clear();
    // A previously pinned denial still erases private state reintroduced by stale data.
    db.persist_actor_state(&affected, &snapshot)?;
    local.client.observe_custody_manifest(
        &native,
        &target.manifest.principal_commitment,
        crate::custody::network_now()?,
    )?;
    assert!(!db.actor_state_exists(&affected)?);
    assert!(db.actor_state_exists(&unaffected)?);
    assert_stale_native_snapshot_is_inert(&local, &target)?;
    Ok(())
}

#[tokio::test]
async fn native_local_revocation_erases_pairs_when_peer_payload_is_unavailable() -> TestResult {
    let local = Fixture::new("native-local-denial").await?;
    let peer = Fixture::new("native-unavailable-peer").await?;
    local.client.persist_identity_directory(&peer.manifest)?;
    let private = pair(&local, &peer)?;
    local.client.retire_custody_directory_payload(&peer.manifest.principal_commitment)?;
    let mut native = local.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = local.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let current = local
        .client
        .current_custody_authority(
            &local.manifest.principal_commitment,
            crate::custody::network_now()?,
        )?
        .ok_or("authority")?;
    native.publication.record =
        primary.revoke_device(&current, "primary", crate::custody::network_now()?)?;
    native.devices.clear();
    local.client.observe_custody_manifest(
        &native,
        &local.manifest.principal_commitment,
        crate::custody::network_now()?,
    )?;
    assert!(!local.client.account_db()?.actor_state_exists(&private)?);
    assert!(
        local
            .client
            .require_current_device_authorization(&local.client.owned_device_identity()?)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn native_message_scope_withdrawal_erases_pairs_without_permanent_device_revocation()
-> TestResult {
    let local = Fixture::new("native-scope-local").await?;
    let peer = Fixture::new("native-scope-peer").await?;
    local.client.persist_identity_directory(&peer.manifest)?;
    let private = pair(&local, &peer)?;
    let identity = peer.client.owned_device_identity()?;
    let mut native = peer.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = peer.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    let mut certificate = body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
    certificate.capabilities.retain(|scope| scope != "message");
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    body.devices[0].branch_certificate = Some(primary.certify_branch(certificate)?);
    native.publication.record = primary.sign_record(body)?;
    native.devices.clear();
    local.client.observe_custody_manifest(
        &native,
        &peer.manifest.principal_commitment,
        crate::custody::network_now()?,
    )?;
    assert!(!local.client.account_db()?.actor_state_exists(&private)?);
    assert!(local.client.require_current_device_authorization(&identity).is_err());
    assert_ne!(
        local
            .client
            .account_db()?
            .load_actor_state::<bool>(&crate::RamfluxClient::device_revocation_key(&identity))?,
        Some(true)
    );
    Ok(())
}

fn assert_stale_native_snapshot_is_inert(local: &Fixture, peer: &Fixture) -> TestResult {
    let anchor = &peer.manifest.principal_commitment;
    assert!(local.client.directory_snapshot_is_obsolete(&peer.manifest)?);
    let link = local.client.account_db()?.friend_link("native-retirement-link")?;
    let mut contact = b"ramflux.own_contact.v1\n".to_vec();
    contact.extend(serde_json::to_vec(&serde_json::json!({
        "manifest": peer.manifest, "link": link,
    }))?);
    let history = serde_json::from_value::<crate::own_device_sync::SdkOwnDeviceHistoryBundle>(
        serde_json::json!({
            "schema":"ramflux.own_device.history.v1", "version":1,
            "principal_commitment":local.manifest.principal_commitment,
            "source_device_id":"sibling", "target_device_id":"primary", "snapshot_id":"stale-native",
            "messages":[], "dm_sessions":[], "groups":[], "sender_key_distributions_base64":[],
            "group_member_pins":[{"group_id":"stale-group", "device_id":"primary",
                "signing_public_key":peer.manifest.devices[0].branch_public_key,
                "principal_id":peer.manifest.principal_id, "principal_commitment":anchor}],
            "device_manifests":[peer.manifest],
            "accepted_contacts":[ramflux_protocol::encode_base64url(&contact)],
        }),
    )?;
    // The containing own-device envelope is authenticated by the caller. Its old but valid
    // public snapshot must never overwrite a newer denial, even after payload eviction.
    local.client.restore_own_history_authority(&history)?;
    local.client.retire_custody_directory_payload(anchor)?;
    assert!(local.client.directory_snapshot_is_obsolete(&peer.manifest)?);
    local.client.restore_own_history_authority(&history)?;
    let native = peer.manifest.custody.as_ref().ok_or("native")?;
    let old = ramflux_crypto::custody::verify_record(
        &native.publication.record,
        crate::custody::network_now()?,
        None,
        None,
    )?;
    let identity = ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&old, "primary")?;
    assert_eq!(
        local
            .client
            .account_db()?
            .load_actor_state::<bool>(&crate::RamfluxClient::device_revocation_key(&identity),)?,
        Some(true)
    );
    assert!(
        local.client.current_custody_authority(anchor, crate::custody::network_now()?).is_err()
    );
    Ok(())
}
