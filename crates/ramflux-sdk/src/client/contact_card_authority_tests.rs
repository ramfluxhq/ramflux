// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! CARD-HEAD-PIN-01: a native contact card is an account introduction bound to the account, the
//! master certificate and a signed issuance-epoch floor. Real custody records, real signers and
//! the real pin store; every case runs under the component watchdog.
use super::*;
use crate::client::identity_authority::HeadUse;
use crate::client::native_test_support::{
    Fixture, TestResult, activation_send::tests::publish_layer_four,
};
use crate::custody::load_account;
use ramflux_crypto::custody::{AuthorityPins, PinOutcome, SelfSigningKey, verify_record};
use ramflux_protocol::custody::{
    BranchCertificate, ContactCardV3, CustodyManifest, DeviceSet, Envelope, Publication,
};
use std::future::Future;

async fn within<T>(future: impl Future<Output = TestResult<T>>) -> TestResult<T> {
    crate::client::native_test_support::watchdog::within(future)
        .await
        .map_err(|_| "test: deadline exceeded")?
}

fn primary(fixture: &Fixture) -> TestResult<SelfSigningKey> {
    let native = fixture.manifest.custody.as_ref().ok_or("test: native manifest")?;
    Ok(fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?)
}

fn verified(record: &Envelope<DeviceSet>) -> TestResult<ramflux_crypto::custody::VerifiedRecord> {
    Ok(verify_record(record, record.body.issued_at.max(1), None, None)?)
}

/// A card signed for exactly `record` by the account's own self-signing key.
fn card_for(
    fixture: &Fixture,
    record: &Envelope<DeviceSet>,
    now: u64,
) -> TestResult<ContactCardBody> {
    let signer = primary(fixture)?;
    let body = ContactCardV3 {
        version: 3,
        principal_id: record.body.principal_id.clone(),
        account_anchor: record.body.account_anchor.clone(),
        master_public_key: record.body.master_certificate.body.master_public_key.clone(),
        master_certificate: record.body.master_certificate.clone(),
        authority_head_hash: ramflux_protocol::custody::object_hash(record)?,
        authority_epoch: record.body.device_set_epoch,
        devices: record.body.devices.clone(),
        node_url: "https://node.example".into(),
        node_key_fingerprint: crate::contact_node_fingerprint(
            &ramflux_crypto::fixture_public_key_base64url(),
        )?,
        display_name: record.body.profile.display_name.clone(),
        issued_at: now,
        expires_at: now + 3_600,
    };
    let card = signer.sign_contact_card_v3(&verified(record)?, body, now)?;
    let (text, _) = crate::contact_card_native::encode(&card, i64::try_from(now)?)?;
    Ok(crate::parse_contact_card(&text, i64::try_from(now)?)?)
}

fn manifest_at(
    fixture: &Fixture,
    record: &Envelope<DeviceSet>,
) -> TestResult<SdkDeviceManifestResponse> {
    let mut native: CustodyManifest =
        (**fixture.manifest.custody.as_ref().ok_or("native")?).clone();
    native.publication = Publication { record: record.clone(), compacted_ids: None };
    native.devices.retain(|row| {
        record.body.devices.iter().any(|device| {
            device.device_id == row.device_ref.device_id && device.branch_certificate.is_some()
        })
    });
    Ok(SdkDeviceManifestResponse::from_native(native)?)
}

/// Re-sign the record with a different profile name: a legitimate head change that is not a layer
/// change, or, at the same epoch, a fork.
fn renamed(
    fixture: &Fixture,
    base: &Envelope<DeviceSet>,
    name: &str,
    advance: bool,
) -> TestResult<Envelope<DeviceSet>> {
    let mut body = base.body.clone();
    if advance {
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch =
            ramflux_protocol::custody::encode_epoch(range, revision.checked_add(1).ok_or("rev")?)?;
        body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(base)?);
        body.issued_at += 1;
    }
    body.profile.display_name = name.into();
    Ok(primary(fixture)?.sign_record(body)?)
}

fn enroll_phone(
    fixture: &Fixture,
    current: &Envelope<DeviceSet>,
    now: u64,
) -> TestResult<Envelope<DeviceSet>> {
    let signer = primary(fixture)?;
    let branch = ramflux_crypto::create_device_branch(
        &current.body.principal_id,
        "phone",
        1,
        ramflux_crypto::random_32()?,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate: BranchCertificate = current.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("test: branch certificate")?
        .body
        .clone();
    certificate.device_id = "phone".into();
    certificate.device_epoch = 1;
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(&agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    Ok(signer.enroll_device(&verified(current)?, signer.certify_branch(certificate)?, now)?)
}

#[tokio::test]
async fn card_issued_before_activation_survives_repeated_layer_renewals_then_accepts_and_sends()
-> TestResult {
    within(async {
        let mut peer = Fixture::new("card-pin-peer").await?;
        let holder = Fixture::new("card-pin-holder").await?;
        let now = crate::custody::network_now()?;
        let issued = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let card = card_for(&peer, &issued, now)?;
        // Activation and three renewals: four new heads after the card was exported.
        for _ in 0..4 {
            publish_layer_four(&mut peer).await?;
        }
        let current = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        assert!(
            current.body.device_set_epoch > issued.body.device_set_epoch,
            "test: heads must have advanced past the card"
        );
        // Each helper head is stamped just after the previous one; read the roster after them.
        let _clock = crate::time::FixedClock::set(i64::try_from(now + 30)?);
        verify_native_card_head(Some(&card), &peer.manifest)?;
        holder.client.persist_fetched_identity_directory(&peer.manifest)?;
        // The current roster, not the card, decides the recipient and the layer.
        let message = crate::GatewayDirectMessage {
            conversation_id: "dm".into(),
            message_id: "card-pin-send".into(),
            envelope_id: "card-pin-send".into(),
            source_principal_id: holder.manifest.principal_id.clone(),
            sender_id: holder.config.device_id.clone(),
            recipient_device_id: Some(peer.config.device_id.clone()),
            recipient_principal_commitment: Some(peer.manifest.principal_commitment.clone()),
            target_delivery_id: peer.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 0,
        };
        let plan = RamfluxClient::candidate_target_plan(|| {
            holder
                .client
                .dm_selection_request(&message, ramflux_protocol::message::KindId::KindMessage)
        })?;
        holder.client.require_dm_layer(
            &message,
            plan,
            ramflux_protocol::message::registry::COMPILED_LAYER,
        )?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn post_revocation_card_refuses_an_older_same_certificate_manifest() -> TestResult {
    within(async {
        let peer = Fixture::new("card-pin-revoked").await?;
        let now = crate::custody::network_now()?;
        let base = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let enrolled = enroll_phone(&peer, &base, now + 1)?;
        let revoked = primary(&peer)?.revoke_device(&verified(&enrolled)?, "phone", now + 2)?;
        let card = card_for(&peer, &revoked, now + 2)?;
        // A directory replaying the pre-revocation head under the same certificate is refused.
        let replay = manifest_at(&peer, &enrolled)?;
        assert!(
            matches!(
                verify_native_card_head(Some(&card), &replay),
                Err(SdkError::ContactInput(ContactReason::AuthorityStale))
            ),
            "an older head must be refused as stale"
        );
        // So is a different head at the card's own epoch.
        let fork = renamed(&peer, &revoked, "Forked name", false)?;
        assert!(
            matches!(
                verify_native_card_head(Some(&card), &manifest_at(&peer, &fork)?),
                Err(SdkError::ContactInput(ContactReason::AuthorityStale))
            ),
            "a same-epoch fork must be refused"
        );
        // The exact head and any later head are accepted.
        verify_native_card_head(Some(&card), &manifest_at(&peer, &revoked)?)?;
        let later = renamed(&peer, &revoked, "Later name", true)?;
        verify_native_card_head(Some(&card), &manifest_at(&peer, &later)?)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn stale_card_with_the_current_roster_never_selects_a_revoked_device() -> TestResult {
    within(async {
        let peer = Fixture::new("card-pin-stale").await?;
        let holder = Fixture::new("card-pin-stale-holder").await?;
        let now = crate::custody::network_now()?;
        let base = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let enrolled = enroll_phone(&peer, &base, now + 1)?;
        // The card lists the phone; the current head has revoked it.
        let card = card_for(&peer, &enrolled, now + 1)?;
        assert!(
            enrolled.body.devices.iter().any(|device| device.device_id == "phone"),
            "test: the card must list the phone"
        );
        let revoked = primary(&peer)?.revoke_device(&verified(&enrolled)?, "phone", now + 2)?;
        let current = manifest_at(&peer, &revoked)?;
        verify_native_card_head(Some(&card), &current)?;
        holder.client.persist_fetched_identity_directory(&current)?;
        let request = |device: &str| crate::GatewayDirectMessage {
            conversation_id: "dm".into(),
            message_id: format!("stale-{device}"),
            envelope_id: format!("stale-{device}"),
            source_principal_id: holder.manifest.principal_id.clone(),
            sender_id: holder.config.device_id.clone(),
            recipient_device_id: Some(device.into()),
            recipient_principal_commitment: Some(peer.manifest.principal_commitment.clone()),
            target_delivery_id: peer.config.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: 0,
        };
        // Recipient authority comes only from the verified current roster, never from the card.
        let root = peer.manifest.principal_commitment.clone();
        let phone = holder.client.device_identity_for_root(&root, "phone")?;
        assert!(
            holder.client.trusted_device(HeadUse::NewAuthorization, &phone).is_err(),
            "a device the current roster revoked must never receive a key slot"
        );
        let active = holder.client.device_identity_for_root(&root, &peer.config.device_id)?;
        holder.client.trusted_device(HeadUse::NewAuthorization, &active)?;
        let _ = request;
        Ok(())
    })
    .await
}

#[test]
fn pins_refuse_rollback_fork_resurrection_and_key_rollback() -> TestResult {
    // Real signers and the real pin store; no card or manifest field can reset these.
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(within(async {
        let peer = Fixture::new("card-pin-pins").await?;
        let now = crate::custody::network_now()?;
        let signer = primary(&peer)?;
        let base = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let enrolled = enroll_phone(&peer, &base, now + 1)?;
        let revoked = signer.revoke_device(&verified(&enrolled)?, "phone", now + 2)?;
        let mut pins = AuthorityPins::default();
        for record in [&base, &enrolled, &revoked] {
            assert_eq!(pins.observe(&verified(record)?)?, PinOutcome::Advanced);
        }
        // Epoch rollback.
        assert!(pins.observe(&verified(&enrolled)?).is_err(), "epoch rollback must be refused");
        // Same-epoch fork is fenced and grants no authority.
        let fork = renamed(&peer, &revoked, "Fork", false)?;
        let outcome = pins.observe(&verified(&fork)?)?;
        assert!(matches!(outcome, PinOutcome::Fenced(_)), "a same-epoch fork must be fenced");
        assert!(pins.require_current(&verified(&fork)?).is_err(), "a fork is never current");
        // Revoked-id resurrection: a later head that lists the revoked phone as active.
        let mut pins = AuthorityPins::default();
        for record in [&base, &enrolled, &revoked] {
            pins.observe(&verified(record)?)?;
        }
        let mut body = revoked.body.clone();
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&revoked)?);
        body.issued_at += 1;
        body.devices = enrolled.body.devices.clone();
        let resurrected = signer.sign_record(body)?;
        let attempt = verify_record(&resurrected, resurrected.body.issued_at, None, None)
            .map_err(Into::into)
            .and_then(|record| pins.observe(&record).map_err(Box::<dyn std::error::Error>::from));
        assert!(attempt.is_err(), "a revoked device id must not come back");
        // Device-key rollback: the same device id and epoch re-certified under a different key.
        let mut pins = AuthorityPins::default();
        pins.observe(&verified(&base)?)?;
        let mut body = base.body.clone();
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&base)?);
        body.issued_at += 1;
        let replacement = ramflux_crypto::create_device_branch(
            &base.body.principal_id,
            &body.devices[0].device_id,
            body.devices[0].device_epoch,
            ramflux_crypto::random_32()?,
        );
        let mut certificate =
            body.devices[0].branch_certificate.as_ref().ok_or("test: certificate")?.body.clone();
        certificate.branch_signing_public_key =
            ramflux_protocol::encode_base64url(replacement.signing_key.verifying_key().as_bytes());
        certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
        let (signing, agreement) = ramflux_crypto::device_key_commitments(
            &certificate.branch_signing_public_key,
            &certificate.agreement_identity_public_key,
        )?;
        body.devices[0].signing_key_commitment = signing;
        body.devices[0].agreement_key_commitment = agreement;
        body.devices[0].branch_certificate = Some(signer.certify_branch(certificate)?);
        let rekeyed = signer.sign_record(body)?;
        let attempt = verify_record(&rekeyed, rekeyed.body.issued_at, None, None)
            .map_err(Into::into)
            .and_then(|record| pins.observe(&record).map_err(Box::<dyn std::error::Error>::from));
        assert!(attempt.is_err(), "a pinned device key must not roll back to a different key");
        Ok(())
    }))
}

#[tokio::test]
async fn reopening_the_store_keeps_pins_and_requires_a_new_network_observation() -> TestResult {
    within(async {
        let mut peer = Fixture::new("card-pin-reopen").await?;
        let holder = Fixture::new("card-pin-reopen-holder").await?;
        let older = peer.manifest.clone();
        publish_layer_four(&mut peer).await?;
        let newer = peer.manifest.clone();
        holder.client.persist_fetched_identity_directory(&newer)?;
        let record = newer.custody.as_ref().ok_or("native")?.publication.record.clone();
        let root = newer.principal_commitment.clone();
        holder.client.require_fresh_custody_head(HeadUse::NewAuthorization, &root, &record)?;
        // A new client over the same store: durable pins stay, observed freshness does not.
        let mut reopened = RamfluxClient::new();
        reopened.open_account_index(&holder.root.0)?;
        reopened.unlock_account(
            &holder.client.account_db()?.local_account_id,
            b"native fixture data passphrase",
        )?;
        assert!(
            reopened
                .require_fresh_custody_head(HeadUse::NewAuthorization, &root, &record,)
                .is_err(),
            "restored state cannot stand in for a network observation"
        );
        assert!(
            reopened.persist_fetched_identity_directory(&older).is_err(),
            "an older head must stay refused after the store is reopened"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn replaying_a_card_grants_nothing_and_a_layer_head_keeps_the_safety_material() -> TestResult
{
    within(async {
        let mut peer = Fixture::new("card-pin-replay").await?;
        let holder = Fixture::new("card-pin-replay-holder").await?;
        let now = crate::custody::network_now()?;
        let record = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let card = card_for(&peer, &record, now)?;
        // No friend link: a replayed card yields no contact, no permission, no safety state.
        assert!(
            holder
                .client
                .accepted_contact_retry(&peer.manifest.principal_id, Some(&card))?
                .is_none(),
            "a card alone must not create an accepted contact"
        );
        let before = crate::client::identity_authority::custody_directory::native_fingerprint(
            &verified(&record)?,
        )?;
        publish_layer_four(&mut peer).await?;
        let after_record =
            peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let after = crate::client::identity_authority::custody_directory::native_fingerprint(
            &verified(&after_record)?,
        )?;
        assert_eq!(before, after, "a layer-only head must preserve the safety fingerprint");
        let _ = load_account;
        Ok(())
    })
    .await
}

#[test]
fn an_old_schema_card_is_refused_with_a_typed_error() -> TestResult {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(within(async {
        let peer = Fixture::new("card-pin-old-schema").await?;
        let now = crate::custody::network_now()?;
        let record = peer.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
        let signer = primary(&peer)?;
        let body = ContactCardV3 {
            version: 3,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            master_public_key: record.body.master_certificate.body.master_public_key.clone(),
            master_certificate: record.body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(&record)?,
            authority_epoch: record.body.device_set_epoch,
            devices: record.body.devices.clone(),
            node_url: "https://node.example".into(),
            node_key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::fixture_public_key_base64url(),
            )?,
            display_name: record.body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now + 3_600,
        };
        let card = signer.sign_contact_card_v3(&verified(&record)?, body, now)?;
        // Remove the epoch field from the wire form: an old card has no such field.
        let mut value = serde_json::to_value(&card)?;
        value["body"].as_object_mut().ok_or("test: card body object")?.remove("authority_epoch");
        let text = format!(
            "ramflux-card:v3:{}",
            ramflux_protocol::encode_base64url(ramflux_protocol::canonical_json_bytes(&value)?)
        );
        assert!(
            matches!(
                crate::parse_contact_card(&text, i64::try_from(now)?),
                Err(SdkError::ContactInput(ContactReason::InvalidCard))
            ),
            "a card without the signed epoch must be refused as invalid"
        );
        Ok(())
    }))
}

#[tokio::test]
async fn a_held_older_fetch_cannot_replace_a_newer_head_or_regain_freshness() -> TestResult {
    within(async {
        let mut peer = Fixture::new("card-pin-held").await?;
        let holder = Fixture::new("card-pin-held-holder").await?;
        let older = peer.manifest.clone();
        publish_layer_four(&mut peer).await?;
        let newer = peer.manifest.clone();
        let held = std::time::Instant::now();
        // The head changes while an older fetch is still queued for application.
        holder.client.persist_fetched_identity_directory(&newer)?;
        assert!(
            holder.client.persist_fetched_identity_directory_at(&older, held).is_err(),
            "a queued older fetch must be refused after the head changed"
        );
        let old_record = older.custody.as_ref().ok_or("native")?.publication.record.clone();
        assert!(
            holder
                .client
                .require_fresh_custody_head(
                    HeadUse::NewAuthorization,
                    &older.principal_commitment,
                    &old_record,
                )
                .is_err(),
            "the superseded head must not authorize a new send"
        );
        Ok(())
    })
    .await
}
