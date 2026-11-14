// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real SDK sealing exercises the checked sender transcript and historical/current branch barrier.
use crate::{
    RamfluxClient,
    client::native_test_support::{Fixture, TestResult},
};
use prost::Message as _;
use ramflux_protocol::{
    contact_reach::{self as wire, Route, Submission, Traffic},
    custody, message as g,
};

struct Outgoing {
    source: Fixture,
    target: Fixture,
    message: crate::GatewayDirectMessage,
    inner: Vec<u8>,
    prekey: Option<ramflux_crypto::PrekeyBundle>,
    recipient: String,
}

async fn outgoing() -> TestResult<Outgoing> {
    let source = Fixture::new("reach-route-source").await?;
    let target = Fixture::new("reach-route-target").await?;
    let recipient = target.client.own_account_anchor()?;
    let own = source.client.own_account_anchor()?;
    let conversation = g::dm_scope::derive(&own, &recipient)?;
    source.client.account_db()?.write_transaction(|| {
        source.client.account_db()?.persist_client_record(
            "conversation",
            &conversation,
            &serde_json::json!({
                "id":conversation,"kind":"direct","group_id":null,
                "participant_roots":[own,recipient],
                "participants":[source.config.principal_id,target.config.principal_id],
            }),
        )?;
        Ok::<(), crate::SdkError>(())
    })?;
    let identity = source.client.allocate_generated_identity(
        &conversation,
        crate::custody::network_now()?.checked_mul(1000).ok_or("identity clock overflow")?,
        false,
    )?;
    let inner = RamfluxClient::encode_generated_inner(
        identity,
        &g::Content {
            value: Some(g::content::Value::Message(g::Message {
                text: "checked native sender transcript".into(),
                ..Default::default()
            })),
        },
    )?;
    let identity = g::Inner::decode(inner.as_slice())?.identity.ok_or("sealed identity")?;
    let material = source.material_for(&target)?;
    let message = crate::GatewayDirectMessage {
        conversation_id: conversation,
        message_id: ramflux_protocol::encode_base64url(identity.id),
        envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        source_principal_id: source.config.principal_id.clone(),
        sender_id: source.config.device_id.clone(),
        recipient_device_id: Some(target.config.device_id.clone()),
        recipient_principal_commitment: Some(recipient.clone()),
        target_delivery_id: target.config.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    Ok(Outgoing { source, target, message, inner, prekey: material.bundle, recipient })
}

async fn sealed() -> TestResult<(Fixture, ramflux_protocol::Envelope, String)> {
    let outgoing = outgoing().await?;
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let prepared = outgoing.source.client.prepare_reach_submission(
        &outgoing.source.config,
        &outgoing.message,
        &outgoing.inner,
        outgoing.prekey,
        crate::contact_reach::ReachSendIntent::Ordinary,
    )?;
    assert_eq!(
        prepared.route.body.traffic,
        Traffic::Dm,
        "the real constructor derives DM from the exact sealed Inner"
    );
    Ok((outgoing.source, prepared.envelope, outgoing.recipient))
}

#[tokio::test(flavor = "current_thread")]
async fn cr_inactive_reach_preview_refuses_before_pair_bootstrap() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), receive_preview()).await?
}

async fn receive_preview() -> TestResult {
    let outgoing = outgoing().await?;
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let prepared = outgoing.source.client.prepare_reach_submission(
        &outgoing.source.config,
        &outgoing.message,
        &outgoing.inner,
        outgoing.prekey,
        crate::contact_reach::ReachSendIntent::Ordinary,
    )?;
    outgoing.target.client.persist_fetched_identity_directory(&outgoing.source.manifest)?;
    let entry = crate::GatewayInboxEntry {
        inbox_seq: 1,
        forwarded: false,
        target_delivery_id: prepared.envelope.target_delivery_id.clone(),
        envelope: prepared.envelope,
        reach: Some(Box::new(wire::DeliveryReach {
            route: prepared.route,
            cost: prepared.cost,
            node_report_receipt: None,
        })),
    };
    let before = crate::contact_reach::group_test_support::sealing_state(&outgoing.target.client)?;
    assert!(
        matches!(
            outgoing.target.client.require_reach_entry_authority(&entry),
            Err(crate::SdkError::ReachRefused(wire::Reason::FeatureDisabled))
        ),
        "an inactive reach carrier cannot enter ordinary effects by silently ignoring its wrapper"
    );
    for _ in 0..2 {
        assert!(
            matches!(
                outgoing
                    .target
                    .client
                    .preview_reach_route(&entry, &outgoing.target.config.device_id),
                Err(crate::SdkError::ReachRefused(wire::Reason::FeatureDisabled))
            ),
            "the actual preview must stop at the inactive profile before speculative decryption"
        );
        assert_eq!(
            crate::contact_reach::group_test_support::sealing_state(&outgoing.target.client)?,
            before,
            "repeated inactive previews cannot commit or consume the incoming pair bootstrap"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_native_producer_rolls_back_sealing_when_final_sender_proof_fails() -> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cr_native_producer_rolls_back_sealing_when_final_sender_proof_fails_body(),
    )
    .await?
}
async fn cr_native_producer_rolls_back_sealing_when_final_sender_proof_fails_body() -> TestResult {
    let outgoing = outgoing().await?;
    let before = crate::contact_reach::group_test_support::sealing_state(&outgoing.source.client)?;
    let mut wrong_id = outgoing.message.clone();
    wrong_id.message_id = ramflux_protocol::encode_base64url([3; 32]);
    assert!(
        outgoing
            .source
            .client
            .prepare_reach_submission(
                &outgoing.source.config,
                &wrong_id,
                &outgoing.inner,
                outgoing.prekey.clone(),
                crate::contact_reach::ReachSendIntent::Ordinary,
            )
            .is_err(),
        "outbound receipt/history ownership cannot use a different logical ID from the sealed Inner"
    );
    assert_eq!(
        crate::contact_reach::group_test_support::sealing_state(&outgoing.source.client)?,
        before,
        "an identity mismatch cannot advance the pair or create history"
    );
    let mut changed = outgoing.source.config.clone();
    let branch = changed.device_branch.as_ref().ok_or("branch")?;
    changed.device_branch = Some(std::sync::Arc::new(ramflux_crypto::create_device_branch(
        &branch.principal_id,
        &branch.device_id,
        branch.device_epoch,
        [9; 32],
    )));
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let result = outgoing.source.client.prepare_reach_submission(
        &changed,
        &outgoing.message,
        &outgoing.inner,
        outgoing.prekey.clone(),
        crate::contact_reach::ReachSendIntent::Ordinary,
    );
    assert!(
        matches!(
            result,
            Err(crate::SdkError::Crypto(ramflux_crypto::CryptoError::Protocol(
                ramflux_protocol::ProtocolError::SignatureVerificationFailed
            )))
        ),
        "the final checked envelope signature rejects a config using an uncertified key"
    );
    assert_eq!(
        crate::contact_reach::group_test_support::sealing_state(&outgoing.source.client)?,
        before,
        "failed sealing retains neither ratchet advancement nor authored-history actor records"
    );
    let prepared = outgoing.source.client.prepare_reach_submission(
        &outgoing.source.config,
        &outgoing.message,
        &outgoing.inner,
        outgoing.prekey,
        crate::contact_reach::ReachSendIntent::Ordinary,
    )?;
    assert_eq!(
        prepared.envelope.envelope_id, outgoing.message.envelope_id,
        "the unchanged logical attempt remains sealable after rollback"
    );
    assert_ne!(
        crate::contact_reach::group_test_support::sealing_state(&outgoing.source.client)?,
        before,
        "successful preparation commits the real pair and authored-history state"
    );
    Ok(())
}
fn publication(source: &Fixture) -> TestResult<custody::CustodyAuthority> {
    Ok(source
        .client
        .current_custody_evidence(
            &source.client.own_account_anchor()?,
            crate::custody::network_now()?,
        )?
        .ok_or("source publication")?)
}
fn attach(
    envelope: &mut ramflux_protocol::Envelope,
    evidence: &custody::CustodyAuthority,
    at: u64,
) -> TestResult {
    let authority = ramflux_crypto::custody::verify_publication(evidence, at)?;
    let device = authority
        .envelope()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == envelope.source_device_id)
        .ok_or("source device")?;
    let branch = device.branch_certificate.as_ref().ok_or("source branch")?;
    envelope.ext.ext.insert("source_device_authority".into(), serde_json::json!({
        "custody_authority":evidence, "root_public_key":null, "signed_device_set":null,
        "principal_id":authority.envelope().body.principal_id, "device_id":device.device_id,
        "device_epoch":device.device_epoch, "branch_public_key":branch.body.branch_signing_public_key,
        "target_delivery_id":ramflux_protocol::qualified_device_id(&authority.envelope().body.account_anchor, &device.device_id)?, "revoked":false,
    }));
    Ok(())
}
fn submission(
    source: &Fixture,
    mut envelope: ramflux_protocol::Envelope,
    recipient: &str,
    evidence: &custody::CustodyAuthority,
) -> TestResult<Submission> {
    let issued_at = u64::try_from(envelope.created_at)?;
    attach(&mut envelope, evidence, issued_at)?;
    let root = &evidence.publication.record.body.account_anchor;
    let branch = source.client.device_branch.as_ref().ok_or("source branch key")?;
    let body = Route {
        version: 1,
        source: custody::DeviceRef {
            account_anchor: root.clone(),
            device_id: branch.device_id.clone(),
            device_epoch: branch.device_epoch,
        },
        recipient_root: recipient.into(),
        conversation_id: g::dm_scope::derive(root, recipient)?,
        traffic: Traffic::Dm,
        group: None,
        envelope_hash: custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &envelope)?,
        authority_head_hash: custody::object_hash(&evidence.publication.record)?,
        issued_at,
        expires_at: issued_at.checked_add(u64::from(envelope.ttl)).ok_or("retention overflow")?,
    };
    Ok(Submission {
        route: ramflux_crypto::contact_reach::sign_route(body, branch)?,
        envelope,
        cost: None,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn cr_native_route_verifies_real_sdk_transcript_and_unchanged_sealed_source_proof()
-> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cr_native_route_verifies_real_sdk_transcript_and_unchanged_sealed_source_proof_body(),
    )
    .await?
}
async fn cr_native_route_verifies_real_sdk_transcript_and_unchanged_sealed_source_proof_body()
-> TestResult {
    let (mut source, envelope, recipient) = sealed().await?;
    let original = publication(&source)?;
    let submission = submission(&source, envelope, &recipient, &original)?;
    let current =
        ramflux_crypto::custody::verify_publication(&original, crate::custody::network_now()?)?;
    ramflux_crypto::contact_reach::verify_current_source_submission(
        &submission,
        &current,
        crate::custody::network_now()?,
    )?;
    let _sibling = source.enroll_sibling("reach-route-second", "second").await?;
    let advanced = publication(&source)?;
    let current =
        ramflux_crypto::custody::verify_publication(&advanced, crate::custody::network_now()?)?;
    assert_ne!(
        custody::object_hash(current.envelope())?,
        submission.route.body.authority_head_hash,
        "the receiving verifier observes a newer current device-set head than the immutable route"
    );
    ramflux_crypto::contact_reach::verify_current_source_submission(
        &submission,
        &current,
        crate::custody::network_now()?,
    )?;
    let mut changed = submission.clone();
    changed.envelope.encrypted_payload.push('A');
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &changed,
            &current,
            crate::custody::network_now()?
        )
        .is_err(),
        "changed ciphertext cannot borrow the signed route or checked payload hash"
    );
    let mut changed = submission;
    changed
        .envelope
        .ext
        .ext
        .get_mut("source_device_authority")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("source proof object")?
        .insert("revoked".into(), serde_json::Value::Bool(true));
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &changed,
            &current,
            crate::custody::network_now()?
        )
        .is_err(),
        "node metadata included in W cannot be substituted after sealing"
    );
    Ok(())
}

fn leased(
    evidence: &custody::CustodyAuthority,
    key: &ramflux_crypto::custody::SelfSigningKey,
    expires: u64,
    issued: u64,
) -> TestResult<custody::CustodyAuthority> {
    certificate_version(evidence, key, issued, |branch| branch.expires_at = expires)
}
fn certificate_version(
    evidence: &custody::CustodyAuthority,
    key: &ramflux_crypto::custody::SelfSigningKey,
    issued: u64,
    edit: impl FnOnce(&mut custody::BranchCertificate),
) -> TestResult<custody::CustodyAuthority> {
    let mut body = evidence.publication.record.body.clone();
    body.device_set_epoch =
        body.device_set_epoch.checked_add(1).ok_or("device-set epoch overflow")?;
    body.previous_record_hash = Some(custody::object_hash(&evidence.publication.record)?);
    body.issued_at = issued;
    let device = body.devices.first_mut().ok_or("source device")?;
    let mut branch = device.branch_certificate.as_ref().ok_or("source certificate")?.body.clone();
    edit(&mut branch);
    branch.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    device.branch_certificate = Some(key.certify_branch(branch)?);
    Ok(custody::CustodyAuthority {
        publication: custody::Publication {
            record: key.sign_record(body)?,
            compacted_ids: evidence.publication.compacted_ids.clone(),
        },
        custodian_publication: evidence.custodian_publication.clone(),
    })
}

fn resign(source: &Fixture, submission: &mut Submission) -> TestResult {
    let branch = source.client.device_branch.as_ref().ok_or("source branch")?;
    submission.envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(branch, &submission.envelope)?;
    submission.route.body.envelope_hash =
        custody::framed_hash(wire::ENVELOPE_HASH_DOMAIN, &submission.envelope)?;
    submission.route =
        ramflux_crypto::contact_reach::sign_route(submission.route.body.clone(), branch)?;
    Ok(())
}

fn invalid_durable_inputs(
    source: &Fixture,
    original: &Submission,
    current: &ramflux_crypto::custody::VerifiedRecord,
    issued: u64,
) -> TestResult {
    let mut excessive = original.clone();
    excessive.envelope.ttl =
        ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS_U32.checked_add(1).ok_or("ttl overflow")?;
    excessive.route.body.expires_at =
        issued.checked_add(u64::from(excessive.envelope.ttl)).ok_or("expiry overflow")?;
    resign(source, &mut excessive)?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &excessive, current, issued
        )
        .is_err(),
        "even a correctly signed wrapper cannot extend the existing durable TTL cap"
    );
    let mut foreign_copy = original.clone();
    foreign_copy.route.body.traffic = Traffic::OwnCopy;
    resign(source, &mut foreign_copy)?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &foreign_copy,
            current,
            issued
        )
        .is_err(),
        "own-copy labels never authorize a foreign recipient root"
    );
    let mut ephemeral = original.clone();
    ephemeral.envelope.delivery_mode = Some("ephemeral".into());
    ephemeral.envelope.ttl = 5;
    ephemeral.route.body.expires_at = issued.checked_add(5).ok_or("ephemeral expiry overflow")?;
    resign(source, &mut ephemeral)?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &ephemeral, current, issued
        )
        .is_err(),
        "a valid sender cannot spool an explicitly ephemeral envelope behind a durable DM label"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_native_route_requires_current_sync_scope_and_preserves_ttl_bounds() -> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cr_native_route_requires_current_sync_scope_and_preserves_ttl_bounds_body(),
    )
    .await?
}
async fn cr_native_route_requires_current_sync_scope_and_preserves_ttl_bounds_body() -> TestResult {
    let (source, envelope, recipient) = sealed().await?;
    let evidence = publication(&source)?;
    let issued = u64::try_from(envelope.created_at)?;
    let original = submission(&source, envelope, &recipient, &evidence)?;
    let current = ramflux_crypto::custody::verify_publication(&evidence, issued)?;
    invalid_durable_inputs(&source, &original, &current, issued)?;
    let own = source.client.owned_device_identity()?;
    let mut own_copy = original;
    own_copy.envelope.target_delivery_id = own.storage_key().into();
    own_copy.route.body.recipient_root = own.root_commitment().into();
    own_copy.route.body.conversation_id = "own-copy".into();
    own_copy.route.body.traffic = Traffic::OwnCopy;
    resign(&source, &mut own_copy)?;
    // This checks outer authorization, not the opaque inner content's own-copy semantics.
    ramflux_crypto::contact_reach::verify_current_source_submission(&own_copy, &current, issued)?;
    let key = source.vault.primary_for_public_key(
        &evidence.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let restricted = certificate_version(&evidence, &key, issued, |branch| {
        branch.capabilities.retain(|capability| capability != "sync");
    })?;
    let restricted = ramflux_crypto::custody::verify_publication(&restricted, issued)?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(
            &own_copy,
            &restricted,
            issued
        )
        .is_err(),
        "a currently message-only branch cannot borrow its historical sync capability"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_native_route_expired_original_lease_needs_live_same_key_and_rejects_revocation()
-> TestResult {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        cr_native_route_expired_original_lease_needs_live_same_key_and_rejects_revocation_body(),
    )
    .await?
}
async fn cr_native_route_expired_original_lease_needs_live_same_key_and_rejects_revocation_body()
-> TestResult {
    let (source, envelope, recipient) = sealed().await?;
    let issued = u64::try_from(envelope.created_at)?;
    let evidence = publication(&source)?;
    let key = source.vault.primary_for_public_key(
        &evidence.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let original = leased(&evidence, &key, issued.checked_add(30).ok_or("old lease")?, issued)?;
    let submission = submission(&source, envelope, &recipient, &original)?;
    let renewed = leased(
        &original,
        &key,
        issued.checked_add(3600).ok_or("renewed lease")?,
        issued.checked_add(1).ok_or("renewal time")?,
    )?;
    let now = issued.checked_add(600).ok_or("delayed verification time")?;
    ramflux_crypto::contact_reach::verify_original_source_submission(&submission, now)?;
    let current = ramflux_crypto::custody::verify_publication(&renewed, now)?;
    ramflux_crypto::contact_reach::verify_current_source_submission(&submission, &current, now)?;
    let expired = ramflux_crypto::custody::verify_publication(&original, issued)?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(&submission, &expired, now)
            .is_err(),
        "historical proof alone cannot satisfy current sending authority"
    );
    let revoked = key.revoke_device(&current, &submission.route.body.source.device_id, now)?;
    let revoked = ramflux_crypto::custody::verify_publication(
        &custody::CustodyAuthority {
            publication: custody::Publication { record: revoked, compacted_ids: None },
            custodian_publication: None,
        },
        now,
    )?;
    assert!(
        ramflux_crypto::contact_reach::verify_current_source_submission(&submission, &revoked, now)
            .is_err(),
        "a genuine old sender signature cannot override a current device revocation"
    );
    ramflux_crypto::contact_reach::verify_original_source_submission(&submission, now)?;
    let mut changed = submission;
    changed.route.signature = ramflux_protocol::encode_base64url([5; 64]);
    assert!(
        ramflux_crypto::contact_reach::verify_original_source_submission(&changed, now).is_err(),
        "bad immutable W bytes are rejected independently of any missing or revoked current cache"
    );
    Ok(())
}
