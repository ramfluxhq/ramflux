// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native sent-copy admission follows certified sync membership without root private keys.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_own_sent_admission_tracks_enrollment_scope_and_revocation() -> TestResult {
    let own = Fixture::new("native-own-sent").await?;
    assert!(own.client.identity_root.is_none());
    assert!(!own.client.own_sent_has_siblings()?);
    let staged = std::cell::Cell::new(false);
    assert!(
        own.client
            .queue_own_sent_copy("no-sibling", || {
                staged.set(true);
                Ok("unexpected staging".into())
            })
            .is_none()
    );
    assert!(!staged.get());
    assert_eq!(own.client.account_db()?.actor_state_usage("own-device/")?.0, 0);
    let mut native = own.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = own.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let now = crate::custody::network_now()?;
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    let branch = ramflux_crypto::create_device_branch(
        &own.manifest.principal_id,
        "sibling",
        1,
        ramflux_crypto::random_32()?,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(ramflux_crypto::random_32()?);
    let mut certificate = native.publication.record.body.devices[0]
        .branch_certificate
        .as_ref()
        .ok_or("certificate")?
        .body
        .clone();
    certificate.device_id = "sibling".into();
    certificate.branch_signing_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().as_bytes());
    certificate.agreement_identity_public_key =
        ramflux_protocol::encode_base64url(agreement.public);
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    native.publication.record =
        primary.enroll_device(&current, primary.certify_branch(certificate)?, now)?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(own.client.own_sent_has_siblings()?);
    assert!(own.client.local_own_copy_manifest().is_err(), "old cached roster must refresh");
    assert_eq!(
        own.client.queue_own_sent_copy("sibling", || Ok("ticket".into())),
        Some("ticket".into())
    );
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch += 1;
    let entry =
        body.devices.iter_mut().find(|entry| entry.device_id == "sibling").ok_or("sibling")?;
    let mut certificate = entry.branch_certificate.as_ref().ok_or("certificate")?.body.clone();
    certificate.capabilities.retain(|scope| scope != "sync");
    certificate.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    entry.branch_certificate = Some(primary.certify_branch(certificate)?);
    native.publication.record = primary.sign_record(body)?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(!own.client.own_sent_has_siblings()?, "message scope must not replace sync");
    let current =
        ramflux_crypto::custody::verify_record(&native.publication.record, now, None, None)?;
    native.publication.record = primary.revoke_device(&current, "sibling", now)?;
    own.client.observe_custody_manifest(&native, &own.manifest.principal_commitment, now)?;
    assert!(!own.client.own_sent_has_siblings()?);
    Ok(())
}

#[tokio::test]
async fn native_live_sent_copy_keeps_a_private_replay_claim_after_deletion() -> TestResult {
    let own = Fixture::new("native-copy-deletion").await?;
    let source = own.client.owned_device_identity()?;
    let db = own.client.account_db()?;
    let ciphertext = b"authenticated original ciphertext";
    let mut bytes = b"ramflux.own_sent_message.v1\n".to_vec();
    bytes.extend(serde_json::to_vec(&json!({
        "envelope_id":"private-copy-envelope","message_id":"original-text-id","sender_id":source.device_id(),
        "context":{"conversation_id":"native-copy-thread","participants":[own.manifest.principal_id,"peer"],"group":null,"friend":null},
        "ciphertext_hash":crate::client::own_sent_message::own_sent_ciphertext_hash(ciphertext),
        "body_base64":ramflux_protocol::encode_base64url(b"copied body")
    }))?);
    let input = crate::client::own_device_copy::OwnMessageInput {
        id: "private-copy-envelope",
        conversation: "native-copy-thread",
        group: None,
        created_at: crate::time::now_unix_timestamp(),
        body: &bytes,
    };
    assert!(own.client.receive_own_sent_message(&source, input)?);
    let rows = own.client.direct_messages("native-copy-thread")?;
    assert_eq!(rows.len(), 1);
    let id = &rows[0].message_id;
    assert_eq!(
        own.client.message_origin("native-copy-thread", id)?.ok_or("origin")?["direction"],
        "outgoing"
    );
    db.delete_direct_message("native-copy-thread", id, "self", "delete")?;
    assert!(own.client.message_origin("native-copy-thread", id)?.is_none());
    assert!(own.client.receive_own_sent_message(&source, input)?);
    let rows = own.client.direct_messages("native-copy-thread")?;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].deleted);
    assert!(rows[0].is_own);
    assert_eq!(rows[0].sender_id, "");
    assert!(db.message_content(id)?.is_none());
    assert!(own.client.message_origin("native-copy-thread", id)?.is_none());
    assert_eq!(db.actor_state_usage("own-device/sent-ciphertext/")?.0, 1);
    let retained =
        serde_json::to_string(&db.list_actor_states::<serde_json::Value>("own-device/")?)?;
    for forbidden in [
        source.device_id(),
        source.root_commitment(),
        source.storage_key(),
        "private-copy-envelope",
        "copied body",
    ] {
        assert!(!retained.contains(forbidden), "private replay state retained {forbidden}");
    }
    Ok(())
}
