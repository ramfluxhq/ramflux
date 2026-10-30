// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native contact consent over the ordinary X3DH/ratchet carrier, without network services.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

fn carrier(
    sender: &Fixture,
    target: &Fixture,
    bytes: &[u8],
    id: &str,
) -> TestResult<GatewayInboxEntry> {
    let mut message = GatewayDirectMessage {
        conversation_id: crate::client::contact_requests::conversation(
            &sender.manifest.principal_commitment,
            &target.manifest.principal_commitment,
        )?,
        message_id: id.into(),
        envelope_id: id.into(),
        source_principal_id: sender.manifest.principal_id.clone(),
        sender_id: "primary".into(),
        recipient_device_id: Some("primary".into()),
        recipient_principal_commitment: Some(target.manifest.principal_commitment.clone()),
        target_delivery_id: target.client.owned_device_identity()?.storage_key().into(),
        encrypted_body: Vec::new(),
        created_at: crate::time::now_unix_timestamp(),
        ttl: 3600,
    };
    let local = sender.client.owned_device_identity()?;
    let remote = target.client.owned_device_identity()?;
    let (mut session, header, bundle) = sender.client.new_send_pair(
        &local,
        &message,
        target.client.load_x3dh_private_state(&remote)?.bundle,
    )?;
    let mut packet = sender.client.seal_routed_with_route(
        &message,
        bytes,
        Route::control(),
        SealPair {
            local: "primary",
            remote: remote.storage_key(),
            session: &mut session,
            header,
            bundle,
        },
    )?;
    packet.schema = crate::client::contact_requests::ENVELOPE_SCHEMA.into();
    message.encrypted_body = serde_json::to_vec(&packet)?;
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: message.target_delivery_id.clone(),
        envelope: crate::dm::gateway_direct_message_envelope(&sender.config, &message, None)?,
    })
}

#[tokio::test]
async fn ordinary_native_contact_preview_rolls_back_and_commit_consumes_replay_state() -> TestResult
{
    let sender = Fixture::new("native-carrier-sender").await?;
    let target = Fixture::new("native-carrier-target").await?;
    sender.client.persist_identity_directory(&target.manifest)?;
    let bytes =
        crate::client::contact_requests::native_tests::approve_request(&sender, &target).await?;
    let mut invalid: ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::ContactConsentV2,
    > = serde_json::from_slice(&bytes)?;
    invalid.body.note = Some("tampered primary intent".into());
    let bad = carrier(&sender, &target, &serde_json::to_vec(&invalid)?, "bad-native-contact")?;
    let (route, preview) = target
        .client
        .preview_native_contact_request(&bad, &sender.manifest, "primary")?
        .ok_or("preview")?;
    assert!(
        target
            .client
            .prepare_native_contact_control(
                &target.config,
                &bad,
                &route,
                &preview,
                Some(&sender.manifest)
            )
            .await
            .is_err()
    );
    let db = target.client.account_db()?;
    assert!(db.client_record("identity", &sender.manifest.principal_id)?.is_none());
    assert!(!db.actor_state_exists(&format!(
        "identity/custody/{}",
        sender.manifest.principal_commitment
    ))?);
    assert!(db.contact_request(&sender.manifest.principal_commitment, "inbound")?.is_none());

    let entry = carrier(&sender, &target, &bytes, "valid-native-contact")?;
    let (route, preview) = target
        .client
        .preview_native_contact_request(&entry, &sender.manifest, "primary")?
        .ok_or("preview")?;
    assert_eq!(preview.as_slice(), bytes);
    assert!(db.client_record("identity", &sender.manifest.principal_id)?.is_none());
    target
        .client
        .prepare_native_contact_control(
            &target.config,
            &entry,
            &route,
            &preview,
            Some(&sender.manifest),
        )
        .await?;
    let delivery =
        target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "primary")?;
    assert!(delivery.routing.as_ref().is_some_and(|routing| routing.kind == Kind::Control));
    assert!(delivery.plaintext.is_none());
    let request = db
        .contact_request(&sender.manifest.principal_commitment, "inbound")?
        .ok_or("native request")?;
    assert_eq!(request.state, "pending");
    assert_eq!(request.principal_id, sender.manifest.principal_id);
    assert!(target.client.open_routed(&entry, "primary").is_err());
    target.client.commit_contact_request_bootstrap(&entry, &sender.manifest, "primary")?;
    assert_eq!(
        serde_json::to_value(
            db.contact_request(&sender.manifest.principal_commitment, "inbound")?
                .ok_or("request")?
        )?,
        serde_json::to_value(request)?
    );
    assert!(target.client.identity_root.is_none());
    assert!(sender.client.identity_root.is_none());
    Ok(())
}
