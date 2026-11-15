// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native contact consent over the ordinary X3DH/ratchet carrier, without network services.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

pub(super) fn carrier(
    sender: &Fixture,
    target: &Fixture,
    bytes: &[u8],
    id: &str,
) -> TestResult<GatewayInboxEntry> {
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: target.config.target_delivery_id.clone(),
        envelope: sender.seal_inner_to_with_id(target, bytes, id)?,
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
    > = crate::client::contact_requests::native_tests::decoded_consent(&bytes)?;
    invalid.body.note = Some("tampered primary intent".into());
    let invalid =
        crate::client::contact_requests::native_tests::encoded_consent(&sender, &invalid)?;
    let bad = carrier(&sender, &target, &invalid, "bad-native-contact")?;
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
