// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retiring stranger metadata preserves native mode and rollback denial authority.
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn native_request_retirement_drops_payload_but_preserves_mode_and_newer_head_floor()
-> TestResult {
    let sender = Fixture::new("native-retired-sender").await?;
    let target = Fixture::new("native-retired-target").await?;
    let original = sender.manifest.custody.as_ref().ok_or("native")?.publication.record.clone();
    let primary = sender
        .vault
        .primary_for_public_key(&original.body.master_certificate.body.self_signing_public_key)?;
    let mut body = original.body.clone();
    body.device_set_epoch += 1;
    body.profile.display_name = "Newer retired name".into();
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&original)?);
    let mut newer = sender.manifest.clone();
    newer.custody.as_mut().ok_or("native")?.publication.record = primary.sign_record(body)?;
    target.client.remember_contact_request_cache(&newer)?;
    target.client.persist_identity_directory(&newer)?;
    let row = ramflux_storage::ContactRequestRecord {
        contact_identity_commitment: newer.principal_commitment.clone(),
        direction: "inbound".into(),
        request_id: ramflux_protocol::encode_base64url([46; 32]),
        principal_id: newer.principal_id.clone(),
        link_id: "retired-native-link".into(),
        state: "expired".into(),
        request_json: b"{}".to_vec(),
        expires_at: crate::time::now_unix_timestamp() - 1,
        updated_at: crate::time::now_unix_timestamp() - 3601,
    };
    target
        .client
        .account_db()?
        .write_transaction(|| target.client.retire_contact_request_cache(&row))?;
    assert!(target.client.account_db()?.client_record("identity", &newer.principal_id)?.is_none());
    assert!(
        target
            .client
            .account_db()?
            .client_record("device", sender.client.owned_device_identity()?.storage_key())?
            .is_none()
    );
    assert!(
        target
            .client
            .current_custody_authority(&newer.principal_commitment, crate::custody::network_now()?)
            .is_err()
    );
    assert!(target.client.persist_identity_directory(&sender.manifest).is_err());
    let legacy = serde_json::json!({"principal_id":newer.principal_id,
        "principal_commitment":newer.principal_commitment,"root_public_key":newer.root_public_key,
        "signed_device_set":null,"devices":[]});
    assert!(matches!(
        target.client.observe_device_manifest_json(legacy, &sender.manifest.principal_commitment),
        Err(crate::SdkError::CustodyModeDowngrade)
    ));
    target.client.persist_identity_directory(&newer)?;
    Ok(())
}
