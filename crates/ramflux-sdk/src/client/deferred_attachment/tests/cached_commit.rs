// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::object::{
    build_signed_object_access_grant, recipient_device_hash, verify_recipient_object_access_grant,
};

fn expired_reference(f: &mut Fixture) -> Result<(), SdkError> {
    let branch = f.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let identity = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
        &ramflux_crypto::create_identity_root("recipient", [0x21; 32]),
        branch,
    )?;
    let now = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let grant = build_signed_object_access_grant(
        branch,
        f.reference.object_id.clone(),
        f.reference.manifest_hash.clone(),
        recipient_device_hash(&identity),
        vec![
            ramflux_protocol::ObjectRelayCapability::Get,
            ramflux_protocol::ObjectRelayCapability::Ack,
        ],
        now - 241,
        now - 1,
    )?;
    verify_recipient_object_access_grant(
        Some(&grant),
        branch,
        &identity,
        &f.reference.object_id,
        &f.reference.manifest_hash,
        now - 2,
    )?;
    assert!(
        verify_recipient_object_access_grant(
            Some(&grant),
            branch,
            &identity,
            &f.reference.object_id,
            &f.reference.manifest_hash,
            now
        )
        .is_err()
    );
    f.reference.access_grant = Some(grant);
    let db = f.client.account_db()?;
    let mut stored: ReceivedAttachment = db
        .load_actor_state(&reference_key("remote-object"))?
        .ok_or_else(|| SdkError::LocalBus("reference missing".into()))?;
    stored.reference = f.reference.clone();
    db.persist_actor_state(&reference_key("remote-object"), &stored)?;
    Ok(())
}

fn stage_chunks(f: &Fixture) -> Result<(), SdkError> {
    let slot = f
        .client
        .received_attachment_prepared_slot(&f.reference)?
        .ok_or_else(|| SdkError::LocalBus("prepared slot missing".into()))?;
    let manifest = ramflux_sync::chunk_manifest_for_object(
        &f.reference.object_id,
        &f.package.object.ciphertext,
        f.reference.chunk_size,
        None,
    );
    let payload =
        ramflux_sync::chunk_payload(&slot.object_key, &manifest, 0, &f.package.object.ciphertext);
    f.client.persist_received_attachment_chunk(&f.reference, &payload)
}

#[tokio::test]
async fn expired_attachment_grant_completes_cached_bytes_but_not_missing_bytes()
-> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    expired_reference(&mut f)?;
    let mut calls = 0;
    let missing = f
        .client
        .fetch_received_with(
            "remote-object",
            "missing",
            FETCH_TIMEOUT,
            async |client, reference| {
                calls += 1;
                let branch = client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                let identity = ramflux_crypto::RootQualifiedDeviceRef::for_owned_device(
                    &ramflux_crypto::create_identity_root("recipient", [0x21; 32]),
                    branch,
                )?;
                verify_recipient_object_access_grant(
                    reference.access_grant.as_ref(),
                    branch,
                    &identity,
                    &reference.object_id,
                    &reference.manifest_hash,
                    u64::try_from(now_unix_timestamp()).unwrap_or(0),
                )?;
                Err(SdkError::LocalBus("an expired grant must not authorize missing bytes".into()))
            },
        )
        .await?;
    assert_eq!(calls, 1, "missing bytes retain the transport/grant path");
    assert_eq!(missing["transfer_state"], "failed");
    stage_chunks(&f)?;
    let receipt = f
        .client
        .fetch_received_with(
            "remote-object",
            "cached",
            FETCH_TIMEOUT,
            async |_client, _reference| {
                calls += 1;
                Err(SdkError::LocalBus("cached completion must not reach relay".into()))
            },
        )
        .await?;
    assert_eq!(calls, 1);
    assert_eq!(receipt["transfer_state"], "available");
    assert_eq!(f.client.decrypt_object("remote-object")?, b"received attachment");
    assert!(f.client.object_key_slot_committed(&f.reference.key_slot)?);
    Ok(())
}

#[tokio::test]
async fn attachment_import_sweeps_acks_and_skips_committed_ack_replays() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.account_db()?.import_direct_message_projection(DirectMessageWrite {
        conversation_id: "conversation",
        message_id: "message",
        sender_id: "owner",
        encrypted_body: b"visible",
        metadata: &MessageMetadata::default(),
        created_at: 1,
    })?;
    stage_chunks(&f)?;
    f.client.acknowledge_received_attachment_with(&f.reference, 1, async |_index| Ok(())).await?;
    let prefix = ack_progress_prefix(&f.reference)?;
    assert_eq!(f.client.account_db()?.actor_state_keys(&prefix)?.len(), 1);
    assert!(f.client.try_import_cached_attachment(&f.reference)?.is_some());
    assert_eq!(f.client.account_db()?.actor_state_keys(&prefix)?, Vec::<String>::new());
    let mut acknowledgements = 0;
    f.client
        .acknowledge_received_attachment_with(&f.reference, 1, async |_index| {
            acknowledgements += 1;
            Ok(())
        })
        .await?;
    assert_eq!(acknowledgements, 0, "a committed import tolerates swept progress");
    Ok(())
}

#[tokio::test]
async fn attachment_erasure_after_import_survives_account_reopen() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    f.client.account_db()?.import_direct_message_projection(DirectMessageWrite {
        conversation_id: "conversation",
        message_id: "message",
        sender_id: "owner",
        encrypted_body: b"visible",
        metadata: &MessageMetadata::default(),
        created_at: 1,
    })?;
    stage_chunks(&f)?;
    assert!(f.client.try_import_cached_attachment(&f.reference)?.is_some());
    f.client.delete_direct_message("conversation", "message", "local", "erase")?;
    assert_eq!(
        f.client.account_db()?.actor_state_keys(&reference_key("remote-object"))?,
        Vec::<String>::new()
    );
    assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    assert!(f.client.decrypt_object("remote-object").is_err(), "durable erasure survives reopen");
    Ok(())
}

#[tokio::test]
async fn attachment_cached_completion_rejects_corrupt_encrypted_chunks() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    expired_reference(&mut f)?;
    stage_chunks(&f)?;
    let mut chunk = f
        .client
        .received_attachment_chunk(&f.reference, 0)?
        .ok_or_else(|| SdkError::LocalBus("chunk missing".into()))?;
    chunk.ciphertext[0] ^= 1;
    f.client.persist_received_attachment_chunk(&f.reference, &chunk)?;
    assert!(f.client.try_import_cached_attachment(&f.reference).is_err());
    assert!(!f.client.object_key_slot_committed(&f.reference.key_slot)?);
    Ok(())
}
