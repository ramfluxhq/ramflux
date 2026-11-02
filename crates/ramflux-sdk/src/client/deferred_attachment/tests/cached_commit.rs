// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::object::{
    build_signed_object_access_grant, recipient_device_hash, verify_recipient_object_access_grant,
};

use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};
use tracing::instrument::WithSubscriber;

fn revocation_entry(f: &Fixture) -> Result<GatewayInboxEntry, SdkError> {
    let seed = [41; 32];
    let manifest = crate::client::identity_authority::test_support::remote_manifest(
        "owner",
        "owner-device",
        seed,
    )?;
    f.client.persist_identity_directory(&manifest)?;
    let root = ramflux_crypto::create_identity_root(
        "owner",
        ramflux_crypto::blake3_256("ramflux.test.remote.root.v1", &seed),
    );
    let branch = ramflux_crypto::create_device_branch("owner", "owner-device", 1, seed);
    let config = unused_engine()
        .map_err(|error| SdkError::LocalBus(error.to_string()))?
        .config
        .with_owned_device(&root, branch)?;
    let message = GatewayDirectMessage {
        conversation_id: "conversation".into(),
        message_id: "revoke-message".into(),
        envelope_id: "revoke-wire".into(),
        source_principal_id: "owner".into(),
        sender_id: "owner-device".into(),
        recipient_device_id: Some("recipient-device".into()),
        recipient_principal_commitment: None,
        target_delivery_id: "recipient-device".into(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "recipient-device".into(),
        envelope: crate::dm::gateway_direct_message_envelope(&config, &message, None)?,
    })
}

fn revoke_before_import(f: &Fixture) -> Result<(), SdkError> {
    assert!(f.client.account_db()?.load_object::<Value>("remote-object")?.is_none());
    f.client.project_contact_control(
        &revocation_entry(f)?,
        &json!({"type":"object.revoke_access","object_id":"remote-object"}),
    )
}

#[tokio::test]
async fn attachment_fetch_maps_mid_fetch_object_tombstone_to_deleted() -> Result<(), SdkError> {
    let mut f = Fixture::new()?;
    let mut fetches = 0;
    let receipt = f
        .client
        .fetch_received_with(
            "remote-object",
            "mid-fetch-revoke",
            FETCH_TIMEOUT,
            async |client, _reference| {
                fetches += 1;
                client.account_db()?.set_object_tombstoned("remote-object")?;
                // The generic object read retains its public error inside an attachment fetch.
                client.decrypt_object("remote-object")?;
                Ok(())
            },
        )
        .await?;
    assert_eq!(fetches, 1);
    assert_eq!(receipt["transfer_state"], "failed");
    assert_eq!(receipt["last_error"], crate::error::ATTACHMENT_DELETED);
    assert_eq!(receipt["retryable"], false);
    assert!(matches!(
        f.client.decrypt_object("remote-object"),
        Err(SdkError::Sync(SyncError::ObjectTombstoned))
    ));
    Ok(())
}

#[tokio::test]
async fn revocation_before_first_import_blocks_cached_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    stage_chunks(&f)?;
    f.client.acknowledge_received_attachment_with(&f.reference, 1, async |_| Ok(())).await?;
    let ack = ack_progress_prefix(&f.reference)?;
    assert_eq!(f.client.account_db()?.actor_state_keys(&ack)?.len(), 1);
    f.client.account_db()?.import_direct_message_projection(DirectMessageWrite {
        conversation_id: "conversation",
        message_id: "message",
        sender_id: "owner",
        encrypted_body: b"visible message",
        metadata: &MessageMetadata::default(),
        created_at: 1,
    })?;
    f.client.account_db()?.store_message_content("conversation", "message", b"visible message")?;
    revoke_before_import(&f)?;
    let receipt = f
        .client
        .received_attachment_receipt("remote-object", "after-revoke")?
        .ok_or("receipt missing")?;
    assert_eq!(receipt["transfer_state"], "failed");
    assert_eq!(receipt["last_error"], crate::error::ATTACHMENT_DELETED);
    assert_eq!(receipt["retryable"], false);
    assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
    assert_eq!(f.client.account_db()?.actor_state_keys(&ack)?, Vec::<String>::new());
    let (placeholder, key) = f
        .client
        .account_db()?
        .load_object::<ramflux_sync::EncryptedObject>("remote-object")?
        .ok_or("fence missing")?;
    assert!(placeholder.tombstoned && placeholder.ciphertext.is_empty() && key.is_none());
    assert_eq!(placeholder.manifest_hash, f.reference.manifest_hash);
    let list = crate::bus::dispatch::object::object_list_response(
        &LocalBusFrame::request("list", None, "object", "object.list", json!({})),
        &f.client,
    )?;
    assert_eq!(list.response_body["objects"], json!([]));
    let directory = crate::bus::test_account_reader_request(
        f.client.account_db()?,
        LocalBusFrame::request(
            "directory",
            Some("account".into()),
            "object",
            "object.directory",
            json!({}),
        ),
    )
    .await?;
    assert_eq!(directory["objects"], json!([]));
    let read = crate::bus::test_account_reader_request(
        f.client.account_db()?,
        LocalBusFrame::request(
            "read",
            None,
            "message",
            "message.read",
            json!({"conversation_id":"conversation"}),
        ),
    )
    .await?;
    assert_eq!(read["messages"][0]["body_utf8"], "visible message");
    assert_eq!(read["messages"][0]["attachments"], json!([]));
    // The fence must also hydrate safely when no full object descriptor was ever stored.
    let previous = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(previous);
    f.client = open(&f.root, false)?;
    assert!(f.client.account_db()?.object_is_tombstoned("remote-object")?);
    assert!(f.client.try_import_cached_attachment(&f.reference).is_err());
    Ok(())
}

#[tokio::test]
async fn revocation_before_first_import_blocks_relay_import()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    revoke_before_import(&f)?;
    assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
    let mut engine = unused_engine()?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let result = f
        .client
        .import_dm_attachment_from_relay_via_gateway(&mut engine, &pool, &f.reference, None)
        .await;
    assert!(
        matches!(result, Err(SdkError::AttachmentDeleted)),
        "revocation must refuse before grant validation, download or persistence"
    );
    assert!(!f.client.object_key_slot_committed(&f.reference.key_slot)?);
    Ok(())
}

#[test]
fn revocation_for_unknown_reference_is_refused() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let error = f
        .client
        .project_contact_control(
            &revocation_entry(&f)?,
            &json!({"type":"object.revoke_access","object_id":"unknown-object"}),
        )
        .err()
        .ok_or("unknown reference accepted")?;
    assert!(error.to_string().contains("does not own the received reference"));
    assert!(f.client.account_db()?.load_object::<Value>("unknown-object")?.is_none());
    // A known reference still requires the authenticated owner's identity.
    f.client.account_db()?.persist_client_record(
        "object",
        "remote-object",
        &json!({"owner":"other-owner"}),
    )?;
    assert!(
        f.client
            .project_contact_control(
                &revocation_entry(&f)?,
                &json!({"type":"object.revoke_access","object_id":"remote-object"})
            )
            .is_err()
    );
    assert!(f.client.account_db()?.load_object::<Value>("remote-object")?.is_none());
    Ok(())
}

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

async fn erase_imported_attachment() -> Result<Fixture, SdkError> {
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
    f.client.acknowledge_received_attachment_with(&f.reference, 1, async |_| Ok(())).await?;
    let prefix = ack_progress_prefix(&f.reference)?;
    assert_eq!(f.client.account_db()?.actor_state_keys(&prefix)?.len(), 1);
    assert!(f.client.try_import_cached_attachment(&f.reference)?.is_some());
    assert_eq!(f.client.account_db()?.actor_state_keys(&prefix)?, Vec::<String>::new());
    f.client.delete_direct_message("conversation", "message", "local", "erase")?;
    assert_eq!(
        f.client.account_db()?.actor_state_keys(&reference_key("remote-object"))?,
        Vec::<String>::new()
    );
    assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
    let old = std::mem::replace(&mut f.client, RamfluxClient::new());
    drop(old);
    f.client = open(&f.root, false)?;
    assert_eq!(f.client.account_db()?.actor_state_keys(&prefix)?, Vec::<String>::new());
    assert_eq!(
        f.client.account_db()?.actor_state_keys(&reference_key("remote-object"))?,
        Vec::<String>::new()
    );
    assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
    Ok(f)
}

#[tokio::test]
async fn attachment_owned_state_erasure_survives_account_reopen() -> Result<(), SdkError> {
    let _fixture = erase_imported_attachment().await?;
    Ok(())
}

// Mutation: skip last-owner object_index payload/key erasure.
#[tokio::test]
async fn attachment_object_payload_erasure_survives_account_reopen() -> Result<(), SdkError> {
    let fixture = erase_imported_attachment().await?;
    assert!(
        fixture.client.decrypt_object("remote-object").is_err(),
        "durable object erasure survives reopen"
    );
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

type TransportFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, TransportError>> + Send + 'a>>;
struct NoNetwork;
impl GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> TransportFuture<'a, ()> {
        Box::pin(async {
            Err(TransportError::Quic("cached lifecycle attempted network I/O".into()))
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(&mut self) -> TransportFuture<'_, Vec<u8>> {
        Box::pin(async {
            Err(TransportError::Quic("cached lifecycle attempted network I/O".into()))
        })
    }
}
fn unused_engine() -> Result<GatewaySessionEngine, Box<dyn std::error::Error>> {
    let endpoint = crate::GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse()?,
        gateway_addr: "127.0.0.1:1".parse()?,
        server_name: "unused.example".into(),
        ca_cert: "unused.pem".into(),
        principal_id: "recipient".into(),
        device_id: "recipient-device".into(),
        target_delivery_id: "recipient-device".into(),
        prekey_http_url: None,
    };
    Ok(GatewaySessionEngine::with_test_transport(
        crate::GatewaySessionConfig::auto(endpoint),
        Box::new(NoNetwork),
    ))
}

#[derive(Clone, Copy)]
enum Deletion {
    Local,
    SenderRevocation,
}
async fn assert_cached_deletion_is_final(mode: Deletion) -> Result<(), Box<dyn std::error::Error>> {
    for gateway_path in [false, true] {
        let mut f = Fixture::new()?;
        stage_chunks(&f)?;
        let available = f
            .client
            .fetch_received_with("remote-object", "before-delete", FETCH_TIMEOUT, async |_, _| {
                Err(SdkError::LocalBus("cached seed reached transport".into()))
            })
            .await?;
        assert_eq!(available["transfer_state"], "available");
        assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_some());
        match mode {
            Deletion::Local => f.client.tombstone_object("remote-object")?,
            Deletion::SenderRevocation => {
                // project_contact_control persists revocation before its memory refresh.
                f.client.account_db()?.set_object_tombstoned("remote-object")?;
                assert!(
                    !f.client
                        .object_store
                        .cached_object("remote-object")
                        .ok_or("live cache missing")?
                        .tombstoned
                );
            }
        }
        assert!(
            f.client.decrypt_object("remote-object").is_err(),
            "a stale memory projection cannot bypass the durable fence"
        );
        if gateway_path {
            let mut engine = unused_engine()?;
            let pool = ramflux_transport::RelayQuicPool::new(
                ramflux_transport::RelayQuicPoolConfig::functional_default()?,
            );
            let result = f
                .client
                .import_dm_attachment_from_relay_via_gateway(&mut engine, &pool, &f.reference, None)
                .await;
            let error = result.err().ok_or("gateway import resurrected a deleted attachment")?;
            assert!(error.to_string().contains(crate::error::ATTACHMENT_DELETED));
        } else {
            let mut calls = 0;
            let receipt = f
                .client
                .fetch_received_with(
                    "remote-object",
                    "after-tombstone",
                    FETCH_TIMEOUT,
                    async |_, _| {
                        calls += 1;
                        Ok(())
                    },
                )
                .await?;
            let durable = f
                .client
                .account_db()?
                .load_object::<ramflux_sync::EncryptedObject>("remote-object")?
                .map(|(object, _)| object.tombstoned);
            assert_eq!(
                (receipt["transfer_state"].clone(), durable),
                (json!("failed"), Some(true)),
                "cached completion must not return available or clear the tombstone"
            );
            assert_eq!(calls, 0);
        }
        assert!(f.client.received_attachment_chunk(&f.reference, 0)?.is_none());
        let replay = f
            .client
            .received_attachment_receipt("remote-object", "before-delete")?
            .ok_or("deleted receipt missing")?;
        assert_eq!(replay["transfer_state"], "failed", "old successful receipts obey revocation");
        assert!(
            f.client
                .account_db()?
                .load_object::<ramflux_sync::EncryptedObject>("remote-object")?
                .is_some_and(|(object, _)| object.tombstoned)
        );
    }
    Ok(())
}

#[tokio::test]
async fn attachment_cached_completion_preserves_local_delete()
-> Result<(), Box<dyn std::error::Error>> {
    assert_cached_deletion_is_final(Deletion::Local).await
}

#[tokio::test]
async fn attachment_cached_completion_obeys_durable_sender_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    assert_cached_deletion_is_final(Deletion::SenderRevocation).await
}

#[tokio::test]
async fn attachment_valid_grant_completes_remaining_cached_acks()
-> Result<(), Box<dyn std::error::Error>> {
    let mut f = Fixture::new()?;
    expired_reference(&mut f)?;
    let expired = f.reference.access_grant.as_ref().ok_or("grant missing")?;
    let branch = f.client.device_branch.as_ref().ok_or("branch missing")?;
    let now = u64::try_from(now_unix_timestamp())?;
    f.reference.access_grant = Some(build_signed_object_access_grant(
        branch,
        expired.object_id.clone(),
        expired.manifest_hash.clone(),
        expired.grantee_device_hash.clone(),
        expired.capabilities.clone(),
        now - 1,
        now + 239,
    )?);
    f.reference.chunk_size = 16;
    let manifest = ramflux_sync::chunk_manifest_for_object(
        &f.reference.object_id,
        &f.package.object.ciphertext,
        16,
        None,
    );
    f.reference.total_chunks = manifest.total_chunks;
    let db = f.client.account_db()?;
    let mut stored: ReceivedAttachment =
        db.load_actor_state(&reference_key("remote-object"))?.ok_or("stored reference missing")?;
    stored.reference = f.reference.clone();
    db.persist_actor_state(&reference_key("remote-object"), &stored)?;
    let key =
        f.client.received_attachment_prepared_slot(&f.reference)?.ok_or("slot missing")?.object_key;
    for (index, bytes) in f.package.object.ciphertext.chunks(16).enumerate() {
        f.client.persist_received_attachment_chunk(
            &f.reference,
            &ramflux_sync::chunk_payload(&key, &manifest, u32::try_from(index)?, bytes),
        )?;
    }
    f.client.acknowledge_received_attachment_with(&f.reference, 1, async |_| Ok(())).await?;
    let mut fetches = 0;
    let mut acknowledgements = Vec::new();
    let receipt = f
        .client
        .fetch_received_with(
            "remote-object",
            "valid-cached",
            FETCH_TIMEOUT,
            async |client, reference| {
                fetches += 1;
                let slot = client
                    .received_attachment_prepared_slot(reference)?
                    .ok_or_else(|| SdkError::LocalBus("slot missing".into()))?;
                client.materialize_cached_attachment(
                    reference,
                    slot.object_key,
                    ramflux_storage::ObjectRetention::Imported,
                    &mut "cached_chunk",
                )?;
                client
                    .acknowledge_received_attachment_with(
                        reference,
                        reference.total_chunks,
                        async |index| {
                            acknowledgements.push(index);
                            Ok(())
                        },
                    )
                    .await?;
                assert!(client.try_import_cached_attachment(reference)?.is_some());
                Ok(())
            },
        )
        .await?;
    assert_eq!(fetches, 1, "an unexpired grant must finish its pending ACK pass");
    assert_eq!(acknowledgements, (1..f.reference.total_chunks).collect::<Vec<_>>());
    assert_eq!(receipt["transfer_state"], "available");
    assert!(f.client.object_key_slot_committed(&f.reference.key_slot)?);
    assert_eq!(
        f.client.account_db()?.actor_state_keys(&ack_progress_prefix(&f.reference)?)?,
        Vec::<String>::new()
    );
    Ok(())
}

#[tokio::test]
async fn attachment_deleted_and_unverified_causes_keep_one_warning_each()
-> Result<(), Box<dyn std::error::Error>> {
    for deleted in [true, false] {
        let mut f = Fixture::new()?;
        if deleted {
            stage_chunks(&f)?;
            assert!(f.client.try_import_cached_attachment(&f.reference)?.is_some());
            f.client.tombstone_object("remote-object")?;
        }
        let (capture, lines) = crate::client::attachment_diagnostics::capture_for_test();
        let receipt = f
            .client
            .fetch_received_with(
                "remote-object",
                "warn-local-cause",
                FETCH_TIMEOUT,
                async |_, _| Ok(()),
            )
            .with_subscriber(capture)
            .await?;
        assert_eq!(receipt["transfer_state"], "failed");
        let lines = lines.lock().map_err(|_| "capture lock")?;
        let warnings = lines.iter().filter(|line| line.starts_with("WARN ")).collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1, "each local failure must have one warning: {lines:?}");
        let cause = if deleted { "attachment_deleted" } else { "attachment_content_unverified" };
        assert!(warnings[0].contains(cause));
    }
    Ok(())
}
