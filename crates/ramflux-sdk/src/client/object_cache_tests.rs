// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A retry verifies cached bytes without resetting a completed download's durable progress.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource, TransportError};

type FrameFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;
struct NoNetwork;
impl GatewaySessionFrameSink for NoNetwork {
    fn send_frame<'a>(&'a mut self, _: &'a [u8]) -> FrameFuture<'a, ()> {
        Box::pin(async {
            Err(TransportError::Quic("cached download attempted network I/O".into()))
        })
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}
impl GatewaySessionFrameSource for NoNetwork {
    fn recv_frame(&mut self) -> FrameFuture<'_, Vec<u8>> {
        Box::pin(async {
            Err(TransportError::Quic("cached download attempted network I/O".into()))
        })
    }
}

fn reference(
    client: &RamfluxClient,
    object: &EncryptedObject,
    manifest: &ChunkManifest,
) -> TestResult<SdkDmAttachmentRef> {
    let branch = client.device_branch.as_ref().ok_or("branch")?;
    let now = u64::try_from(now_unix_timestamp())?;
    let grant = build_signed_object_access_grant(
        branch,
        object.object_id.clone(),
        object.manifest_hash.clone(),
        recipient_device_hash(&client.owned_device_identity()?),
        vec![
            ramflux_protocol::ObjectRelayCapability::Get,
            ramflux_protocol::ObjectRelayCapability::Ack,
        ],
        now,
        now + 240,
    )?;
    // The importer has already prepared the slot; this download-only regression never unseals it.
    Ok(serde_json::from_value(serde_json::json!({
        "schema":"ramflux.sdk.dm_attachment_ref.v1","version":1,
        "object_id":object.object_id,"manifest_hash":object.manifest_hash,
        "plaintext_hash":object.plaintext_hash,"cipher_size":object.ciphertext.len(),
        "chunk_size":manifest.chunk_size,"total_chunks":manifest.total_chunks,
        "relay_endpoint":"https://unused.invalid","owner_principal_id":branch.principal_id,
        "owner_device_epoch":branch.device_epoch,"access_grant":grant,
        "key_slot":{"schema":"ramflux.sdk.object_key_slot.dm.v1","version":1,
            "object_id":object.object_id,"conversation_id":"unused-slot",
            "recipient_device_id":branch.device_id,"x3dh":null,
            "ciphertext":{"session_id":"unused","counter":0,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[]}}
    }))?)
}

#[tokio::test]
async fn cached_attachment_retry_keeps_completed_download_state_without_rewriting_verified_chunks()
-> TestResult {
    let mut fixture = Fixture::new("cached-attachment").await?;
    let object = fixture.client.put_encrypted_object("cached-object", &vec![0x5a; 3072])?;
    let key = fixture.client.object_content_key(&object.object_id)?;
    let manifest = chunk_manifest_for_object(&object.object_id, &object.ciphertext, 1024, None);
    let reference = reference(&fixture.client, &object, &manifest)?;
    fixture
        .client
        .persist_received_attachment_reference(&reference, "owner", "thread", "message")?;
    for index in 0..manifest.total_chunks {
        let bytes =
            ciphertext_slice(&object.ciphertext, manifest.chunk_size, index).ok_or("chunk")?;
        let payload = ramflux_sync::chunk_payload(&key, &manifest, index, bytes);
        fixture.client.persist_received_attachment_chunk(&reference, &payload)?;
    }
    let completed = (0..manifest.total_chunks).collect::<Vec<_>>();
    fixture.client.persist_object_transfer(ObjectTransferPersist {
        transfer_id: "cached-transfer",
        object: &object,
        direction: OBJECT_TRANSFER_DOWNLOAD,
        relay_endpoint: Some(&reference.relay_endpoint),
        chunk_size: manifest.chunk_size,
        total_chunks: manifest.total_chunks,
        completed: &completed,
        done_bytes: u64::try_from(object.ciphertext.len())?,
        state: "complete",
        last_error: None,
        resume_token: None,
        expires_at: None,
    })?;
    let before = serde_json::to_value(
        fixture.client.object_transfer_status(&object.object_id, Some(OBJECT_TRANSFER_DOWNLOAD))?,
    )?;
    let pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let mut engine =
        GatewaySessionEngine::with_test_transport(fixture.config.clone(), Box::new(NoNetwork));
    let downloaded = fixture
        .client
        .download_dm_attachment_ciphertext_via_gateway(&mut engine, &pool, &reference, key, None)
        .await?;
    assert_eq!(downloaded.ciphertext, object.ciphertext);
    assert_eq!(before["state"], "complete");
    let after = serde_json::to_value(
        fixture.client.object_transfer_status(&object.object_id, Some(OBJECT_TRANSFER_DOWNLOAD))?,
    )?;
    assert_eq!(after, before, "a retry must not reset durable completion before resuming ACKs");
    Ok(())
}
