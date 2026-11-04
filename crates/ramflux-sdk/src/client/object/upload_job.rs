// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned relay-upload inputs and one durable progress acknowledgement per network step.

use super::{
    ObjectTransferPersist, ciphertext_slice, put_object_chunk_via_relay_quic, relay_expires_at,
};
use crate::prelude::{
    DeviceBranch, EncryptedObject, GatewaySessionAccess, OBJECT_TRANSFER_UPLOAD, RamfluxClient,
    RelayTokenProvider, RelayTransferOptions, SdkError, SdkObjectRelayPutResponse,
    SdkObjectTransferStatus, SdkRelayChunkStatus, chunk_manifest_for_object, object_relay_chunk_id,
    object_transfer_id, object_transfer_status,
};
use std::{future::Future, sync::Arc};

pub(crate) struct UploadInput {
    pub object: Arc<EncryptedObject>,
    key: zeroize::Zeroizing<[u8; 32]>,
    branch: DeviceBranch,
    pub options: RelayTransferOptions,
    #[cfg(feature = "itest-local-mint")]
    pub http_timeout: std::time::Duration,
    pub chunk_size: usize,
    pub completed: Vec<u32>,
    pub transfer_id: String,
    pub expires_at: u64,
}

#[derive(Clone)]
pub(crate) struct UploadProgress {
    pub chunk_index: Option<u32>,
    pub completed: Vec<u32>,
    pub done_bytes: u64,
    pub state: &'static str,
}

impl RamfluxClient {
    pub(crate) fn prepare_upload_input(
        &self,
        object: Arc<EncryptedObject>,
        chunk_size: usize,
        options: RelayTransferOptions,
    ) -> Result<UploadInput, SdkError> {
        let key = zeroize::Zeroizing::new(self.object_content_key(&object.object_id)?);
        let branch = self.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let completed = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map_or_else(Vec::new, |record| record.completed_chunks);
        let transfer_id =
            object_transfer_id(&object.object_id, &object.manifest_hash, OBJECT_TRANSFER_UPLOAD);
        Ok(UploadInput {
            object,
            key,
            branch,
            options,
            #[cfg(feature = "itest-local-mint")]
            http_timeout: std::time::Duration::from_secs(60),
            chunk_size: chunk_size.max(1),
            completed,
            transfer_id,
            expires_at: relay_expires_at(),
        })
    }

    pub(crate) fn persist_upload_progress(
        &self,
        input: &UploadInput,
        progress: &UploadProgress,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        self.account_db()?
            .check_object_identity(&input.object.object_id, &input.object.manifest_hash)?;
        if progress.chunk_index.is_some_and(|index| !progress.completed.contains(&index)) {
            return Err(SdkError::LocalBus("upload checkpoint omits its completed chunk".into()));
        }
        let manifest = chunk_manifest_for_object(
            &input.object.object_id,
            &input.object.ciphertext,
            input.chunk_size,
            None,
        );
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &input.transfer_id,
            object: &input.object,
            direction: OBJECT_TRANSFER_UPLOAD,
            relay_endpoint: Some(&input.options.relay_endpoint),
            chunk_size: input.chunk_size,
            total_chunks: manifest.total_chunks,
            completed: &progress.completed,
            done_bytes: progress.done_bytes,
            state: progress.state,
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(input.expires_at).unwrap_or(i64::MAX)),
        })?;
        let record = self
            .account_db()?
            .object_transfer(&input.object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .ok_or_else(|| SdkError::LocalBus("missing object transfer state".into()))?;
        Ok(object_transfer_status(record))
    }
}

pub(crate) async fn run<F, Fut>(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: &UploadInput,
    mut checkpoint: F,
) -> Result<(), SdkError>
where
    F: FnMut(UploadProgress) -> Fut,
    Fut: Future<Output = Result<(), SdkError>>,
{
    let manifest = chunk_manifest_for_object(
        &input.object.object_id,
        &input.object.ciphertext,
        input.chunk_size,
        None,
    );
    let mut completed = input.completed.clone();
    let mut done_bytes = completed
        .iter()
        .filter_map(|index| ciphertext_slice(&input.object.ciphertext, input.chunk_size, *index))
        .map(|bytes| u64::try_from(bytes.len()).unwrap_or(0))
        .sum::<u64>();
    let mut transferred = 0_u32;
    for index in 0..manifest.total_chunks {
        if completed.contains(&index) {
            continue;
        }
        if input.options.interrupt_after_chunks.is_some_and(|limit| transferred >= limit) {
            checkpoint(UploadProgress {
                chunk_index: None,
                completed,
                done_bytes,
                state: "paused",
            })
            .await?;
            return Err(SdkError::LocalBus("object relay upload interrupted".into()));
        }
        let bytes = ciphertext_slice(&input.object.ciphertext, input.chunk_size, index)
            .ok_or_else(|| SdkError::LocalBus("upload chunk outside ciphertext".into()))?;
        let payload = ramflux_sync::chunk_payload(&input.key, &manifest, index, bytes);
        let encrypted_chunk = serde_json::to_vec(&payload)?;
        let response = put(engine, pool, input, index, encrypted_chunk).await?;
        let expected =
            object_relay_chunk_id(&input.object.object_id, &input.object.manifest_hash, index);
        if response.chunk_id != expected
            || response.object_id != input.object.object_id
            || response.manifest_hash != input.object.manifest_hash
            || response.status != SdkRelayChunkStatus::Available
        {
            return Err(SdkError::LocalBus("object relay put response binding mismatch".into()));
        }
        completed.push(index);
        completed.sort_unstable();
        completed.dedup();
        done_bytes = done_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(0));
        transferred = transferred.saturating_add(1);
        // U1: durable acknowledgement precedes the next PUT, including after resume.
        checkpoint(UploadProgress {
            chunk_index: Some(index),
            completed: completed.clone(),
            done_bytes,
            state: "running",
        })
        .await?;
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::OwnerPut).await?;
    }
    checkpoint(UploadProgress {
        chunk_index: None,
        completed,
        done_bytes: u64::try_from(input.object.ciphertext.len()).unwrap_or(u64::MAX),
        state: "complete",
    })
    .await
}

async fn put(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: &UploadInput,
    index: u32,
    bytes: Vec<u8>,
) -> Result<SdkObjectRelayPutResponse, SdkError> {
    match &input.options.token_provider {
        RelayTokenProvider::GatewayIssued => {
            put_object_chunk_via_relay_quic(
                engine,
                pool,
                &input.options,
                &input.branch,
                &input.object,
                index,
                bytes,
                input.expires_at,
            )
            .await
        }
        #[cfg(feature = "itest-local-mint")]
        RelayTokenProvider::LocalMint { .. } => local_put(input, index, bytes).await,
    }
}

#[cfg(feature = "itest-local-mint")]
async fn local_put(
    input: &UploadInput,
    index: u32,
    bytes: Vec<u8>,
) -> Result<SdkObjectRelayPutResponse, SdkError> {
    use crate::prelude::{
        SdkObjectChunkFrame, SdkObjectRelayCapability, object_permission_for_chunk,
        object_relay_chunk_cipher_hash,
    };
    let options = &input.options;
    let object = &input.object;
    let branch = &input.branch;
    let expires_at = input.expires_at;
    let token = super::local_relay_token_for_chunk(
        options,
        branch,
        object,
        index,
        SdkObjectRelayCapability::Put,
        expires_at,
    )?;
    let permission = object_permission_for_chunk(
        branch,
        object,
        index,
        SdkObjectRelayCapability::Put,
        expires_at,
    )?;
    let frame = SdkObjectChunkFrame {
        schema: "ramflux.object_chunk_frame.v1".into(),
        object_id: object.object_id.clone(),
        manifest_hash: object.manifest_hash.clone(),
        chunk_index: index,
        chunk_id: token.chunk_id.clone(),
        chunk_cipher_hash: object_relay_chunk_cipher_hash(&object.manifest_hash, index, &bytes),
        cipher_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        encrypted_chunk: bytes,
        relay_token: token,
        object_permission_envelope: permission,
        expires_at,
        delete_after_ack: false,
    };
    super::local_relay::post(
        &options.relay_endpoint,
        "/relay/v1/object/put_chunk",
        &frame,
        input.http_timeout,
    )
    .await
}
