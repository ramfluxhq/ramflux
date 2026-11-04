// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned attachment network steps; account data changes remain actor checkpoints.

use super::{
    DmAttachmentDownload, DmAttachmentFetch, ObjectTransferPersist,
    ack_dm_attachment_chunk_via_relay_quic, dm_attachment_object_stub,
    fetch_dm_attachment_chunk_via_gateway, validate_dm_attachment_chunk,
};
use crate::client::deferred_attachment::job::FetchBinding;
use crate::prelude::{
    ChunkManifest, ChunkPayload, DeviceBranch, EncryptedObject, GatewaySessionAccess,
    OBJECT_TRANSFER_DOWNLOAD, ObjectSyncSession, RamfluxClient, RelayTokenProvider,
    RelayTransferOptions, SdkDmAttachmentRef, SdkError, SdkObjectRelayAckResponse,
    now_unix_timestamp, object_transfer_id, verify_recipient_object_access_grant,
};
use ramflux_storage::ObjectRetention;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

pub(crate) struct FetchInput {
    pub reference: SdkDmAttachmentRef,
    pub object: EncryptedObject,
    pub manifest: ChunkManifest,
    pub transfer_id: String,
    pub options: RelayTransferOptions,
    #[cfg(feature = "itest-local-mint")]
    pub http_timeout: std::time::Duration,
    pub branch: DeviceBranch,
    pub key: zeroize::Zeroizing<[u8; 32]>,
    pub cached: BTreeMap<u32, ChunkPayload>,
    pub confirmed: BTreeSet<u32>,
    pub expires_at: u64,
}
pub(crate) struct FetchChunk {
    pub payload: ChunkPayload,
    pub completed: Vec<u32>,
    pub done_bytes: u64,
}
pub(crate) struct FetchCipher(DmAttachmentDownload);

impl RamfluxClient {
    pub(crate) fn prepare_fetch_input(
        &self,
        binding: &FetchBinding,
    ) -> Result<FetchInput, SdkError> {
        self.prepare_reference_fetch_input(&binding.fence.reference, binding.slot.object_key)
    }

    pub(crate) fn prepare_reference_fetch_input(
        &self,
        reference: &SdkDmAttachmentRef,
        object_key: [u8; 32],
    ) -> Result<FetchInput, SdkError> {
        let object_key = zeroize::Zeroizing::new(object_key);
        let reference = reference.clone();
        self.validate_attachment_import(&reference)?;
        let options = self
            .relay_transfer_options(Some(reference.relay_endpoint.clone()), None, None)?
            .ok_or_else(|| SdkError::LocalBus("DM attachment relay options missing".into()))?;
        let branch = self.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        verify_recipient_object_access_grant(
            reference.access_grant.as_ref(),
            &branch,
            &self.owned_device_identity()?,
            &reference.object_id,
            &reference.manifest_hash,
            u64::try_from(now_unix_timestamp()).unwrap_or(0),
        )?;
        let manifest = ChunkManifest {
            object_id: reference.object_id.clone(),
            manifest_hash: reference.manifest_hash.clone(),
            chunk_size: reference.chunk_size.max(1),
            total_chunks: reference.total_chunks,
            object_created_group_key_epoch: None,
        };
        let transfer_id = object_transfer_id(
            &reference.object_id,
            &reference.manifest_hash,
            OBJECT_TRANSFER_DOWNLOAD,
        );
        let mut cached = BTreeMap::new();
        for index in 0..reference.total_chunks {
            if let Some(payload) = self.received_attachment_chunk(&reference, index)? {
                cached.insert(index, payload);
            }
        }
        let confirmed = self.confirmed_received_attachment_indexes(&reference)?;
        let object = dm_attachment_object_stub(&reference);
        Ok(FetchInput {
            reference,
            object,
            manifest,
            transfer_id,
            options,
            #[cfg(feature = "itest-local-mint")]
            http_timeout: std::time::Duration::from_secs(60),
            branch,
            key: object_key,
            cached,
            confirmed,
            expires_at: super::relay_expires_at(),
        })
    }

    pub(crate) fn persist_fetch_chunk(
        &self,
        input: &FetchInput,
        chunk: &FetchChunk,
    ) -> Result<(), SdkError> {
        self.account_db()?.write_transaction(|| {
            self.persist_received_attachment_chunk(&input.reference, &chunk.payload)?;
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &input.transfer_id,
                object: &input.object,
                direction: OBJECT_TRANSFER_DOWNLOAD,
                relay_endpoint: Some(&input.options.relay_endpoint),
                chunk_size: input.manifest.chunk_size,
                total_chunks: input.manifest.total_chunks,
                completed: &chunk.completed,
                done_bytes: chunk.done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(input.expires_at).unwrap_or(i64::MAX)),
            })
        })
    }

    pub(crate) fn persist_fetch_cipher(
        &mut self,
        input: &FetchInput,
        cipher: &FetchCipher,
    ) -> Result<(), SdkError> {
        self.persist_fetch_cipher_retained(input, cipher, ObjectRetention::Imported)
    }

    pub(crate) fn persist_fetch_cipher_retained(
        &mut self,
        input: &FetchInput,
        cipher: &FetchCipher,
        retention: ObjectRetention,
    ) -> Result<(), SdkError> {
        self.verify_persist_dm_attachment_retained(
            &input.reference,
            &cipher.0,
            *input.key,
            retention,
        )
        .map(|_| ())
    }

    pub(crate) fn authorize_fetch_ack(&self, input: &FetchInput) -> Result<bool, SdkError> {
        self.account_db()?
            .check_object_identity(&input.reference.object_id, &input.reference.manifest_hash)?;
        if !self.received_attachment_is_verified_local(&input.reference)? {
            return Err(SdkError::InboundPending("attachment import is not durable".into()));
        }
        Ok(!self.object_key_slot_committed(&input.reference.key_slot)?
            && input.reference.access_grant.as_ref().is_some_and(|grant| {
                grant.capabilities.contains(&ramflux_protocol::ObjectRelayCapability::Ack)
            }))
    }
}

pub(crate) async fn download<F, Fut>(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: &FetchInput,
    mut checkpoint: F,
) -> Result<FetchCipher, SdkError>
where
    F: FnMut(FetchChunk) -> Fut,
    Fut: Future<Output = Result<(), SdkError>>,
{
    let mut session = ObjectSyncSession::new(input.manifest.clone(), *input.key);
    let mut completed = Vec::new();
    let mut done_bytes = 0_u64;
    for index in 0..input.manifest.total_chunks {
        let fresh = !input.cached.contains_key(&index);
        let chunk = if let Some(payload) = input.cached.get(&index) {
            super::DmAttachmentChunk {
                payload: payload.clone(),
                len: u64::try_from(
                    ramflux_sync::decrypt_chunk_payload(&input.key, &input.manifest, payload)?
                        .len(),
                )
                .unwrap_or(0),
            }
        } else {
            fetch_chunk(engine, pool, input, index).await?
        };
        validate_dm_attachment_chunk(&input.reference, index, &chunk)?;
        session.receive_chunk(chunk.payload.clone(), &input.branch)?;
        completed.push(index);
        done_bytes = done_bytes.saturating_add(chunk.len);
        if fresh {
            checkpoint(FetchChunk {
                payload: chunk.payload,
                completed: completed.clone(),
                done_bytes,
            })
            .await?;
        }
    }
    Ok(FetchCipher(DmAttachmentDownload {
        ciphertext: session.assemble()?,
        manifest: input.manifest.clone(),
        transfer_id: input.transfer_id.clone(),
        relay_endpoint: input.options.relay_endpoint.clone(),
        completed,
        expires_at: input.expires_at,
    }))
}

pub(crate) async fn acknowledge(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: &FetchInput,
    index: u32,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    let response = match input.options.token_provider {
        RelayTokenProvider::GatewayIssued => {
            ack_dm_attachment_chunk_via_relay_quic(engine, pool, &context(input), index).await?
        }
        #[cfg(feature = "itest-local-mint")]
        RelayTokenProvider::LocalMint { .. } => {
            super::local_relay::ack(&context(input), index, input.http_timeout).await?
        }
    };
    let expected = crate::object::object_relay_chunk_id(
        &input.reference.object_id,
        &input.reference.manifest_hash,
        index,
    );
    if response.chunk_id != expected
        || !matches!(
            response.status,
            crate::object::SdkRelayChunkStatus::Available
                | crate::object::SdkRelayChunkStatus::AckedDeleted
        )
    {
        return Err(SdkError::InboundRejected("attachment ACK response binding mismatch".into()));
    }
    Ok(response)
}
fn context(input: &FetchInput) -> DmAttachmentFetch<'_> {
    DmAttachmentFetch {
        options: &input.options,
        branch: &input.branch,
        attachment: Some(&input.reference),
        object: &input.object,
        manifest: &input.manifest,
        object_key: *input.key,
        expires_at: input.expires_at,
    }
}

async fn fetch_chunk(
    engine: &mut impl GatewaySessionAccess,
    pool: &ramflux_transport::RelayQuicPool,
    input: &FetchInput,
    index: u32,
) -> Result<super::DmAttachmentChunk, SdkError> {
    match input.options.token_provider {
        RelayTokenProvider::GatewayIssued => {
            fetch_dm_attachment_chunk_via_gateway(engine, pool, &context(input), index).await
        }
        #[cfg(feature = "itest-local-mint")]
        RelayTokenProvider::LocalMint { .. } => {
            super::local_relay::get(&context(input), index, input.http_timeout).await
        }
    }
}
