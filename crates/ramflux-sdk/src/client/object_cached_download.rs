// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reconstruct a complete verified attachment from durable encrypted chunks without a grant.
use super::*;

impl RamfluxClient {
    pub(in crate::client) fn cached_attachment_bytes_complete(
        &self,
        reference: &SdkDmAttachmentRef,
    ) -> Result<bool, SdkError> {
        if reference.total_chunks == 0 || reference.total_chunks > 4096 {
            return Ok(false);
        }
        for index in 0..reference.total_chunks {
            if self.received_attachment_chunk(reference, index)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(in crate::client) fn materialize_cached_attachment(
        &mut self,
        reference: &SdkDmAttachmentRef,
        key: [u8; 32],
        check: &mut &'static str,
    ) -> Result<(), SdkError> {
        let branch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let manifest = ChunkManifest {
            object_id: reference.object_id.clone(),
            manifest_hash: reference.manifest_hash.clone(),
            chunk_size: reference.chunk_size,
            total_chunks: reference.total_chunks,
            object_created_group_key_epoch: None,
        };
        let mut session = ObjectSyncSession::new(manifest.clone(), key);
        for index in 0..manifest.total_chunks {
            *check = "cached_chunk";
            let payload = self
                .received_attachment_chunk(reference, index)?
                .ok_or_else(|| SdkError::LocalBus("cached attachment chunk disappeared".into()))?;
            let chunk = DmAttachmentChunk {
                len: u64::try_from(decrypt_chunk_payload(&key, &manifest, &payload)?.len())
                    .unwrap_or(u64::MAX),
                payload,
            };
            validate_dm_attachment_chunk(reference, index, &chunk)?;
            session.receive_chunk(chunk.payload, branch)?;
        }
        let download = DmAttachmentDownload {
            ciphertext: session.assemble()?,
            transfer_id: object_transfer_id(
                &reference.object_id,
                &reference.manifest_hash,
                OBJECT_TRANSFER_DOWNLOAD,
            ),
            relay_endpoint: reference.relay_endpoint.clone(),
            completed: (0..manifest.total_chunks).collect(),
            manifest,
            // Local completion does not renew the expired relay grant or its transfer lease.
            expires_at: 0,
        };
        self.verify_persist_dm_attachment(reference, &download, key, check)?;
        Ok(())
    }
}
