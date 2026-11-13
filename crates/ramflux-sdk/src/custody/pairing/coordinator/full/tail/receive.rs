// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Installed B receives bounded durable input before two semantic selected-writer passes.
use super::{DataPacket, Phase, SdkError, TailJob, hash, wrong};
use ramflux_protocol::{
    custody::pairing::full_transfer::{CHUNK_BYTES, ManifestKind, U64, chunk_digest},
    encode_base64url,
};
impl TailJob {
    async fn receipt(&mut self, hash: String, prefix: Option<u64>) -> Result<(), SdkError> {
        self.send(DataPacket::Receipt {
            manifest_hash: hash,
            durable_through: prefix.map(U64),
            credit: 1,
        })
        .await
    }
    pub(super) async fn receive_manifest(&mut self) -> Result<(), SdkError> {
        let Some(data) = self.poll().await? else {
            return Ok(());
        };
        let Some(manifest) = self.assembler.push(&data).map_err(|_| wrong())? else {
            return Ok(());
        };
        if manifest.manifest.kind != ManifestKind::Tail {
            return Err(wrong());
        }
        let hash = hash(&manifest)?;
        let retained = manifest.clone();
        let retained_hash = hash.clone();
        let prefix = self
            .io
            .endpoint(move |mut endpoint, now| {
                endpoint.retain_recipient(&retained, now)?;
                Ok(endpoint.durable_recipient_prefix(&retained_hash, now)?)
            })
            .await?;
        self.next = prefix.map_or(0, |p| p + 1);
        if self.next > manifest.manifest.chunk_count.0 {
            return Err(wrong());
        }
        self.phase = if self.next == manifest.manifest.chunk_count.0 {
            Phase::Validate
        } else {
            Phase::Chunk
        };
        self.manifest = Some(manifest);
        self.receipt(hash, prefix).await
    }
    pub(super) async fn receive_chunk(&mut self) -> Result<(), SdkError> {
        let Some(data) = self.poll().await? else {
            return Ok(());
        };
        let DataPacket::Chunk { manifest_hash, index, length, digest, bytes } = data else {
            return Err(wrong());
        };
        let manifest = self.manifest.as_ref().ok_or_else(wrong)?;
        let hash = hash(manifest)?;
        if manifest_hash != hash || index.0 != self.next {
            return Err(wrong());
        }
        let bytes = bytes.decode(CHUNK_BYTES as usize).map_err(|_| wrong())?;
        if bytes.len() as u64 != length.0
            || encode_base64url(chunk_digest(index.0, &bytes).map_err(|_| wrong())?) != digest
        {
            return Err(SdkError::PairingCode("ChunkMismatch"));
        }
        let retained_hash = hash.clone();
        self.io
            .endpoint(move |endpoint, now| {
                endpoint.retain_recipient_chunk(&retained_hash, index.0, &bytes, now)?;
                Ok(())
            })
            .await?;
        self.next += 1;
        if self.next == manifest.manifest.chunk_count.0 {
            self.phase = Phase::Validate;
        }
        self.receipt(hash, Some(index.0)).await
    }
    pub(super) async fn commit(&mut self) -> Result<(), SdkError> {
        let hash = hash(self.manifest.as_ref().ok_or_else(wrong)?)?;
        let packet = self
            .io
            .request(move |participant, db, context, _| {
                participant.commit_full_tail_receipt(db, context, &hash)
            })
            .await?;
        self.send(packet).await?;
        self.finish();
        Ok(())
    }
}
