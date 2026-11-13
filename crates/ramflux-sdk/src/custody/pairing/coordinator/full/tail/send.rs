// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original A's one saved tail, bounded credit and original B's semantic acknowledgement.
use super::{DataPacket, Phase, SdkError, TailJob, hash, wrong};
use ramflux_protocol::{
    custody::pairing::full_transfer::{SecretBase64, U64, chunk_digest},
    encode_base64url,
};
impl TailJob {
    pub(super) async fn send(&mut self, data: DataPacket) -> Result<(), SdkError> {
        self.io.fresh().await?;
        let encrypted = self.packet.as_mut().ok_or_else(wrong)?.seal_packet(&data)?;
        drop(data);
        self.packet
            .as_mut()
            .ok_or_else(wrong)?
            .send(self.relay.as_ref(), &self.origin, encrypted)
            .await
    }
    pub(super) async fn send_manifest(&mut self) -> Result<(), SdkError> {
        let manifest = self.manifest.as_ref().ok_or_else(wrong)?;
        let hash = hash(manifest)?;
        let bytes = zeroize::Zeroizing::new(manifest.to_wire_bytes().map_err(|_| wrong())?);
        let offset = usize::try_from(self.next).map_err(|_| wrong())?;
        let end = offset.saturating_add(262_144).min(bytes.len());
        let part = bytes.get(offset..end).filter(|part| !part.is_empty()).ok_or_else(wrong)?;
        let data = DataPacket::Manifest {
            manifest_hash: hash,
            offset: U64(self.next),
            total: U64(bytes.len() as u64),
            bytes: SecretBase64::from_bytes(part),
        };
        self.send(data).await?;
        self.next = end as u64;
        if end == bytes.len() {
            self.next = 0;
            self.phase = Phase::SourceReceipt;
        }
        Ok(())
    }
    pub(super) async fn source_receipt(&mut self) -> Result<(), SdkError> {
        let Some(data) = self.poll().await? else {
            return Ok(());
        };
        let DataPacket::Receipt { manifest_hash, durable_through, credit } = data else {
            return Err(wrong());
        };
        let manifest = self.manifest.as_ref().ok_or_else(wrong)?;
        if manifest_hash != hash(manifest)?
            || credit != 1
            || durable_through.is_some_and(|p| p.0 >= manifest.manifest.chunk_count.0)
        {
            return Err(wrong());
        }
        let next = durable_through.map_or(0, |p| p.0 + 1);
        if next < self.next {
            return Err(wrong());
        }
        self.next = next;
        self.phase = if next == manifest.manifest.chunk_count.0 {
            Phase::SourceDv
        } else {
            Phase::SourceChunk
        };
        Ok(())
    }
    pub(super) async fn source_chunk(&mut self) -> Result<(), SdkError> {
        let hash = hash(self.manifest.as_ref().ok_or_else(wrong)?)?;
        let index = self.next;
        let chunk_hash = hash.clone();
        let bytes = self
            .io
            .endpoint(move |endpoint, now| {
                Ok(endpoint.read_source_chunk(&chunk_hash, index, now)?)
            })
            .await?;
        let data = DataPacket::Chunk {
            manifest_hash: hash,
            index: U64(index),
            length: U64(bytes.len() as u64),
            digest: encode_base64url(chunk_digest(index, &bytes).map_err(|_| wrong())?),
            bytes: SecretBase64::from_bytes(&bytes),
        };
        drop(bytes);
        self.send(data).await?;
        self.next += 1;
        self.phase = Phase::SourceReceipt;
        Ok(())
    }
    pub(super) async fn source_dv(&mut self) -> Result<(), SdkError> {
        let Some(data) = self.poll().await? else {
            return Ok(());
        };
        let DataPacket::DataVerified { manifest_hash, .. } = &data else {
            return Err(wrong());
        };
        if *manifest_hash != hash(self.manifest.as_ref().ok_or_else(wrong)?)? {
            return Err(wrong());
        }
        self.io
            .endpoint(move |mut endpoint, now| Ok(endpoint.record_source_receipt(&data, now)?))
            .await?;
        self.finish();
        Ok(())
    }
}
