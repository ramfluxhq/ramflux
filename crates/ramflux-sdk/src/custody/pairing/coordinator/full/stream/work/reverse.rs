// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B's frozen reverse cut and A's original-writer semantic DV precede forward credit/candidate.
use super::{
    CHUNK_BYTES, DataPacket, FullStreamWork, SdkError, SecretBase64, SourceManifest, U64,
    chunk_digest, encode_base64url, hash, mismatch, wire, wrong,
};
impl FullStreamWork {
    pub(super) async fn prepare_own_reverse(&mut self) -> Result<SourceManifest, SdkError> {
        let draft = if self.linked_target {
            let work = self.io.reverse_source_work().await?;
            let encoded = self.runtime.clone().run_blocking(move || Ok(work.encode()?)).await?;
            self.fresh().await?;
            self.io.reverse_source_draft(encoded).await?
        } else {
            self.io.prepare_empty_reverse().await?
        };
        let participant = self.participant.clone();
        self.runtime.clone().run_blocking(move || participant.sign_reverse_manifest(&draft)).await
    }
    pub(super) async fn receive_and_apply_reverse(
        &mut self,
        manifest: &SourceManifest,
    ) -> Result<(), SdkError> {
        let input_hash = hash(manifest)?;
        let chunks = manifest.manifest.chunk_count.0;
        let prefix = self.io.reverse_prefix(&input_hash).await?;
        if prefix.is_some_and(|index| index >= chunks) {
            return Err(mismatch());
        }
        let mut next = prefix.map_or(0, |index| index + 1);
        self.receipt(&input_hash, prefix).await?;
        while next < chunks {
            let packet = self.receive().await?;
            let bytes = reverse_chunk(packet, &input_hash, next)?;
            self.fresh().await?;
            if self.io.retain_reverse_chunk(&input_hash, next, bytes).await? != Some(next) {
                return Err(mismatch());
            }
            self.receipt(&input_hash, Some(next)).await?;
            next += 1;
        }
        self.fresh().await?;
        let work = self.io.reverse_validation_work(&input_hash).await?;
        let validated = self.runtime.clone().run_blocking(move || Ok(work.validate()?)).await?;
        self.fresh().await?;
        self.io.accept_reverse_input(validated).await?;
        loop {
            self.fresh().await?;
            if self.io.merge_reverse_batch(&input_hash).await? {
                break;
            }
        }
        Ok(())
    }
    pub(super) async fn send_reverse_input(
        &mut self,
        manifest: &SourceManifest,
    ) -> Result<(), SdkError> {
        let input_hash = hash(manifest)?;
        let chunks = manifest.manifest.chunk_count.0;
        let DataPacket::Receipt { manifest_hash, durable_through, credit } = self.receive().await?
        else {
            return Err(wrong());
        };
        if manifest_hash != input_hash
            || credit == 0
            || durable_through.is_some_and(|index| index.0 >= chunks)
        {
            return Err(mismatch());
        }
        let mut next = durable_through.map_or(0, |index| index.0 + 1);
        while next < chunks {
            self.fresh().await?;
            let encrypted = {
                let bytes = self.io.read_reverse_source_chunk(&input_hash, next).await?;
                let digest = chunk_digest(next, &bytes).map_err(|error| wire(&error))?;
                self.packet.seal_packet(&DataPacket::Chunk {
                    manifest_hash: input_hash.clone(),
                    index: U64(next),
                    length: U64(bytes.len() as u64),
                    digest: encode_base64url(digest),
                    bytes: SecretBase64::from_bytes(&bytes),
                })?
            };
            self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await?;
            let DataPacket::Receipt { manifest_hash, durable_through, credit } =
                self.receive().await?
            else {
                return Err(wrong());
            };
            if manifest_hash != input_hash || durable_through != Some(U64(next)) || credit == 0 {
                return Err(mismatch());
            }
            next += 1;
        }
        let verified = self.receive().await?;
        self.fresh().await?;
        self.io.record_reverse_source_data_verified(verified).await?;
        Ok(())
    }
}
fn reverse_chunk(
    packet: DataPacket,
    hash: &str,
    next: u64,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    let DataPacket::Chunk { manifest_hash, index, length, digest, bytes } = packet else {
        return Err(wrong());
    };
    if manifest_hash != hash || index.0 != next {
        return Err(mismatch());
    }
    let bytes = bytes.decode(CHUNK_BYTES as usize).map_err(|error| wire(&error))?;
    if bytes.len() as u64 != length.0
        || encode_base64url(chunk_digest(next, &bytes).map_err(|error| wire(&error))?) != digest
    {
        return Err(SdkError::PairingCode("ChunkMismatch"));
    }
    Ok(bytes)
}
