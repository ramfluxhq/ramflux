// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Sequential signed cuts with bounded disk credit; no ordinary writer loan over bulk/network.
use super::{
    CHUNK_BYTES, DataPacket, FullStreamWork, SdkError, SecretBase64, SourceManifest, U64,
    chunk_digest, encode_base64url, hash, mismatch, wire, wrong,
};
impl FullStreamWork {
    pub(super) async fn transfer_source_input(
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
            || durable_through.is_some_and(|prefix| prefix.0 >= chunks)
        {
            return Err(mismatch());
        }
        let mut next = durable_through.map_or(0, |prefix| prefix.0 + 1);
        self.note_durable(manifest, next)?;
        while next < chunks {
            self.fresh().await?;
            let encrypted = {
                let bytes = self.io.read_source_chunk(&input_hash, next).await?;
                let digest = chunk_digest(next, &bytes).map_err(|error| wire(&error))?;
                let packet = DataPacket::Chunk {
                    manifest_hash: input_hash.clone(),
                    index: U64(next),
                    length: U64(bytes.len() as u64),
                    digest: encode_base64url(digest),
                    bytes: SecretBase64::from_bytes(&bytes),
                };
                self.packet.seal_packet(&packet)?
            };
            // No chunk plaintext, database loan or stage key survives the relay await.
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
            self.note_durable(manifest, next)?;
        }
        self.runtime.require_live()?;
        let verified = self.receive().await?;
        if !matches!(verified, DataPacket::DataVerified { .. }) {
            return Err(wrong());
        }
        self.fresh().await?;
        self.io.record_source_data_verified(verified).await?;
        Ok(())
    }
    pub(super) async fn receive_forward_input(
        &mut self,
        manifest: &SourceManifest,
        prefix: Option<u64>,
    ) -> Result<(), SdkError> {
        let hash = hash(manifest)?;
        let chunks = manifest.manifest.chunk_count.0;
        if prefix.is_some_and(|index| index >= chunks) {
            return Err(mismatch());
        }
        let mut next = prefix.map_or(0, |prefix| prefix + 1);
        if next == chunks {
            self.io.verify_forward_root(&hash).await?;
        }
        self.note_durable(manifest, next)?;
        if manifest.manifest.kind
            == ramflux_protocol::custody::pairing::full_transfer::ManifestKind::Base
        {
            let verified_reverse = self.receive().await?;
            self.fresh().await?;
            self.io.record_reverse_source_data_verified(verified_reverse).await?;
        }
        // First consume/acknowledge A's reverse DV. Sending credit earlier can
        // fill both outbound slots, leaving neither peer room for the ACK poll.
        self.receipt(&hash, prefix).await?;
        while next < chunks {
            let DataPacket::Chunk { manifest_hash, index, length, digest, bytes } =
                self.receive().await?
            else {
                return Err(wrong());
            };
            if manifest_hash != hash || index.0 != next {
                return Err(mismatch());
            }
            let bytes = bytes.decode(CHUNK_BYTES as usize).map_err(|error| wire(&error))?;
            if bytes.len() as u64 != length.0
                || encode_base64url(chunk_digest(next, &bytes).map_err(|error| wire(&error))?)
                    != digest
            {
                return Err(SdkError::PairingCode("ChunkMismatch"));
            }
            self.fresh().await?;
            if self.io.retain_chunk(&hash, next, bytes).await? != Some(next) {
                return Err(mismatch());
            }
            if next + 1 == chunks {
                self.io.verify_forward_root(&hash).await?;
            }
            self.note_durable(manifest, next + 1)?;
            self.receipt(&hash, Some(next)).await?;
            next += 1;
        }
        Ok(())
    }
    pub(super) async fn next_source_manifest(&mut self) -> Result<SourceManifest, SdkError> {
        self.fresh().await?;
        let work = self.io.source_successor_work().await?;
        let proof = self.runtime.clone().run_blocking(move || Ok(work.encode()?)).await?;
        let draft = self.io.source_delta_draft(proof)?;
        let participant = self.participant.clone();
        let (draft, manifest) = self
            .runtime
            .clone()
            .run_blocking(move || {
                let manifest = participant.sign_delta_manifest(&draft)?;
                Ok((draft, manifest))
            })
            .await?;
        self.fresh().await?;
        self.io.retain_source_delta(draft, &manifest).await?;
        self.runtime.require_live()?;
        Ok(manifest)
    }
}
