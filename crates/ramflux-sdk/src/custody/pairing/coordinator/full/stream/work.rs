// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! New-target disk transport. Every native query and local writer use ends before send.
use super::{FullStreamFinished, FullStreamWork, SourceManifest, wrong};
use crate::{SdkError, custody::pairing::transport::wire};
use ramflux_protocol::{
    custody::pairing::full_transfer::{
        CHUNK_BYTES, DataPacket, ManifestAssembler, SecretBase64, U64, chunk_digest, manifest_hash,
    },
    encode_base64url,
};
use tokio::time::Duration;

fn mismatch() -> SdkError {
    SdkError::PairingCode("ManifestMismatch")
}
fn hash(manifest: &SourceManifest) -> Result<String, SdkError> {
    manifest_hash(manifest).map(encode_base64url).map_err(|error| wire(&error))
}
impl FullStreamWork {
    fn note_durable(&self, manifest: &SourceManifest, chunks: u64) -> Result<(), SdkError> {
        let progress = super::super::status::FullProgress::observed(manifest, chunks)?;
        *self.progress.lock().map_err(|_| SdkError::PairingCode("Busy"))? = progress;
        Ok(())
    }

    async fn fresh(&mut self) -> Result<(), SdkError> {
        self.runtime.require_live()?;
        let participant = self.participant.clone();
        let anchor = self.anchor.clone();
        let target = self.new_target.clone();
        // This endpoint's own query persists its installed pins before any base refusal.
        // The local service then persists the additional encrypted job floor BEFORE its
        // grant role/key predicate. Neither query nor writer loan overlaps relay waits.
        let current = self
            .runtime
            .clone()
            .run_blocking(move || {
                participant.full_native_stream_head(
                    &anchor,
                    target.as_ref().map(|(operation, reference)| (operation.as_str(), reference)),
                )
            })
            .await?;
        self.io.observe_prepublication_head(current).await?;
        self.runtime.require_live()
    }
    async fn receive(&mut self) -> Result<DataPacket, SdkError> {
        loop {
            self.runtime.require_live()?;
            if let Some(packet) = self.packet.poll(self.relay.as_ref(), &self.origin).await? {
                self.runtime.require_live()?;
                if let Some(data) = self.packet.open_packet(&packet)? {
                    return Ok(data);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    async fn receive_manifest(&mut self) -> Result<SourceManifest, SdkError> {
        let mut assembler = ManifestAssembler::default();
        loop {
            self.runtime.require_live()?;
            if let Some(manifest) =
                self.packet.poll_manifest(self.relay.as_ref(), &self.origin, &mut assembler).await?
            {
                self.runtime.require_live()?;
                return Ok(manifest);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    async fn receipt(&mut self, hash: &str, prefix: Option<u64>) -> Result<(), SdkError> {
        let encrypted = self.packet.seal_packet(&DataPacket::Receipt {
            manifest_hash: hash.into(),
            durable_through: prefix.map(U64),
            credit: 1,
        })?;
        self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await
    }
    pub(super) async fn source(
        mut self,
        manifest: SourceManifest,
    ) -> Result<FullStreamFinished, SdkError> {
        self.fresh().await?;
        let hash = hash(&manifest)?;
        self.packet.send_manifest(self.relay.as_ref(), &self.origin, &manifest).await?;
        // The responder's first data object MUST be its actual restrictive manifest,
        // even for a new empty target. A receipt cannot replace that position.
        let reverse = self.receive_manifest().await?;
        self.fresh().await?;
        self.io.retain_reverse_manifest(&reverse).await?;
        if reverse.manifest.chunk_count.0 != 0 || reverse.manifest.total_bytes.0 != 0 {
            return Err(SdkError::PairingCode("UnsupportedRecord"));
        }
        let chunks = manifest.manifest.chunk_count.0;
        let DataPacket::Receipt { manifest_hash, durable_through, credit } = self.receive().await?
        else {
            return Err(wrong());
        };
        if manifest_hash != hash
            || credit == 0
            || durable_through.is_some_and(|prefix| prefix.0 >= chunks)
        {
            return Err(mismatch());
        }
        let mut next = durable_through.map_or(0, |prefix| prefix.0 + 1);
        self.note_durable(&manifest, next)?;
        while next < chunks {
            self.fresh().await?;
            let encrypted = {
                let bytes = self.io.read_source_chunk(&hash, next).await?;
                let digest = chunk_digest(next, &bytes).map_err(|error| wire(&error))?;
                let packet = DataPacket::Chunk {
                    manifest_hash: hash.clone(),
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
            if manifest_hash != hash || durable_through != Some(U64(next)) || credit == 0 {
                return Err(mismatch());
            }
            next += 1;
            self.note_durable(&manifest, next)?;
        }
        self.runtime.require_live()?;
        // Receipt frees no immutable cut and authorizes no candidate. Keep the exact
        // cipher for the future semantic/DV workflow; never synthesize a peer DV here.
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver: None })
    }
    pub(super) async fn destination(mut self) -> Result<FullStreamFinished, SdkError> {
        let manifest = self.receive_manifest().await?;
        self.fresh().await?;
        let hash = hash(&manifest)?;
        let prefix = self.io.retain_manifest(&manifest).await?;
        let draft = self.io.prepare_empty_reverse().await?;
        let participant = self.participant.clone();
        let reverse = self
            .runtime
            .clone()
            .run_blocking(move || participant.sign_empty_reverse_manifest(&draft))
            .await?;
        self.io.retain_reverse_manifest(&reverse).await?;
        self.fresh().await?;
        self.packet.send_manifest(self.relay.as_ref(), &self.origin, &reverse).await?;
        let chunks = manifest.manifest.chunk_count.0;
        if prefix.is_some_and(|index| index >= chunks) {
            return Err(mismatch());
        }
        let mut next = prefix.map_or(0, |prefix| prefix + 1);
        if next == chunks {
            self.io.verify_forward_root(&hash).await?;
        }
        self.note_durable(&manifest, next)?;
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
            self.note_durable(&manifest, next + 1)?;
            self.receipt(&hash, Some(next)).await?;
            next += 1;
        }
        self.runtime.require_live()?;
        self.fresh().await?;
        let pinned = self.io.pin_receiver_base(&hash).await?;
        let copy = self.runtime.clone().run_blocking(move || Ok(Box::new(pinned.copy()?))).await?;
        let receiver = self.io.project_receiver_base(copy).await?;
        self.runtime.require_live()?;
        // Typed projection into B's own private copy is complete. Contribution/root and
        // semantic/DV validation still precede any receipt, publication or selection.
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver: Some(receiver) })
    }
}
