// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Idle positions use each endpoint's own persisted DV and still finish the reverse proof.
use super::{
    DataPacket, FullStreamFinished, FullStreamWork, SdkError, SourceManifest, hash, mismatch, wire,
};
use ramflux_protocol::custody::pairing::full_transfer::ManifestAssembler;
impl FullStreamWork {
    pub(super) async fn send_idle(&mut self, manifest: &SourceManifest) -> Result<(), SdkError> {
        let own = self.idle_manifest.as_ref().ok_or_else(mismatch)?;
        if hash(own)? != hash(manifest)? {
            return Err(mismatch());
        }
        let encrypted = self.packet.seal_packet(&DataPacket::Idle { last_verified: hash(own)? })?;
        self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await?;
        Ok(())
    }
    pub(super) async fn finish_prepared_source(
        mut self,
        manifest: SourceManifest,
        reverse: SourceManifest,
    ) -> Result<FullStreamFinished, SdkError> {
        if !self.source_idle || !manifest.manifest.is_last_prepublication_delta() {
            return Err(mismatch());
        }
        let verified = self.io.retained_reverse_receipt().await?;
        let DataPacket::DataVerified { manifest_hash, chunks_root, .. } = &verified else {
            return Err(mismatch());
        };
        let expected = hash(&reverse)?;
        if manifest_hash != &expected || chunks_root != &reverse.manifest.chunks_root {
            return Err(mismatch());
        }
        self.receipt(&expected, reverse.manifest.chunk_count.0.checked_sub(1)).await?;
        let encrypted = self.packet.seal_packet(&verified)?;
        self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await?;
        let proof = self.io.prepared_duplex().await?;
        self.packet.allow_verified_duplex(&proof)?;
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver: None })
    }
    pub(super) async fn receive_position(&mut self) -> Result<(SourceManifest, bool), SdkError> {
        let packet = self.receive().await?;
        if let DataPacket::Idle { last_verified } = packet {
            let own = self.idle_manifest.as_ref().ok_or_else(mismatch)?;
            if hash(own)? != last_verified {
                return Err(mismatch());
            }
            return Ok((own.clone(), true));
        }
        let mut assembler = ManifestAssembler::default();
        if let Some(manifest) = assembler.push(&packet).map_err(|error| wire(&error))? {
            return Ok((manifest, false));
        }
        loop {
            let packet = self.receive().await?;
            if let Some(manifest) = assembler.push(&packet).map_err(|error| wire(&error))? {
                return Ok((manifest, false));
            }
        }
    }
    pub(super) async fn finish_idle_destination(
        mut self,
        manifest: SourceManifest,
    ) -> Result<FullStreamFinished, SdkError> {
        self.fresh().await?;
        if self.prepared_resume() {
            // The durable candidate pins the already verified union. Reconnecting
            // cannot rebuild it from a later B snapshot or mint another candidate.
            let proof = self.io.prepared_duplex().await?;
            self.packet.allow_verified_duplex(&proof)?;
            return Ok(FullStreamFinished { packet: self.packet, manifest, receiver: None });
        }
        let pinned = self.io.pin_original_receiver_base().await?;
        let copy = self.runtime.clone().run_blocking(move || Ok(Box::new(pinned.copy()?))).await?;
        let work = self.io.receiver_replay_work(copy, &hash(&manifest)?).await?;
        let copy = self.runtime.clone().run_blocking(move || Ok(Box::new(work.replay()?))).await?;
        self.fresh().await?;
        let copy = self.io.retain_replayed_application(copy).await?;
        let (proof, receiver) = self.io.verify_duplex(Some(copy)).await?;
        self.packet.allow_verified_duplex(&proof)?;
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver })
    }
}
