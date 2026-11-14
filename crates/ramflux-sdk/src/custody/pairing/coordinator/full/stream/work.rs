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
mod application;
mod catchup;
mod idle;
mod rebind;
mod reverse;

fn mismatch() -> SdkError {
    SdkError::PairingCode("ManifestMismatch")
}
fn hash(manifest: &SourceManifest) -> Result<String, SdkError> {
    manifest_hash(manifest).map(encode_base64url).map_err(|error| wire(&error))
}
impl FullStreamWork {
    fn note_failure(section: &'static str, error: &SdkError) {
        tracing::debug!(
            section,
            code = crate::custody::pairing::PairingActor::background_error_code(error),
            "full stream refused"
        );
        #[cfg(test)]
        eprintln!("test: full stream {section}: {error}");
    }
    fn note_durable(&self, manifest: &SourceManifest, chunks: u64) -> Result<(), SdkError> {
        let progress = super::super::status::FullProgress::observed(manifest, chunks)?;
        *self.progress.lock().map_err(|_| SdkError::PairingCode("Busy"))? = progress;
        Ok(())
    }

    async fn receive(&mut self) -> Result<DataPacket, SdkError> {
        loop {
            self.runtime.require_live()?;
            if let Some(packet) =
                self.packet.poll(self.relay.as_ref(), &self.origin).await.inspect_err(|error| {
                    Self::note_failure(
                        if self.role == ramflux_crypto::custody::pairing::PairingRole::Initiator {
                            "source DATA poll"
                        } else {
                            "recipient DATA poll"
                        },
                        error,
                    );
                })?
            {
                self.runtime.require_live()?;
                if let Some(data) = self.packet.open_packet(&packet).inspect_err(|error| {
                    Self::note_failure("packet authentication/position", error);
                })? {
                    if matches!(data, DataPacket::Rebind { .. }) {
                        Box::pin(self.accept_rebind(data)).await?;
                        continue;
                    }
                    return Ok(data);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    async fn receive_manifest(&mut self) -> Result<SourceManifest, SdkError> {
        let mut assembler = ManifestAssembler::default();
        loop {
            let packet = self.receive().await?;
            if let Some(manifest) = assembler.push(&packet).map_err(|error| wire(&error))? {
                tracing::debug!(role = self.role.as_str(), "full data manifest received");
                return Ok(manifest);
            }
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
        mut manifest: SourceManifest,
    ) -> Result<FullStreamFinished, SdkError> {
        self.fresh_for_first_position().await.inspect_err(|error| {
            Self::note_failure("first-position native rebind", error);
        })?;
        if self.source_idle {
            self.send_idle(&manifest).await?;
        } else {
            self.send_manifest(&manifest).await?;
        }
        tracing::debug!("full source first position sent");
        // The responder's first data object MUST be its actual restrictive manifest,
        // even for a new empty target. A receipt cannot replace that position.
        let reverse = self.receive_manifest().await?;
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        self.io
            .retain_reverse_manifest(&reverse)
            .await
            .inspect_err(|error| Self::note_failure("retain reverse manifest", error))?;
        if self.prepared_resume() {
            return self.finish_prepared_source(manifest, reverse).await;
        }
        self.receive_and_apply_reverse(&reverse)
            .await
            .inspect_err(|error| Self::note_failure("apply reverse", error))?;
        let draft = self.io.prepare_reverse_data_verified().await.inspect_err(|error| {
            Self::note_failure("prepare reverse application receipt", error);
        })?;
        let participant = self.participant.clone();
        let (draft, verified) =
            self.runtime
                .clone()
                .run_blocking(move || {
                    let verified = participant.sign_application_data_verified(&draft).inspect_err(
                        |error| Self::note_failure("original branch application signer", error),
                    )?;
                    Ok((draft, verified))
                })
                .await?;
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        self.io
            .record_reverse_data_verified(draft, &verified)
            .await
            .inspect_err(|error| Self::note_failure("record reverse application receipt", error))?;
        let encrypted = self
            .packet
            .seal_packet(&verified)
            .inspect_err(|error| Self::note_failure("seal application receipt", error))?;
        self.packet
            .send(self.relay.as_ref(), &self.origin, encrypted)
            .await
            .inspect_err(|error| Self::note_failure("send application receipt", error))?;
        if self.source_idle {
            if manifest.manifest.is_last_prepublication_delta() {
                let (proof, _) = self
                    .io
                    .verify_duplex(None)
                    .await
                    .inspect_err(|error| Self::note_failure("source durable duplex", error))?;
                self.packet.allow_verified_duplex(&proof).inspect_err(|error| {
                    Self::note_failure("authenticate durable duplex control gate", error);
                })?;
                return Ok(FullStreamFinished { packet: self.packet, manifest, receiver: None });
            }
            manifest = self
                .next_source_manifest()
                .await
                .inspect_err(|error| Self::note_failure("next source cut", error))?;
            self.send_manifest(&manifest).await?;
        }
        loop {
            self.transfer_source_input(&manifest)
                .await
                .inspect_err(|error| Self::note_failure("send forward input", error))?;
            if manifest.manifest.is_last_prepublication_delta() {
                break;
            }
            manifest = self
                .next_source_manifest()
                .await
                .inspect_err(|error| Self::note_failure("next source cut", error))?;
            self.send_manifest(&manifest).await?;
        }
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        let (proof, _) = self
            .io
            .verify_duplex(None)
            .await
            .inspect_err(|error| Self::note_failure("source durable duplex", error))?;
        self.packet.allow_verified_duplex(&proof).inspect_err(|error| {
            Self::note_failure("authenticate durable duplex control gate", error);
        })?;
        // A signed DV still grants neither publication nor immutable-cut deletion.
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver: None })
    }
    pub(super) async fn destination(mut self) -> Result<FullStreamFinished, SdkError> {
        let (mut manifest, idle) = self.receive_position().await?;
        tracing::debug!("full recipient first position received");
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        let mut prefix = if idle {
            None
        } else {
            self.io
                .retain_manifest(&manifest)
                .await
                .inspect_err(|error| Self::note_failure("retain forward manifest", error))?
        };
        let reverse = self
            .prepare_own_reverse()
            .await
            .inspect_err(|error| Self::note_failure("prepare reverse", error))?;
        self.io
            .retain_reverse_manifest(&reverse)
            .await
            .inspect_err(|error| Self::note_failure("retain reverse manifest", error))?;
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        self.send_manifest(&reverse).await?;
        self.send_reverse_input(&reverse)
            .await
            .inspect_err(|error| Self::note_failure("send reverse input and receipt", error))?;
        if idle {
            if manifest.manifest.is_last_prepublication_delta() {
                return self.finish_idle_destination(manifest).await;
            }
            manifest = self.receive_manifest().await?;
            self.fresh()
                .await
                .inspect_err(|error| Self::note_failure("native freshness", error))?;
            prefix = self
                .io
                .retain_manifest(&manifest)
                .await
                .inspect_err(|error| Self::note_failure("retain forward manifest", error))?;
        }
        let mut receiver = None;
        loop {
            receiver = Some(self.apply_forward_input(&manifest, prefix, receiver.take()).await?);
            if manifest.manifest.is_last_prepublication_delta() {
                break;
            }
            manifest = self.receive_manifest().await?;
            self.fresh()
                .await
                .inspect_err(|error| Self::note_failure("native freshness", error))?;
            prefix = self
                .io
                .retain_manifest(&manifest)
                .await
                .inspect_err(|error| Self::note_failure("retain forward manifest", error))?;
        }
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        let (proof, receiver) = self
            .io
            .verify_duplex(receiver)
            .await
            .inspect_err(|error| Self::note_failure("recipient durable duplex", error))?;
        self.packet.allow_verified_duplex(&proof).inspect_err(|error| {
            Self::note_failure("authenticate durable duplex control gate", error);
        })?;
        // Final signed input and reverse application precede user preparation/publication.
        Ok(FullStreamFinished { packet: self.packet, manifest, receiver })
    }
}
