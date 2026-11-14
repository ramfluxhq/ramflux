// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compatible head changes use original-A signatures and B's independent native observation.
use super::{DataPacket, FullStreamWork, SdkError, SecretBase64, SourceManifest, U64, hash, wire};
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::custody::pairing::PairingWire as _;
impl FullStreamWork {
    async fn own_native_head(&self) -> Result<VerifiedRecord, SdkError> {
        self.runtime.require_live()?;
        let participant = self.participant.clone();
        let anchor = self.anchor.clone();
        let target = self.new_target.clone();
        self.runtime
            .clone()
            .run_blocking(move || {
                participant.full_native_stream_head(
                    &anchor,
                    target.as_ref().map(|(operation, reference)| (operation.as_str(), reference)),
                )
            })
            .await
    }
    pub(super) async fn fresh(&mut self) -> Result<(), SdkError> {
        tracing::debug!(role = self.role.as_str(), "full data native observation started");
        let current = self.own_native_head().await?;
        tracing::debug!(role = self.role.as_str(), "full data native observation returned");
        let (observed, bound) = self.io.observe_prepublication_binding(current.clone()).await?;
        tracing::debug!(
            role = self.role.as_str(),
            "full data original writer observed native binding"
        );
        if self.role == PairingRole::Initiator && observed != bound {
            let draft = self
                .io
                .prepare_rebind(current.clone())
                .await
                .inspect_err(|error| Self::note_failure("prepare native rebind", error))?;
            let participant = self.participant.clone();
            let packet = self
                .runtime
                .clone()
                .run_blocking(move || draft.sign(&participant))
                .await
                .inspect_err(|error| Self::note_failure("sign native rebind", error))?;
            self.io
                .retain_rebind(current, packet.clone())
                .await
                .inspect_err(|error| Self::note_failure("retain native rebind", error))?;
            self.pending_rebind = Some(packet);
        }
        self.flush_rebind().await?;
        self.runtime.require_live()
    }
    pub(super) async fn flush_rebind(&mut self) -> Result<(), SdkError> {
        if self.forward_started
            && let Some(packet) = self.pending_rebind.take()
        {
            let encrypted = self.packet.seal_packet(&packet)?;
            self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await?;
        }
        Ok(())
    }
    pub(super) async fn send_manifest(
        &mut self,
        manifest: &SourceManifest,
    ) -> Result<(), SdkError> {
        self.send_manifest_inner(manifest).await.inspect_err(|error| {
            Self::note_failure("manifest send/rebind", error);
        })?;
        tracing::debug!(role = self.role.as_str(), "full data manifest sent");
        Ok(())
    }
    async fn send_manifest_inner(&mut self, manifest: &SourceManifest) -> Result<(), SdkError> {
        let bytes =
            zeroize::Zeroizing::new(manifest.to_wire_bytes().map_err(|error| wire(&error))?);
        let manifest_hash = hash(manifest)?;
        for (index, part) in bytes.chunks(262_144).enumerate() {
            self.fresh().await?;
            let offset = u64::try_from(index)
                .map_err(|_| SdkError::PairingCode("TransferCapacity"))?
                .checked_mul(262_144)
                .ok_or(SdkError::PairingCode("TransferCapacity"))?;
            let encrypted = self.packet.seal_packet(&DataPacket::Manifest {
                manifest_hash: manifest_hash.clone(),
                offset: U64(offset),
                total: U64(bytes.len() as u64),
                bytes: SecretBase64::from_bytes(part),
            })?;
            self.packet.send(self.relay.as_ref(), &self.origin, encrypted).await?;
            if self.role == PairingRole::Initiator {
                self.forward_started = true;
                self.flush_rebind().await?;
            }
        }
        Ok(())
    }
    pub(super) async fn accept_rebind(&mut self, packet: DataPacket) -> Result<(), SdkError> {
        let expected = self.io.verify_rebind_hint(&packet)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let current = self.own_native_head().await?;
                let (observed, _) = self.io.observe_prepublication_binding(current.clone()).await?;
                if observed == expected {
                    return self.io.retain_rebind(current, packet).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await
        .map_err(|_| SdkError::PairingCode("HeadChanged"))?
    }
}
