// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original recipient applies one retained input before signing its durable receipt.
use super::{FullStreamWork, SdkError, SourceManifest, hash};
impl FullStreamWork {
    pub(super) async fn apply_forward_input(
        &mut self,
        manifest: &SourceManifest,
        prefix: Option<u64>,
        previous: Option<Box<ramflux_storage::FullReceiverBaseCopy>>,
    ) -> Result<Box<ramflux_storage::FullReceiverBaseCopy>, SdkError> {
        self.receive_forward_input(manifest, prefix)
            .await
            .inspect_err(|error| Self::note_failure("receive forward input", error))?;
        let hash = hash(manifest)?;
        self.runtime.require_live()?;
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        let copy = if let Some(copy) = previous {
            copy
        } else {
            let pinned = self.io.pin_original_receiver_base().await.inspect_err(|error| {
                Self::note_failure("pin current recipient contribution", error);
            })?;
            self.runtime
                .clone()
                .run_blocking(move || Ok(Box::new(pinned.copy()?)))
                .await
                .inspect_err(|error| Self::note_failure("copy recipient contribution", error))?
        };
        self.fresh().await.inspect_err(|error| Self::note_failure("native freshness", error))?;
        let work = self
            .io
            .receiver_replay_work(copy, &hash)
            .await
            .inspect_err(|error| Self::note_failure("prepare recipient replay", error))?;
        let prepared = self
            .runtime
            .clone()
            .run_blocking(move || Ok(Box::new(work.replay()?)))
            .await
            .inspect_err(|error| Self::note_failure("replay recipient input", error))?;
        let (copy, draft) = self.io.prepare_data_verified(prepared).await.inspect_err(|error| {
            Self::note_failure("prepare recipient application receipt", error);
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
        let copy =
            self.io.record_data_verified(copy, draft, &verified).await.inspect_err(|error| {
                Self::note_failure("record recipient application receipt", error);
            })?;
        let encrypted = self
            .packet
            .seal_packet(&verified)
            .inspect_err(|error| Self::note_failure("seal application receipt", error))?;
        self.packet
            .send(self.relay.as_ref(), &self.origin, encrypted)
            .await
            .inspect_err(|error| Self::note_failure("send application receipt", error))?;
        self.runtime.require_live()?;
        Ok(copy)
    }
}
