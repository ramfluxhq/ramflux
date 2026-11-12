// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public totals only. A disk receipt never advances semantic or authority phases.
use super::super::{PairingActor, PairingWire, SdkError, wire};
use ramflux_protocol::custody::pairing::{
    full_transfer::{CHUNK_BYTES, FullError, SourceManifest, U64},
    local_dto::{FullStatus, FullStatusStage, FullTailStatus, LocalResult, Outcome, StatusRequest},
};

#[derive(Clone, Copy, Default)]
pub(super) struct FullProgress {
    pub(super) total: u64,
    pub(super) durable: u64,
    pub(super) cut: u64,
}
impl FullProgress {
    pub(super) fn observed(manifest: &SourceManifest, chunks: u64) -> Result<Self, SdkError> {
        if chunks > manifest.manifest.chunk_count.0 {
            return Err(SdkError::PairingCode("ManifestMismatch"));
        }
        Ok(Self {
            total: manifest.manifest.total_bytes.0,
            durable: chunks
                .checked_mul(u64::from(CHUNK_BYTES))
                .ok_or(SdkError::PairingCode("InvalidInput"))?
                .min(manifest.manifest.total_bytes.0),
            cut: manifest.manifest.snapshot_cut.0,
        })
    }
}
impl PairingActor {
    /// Full-profile local progress when a durable stage exists; legacy status otherwise.
    /// # Errors
    /// Rejects foreign operation/generation, a retired actor or invalid local state.
    pub async fn transfer_status(
        &mut self,
        request: &StatusRequest,
    ) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        let legacy = self.status(request).await?;
        let Some(value) = self.current_full_status()? else { return Ok(legacy) };
        Ok(LocalResult {
            schema: "ramflux.pairing.LocalResult.v2".into(),
            version: 2,
            outcome: Outcome::FullStatus { value: Box::new(value) },
        })
    }
    pub(in crate::custody::pairing::coordinator) fn capture_full_terminal_status(
        &mut self,
        phase: &str,
    ) {
        let stage = match phase {
            "cancelled" => FullStatusStage::Cancelled,
            "expired" => FullStatusStage::Expired,
            _ => return,
        };
        // Public display data only; failed capture must never obstruct key erasure.
        let Ok(Some(mut value)) = self.current_full_status() else { return };
        value.stage = stage;
        value.result = if phase == "expired" { Some(FullError::LeaseExpired) } else { None };
        if let Some(c) = &mut self.ceremony {
            c.full_terminal_status = Some(Box::new(value));
        }
    }
    fn current_full_status(&self) -> Result<Option<FullStatus>, SdkError> {
        let c = self.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?;
        if let Some(saved) = &c.full_terminal_status {
            return Ok(Some((**saved).clone()));
        }
        let Some(state) = c.full.as_ref().and_then(|full| full.bootstrap.as_ref()) else {
            return Ok(None);
        };
        let Some(trust) = &state.trust else { return Ok(None) };
        let progress = if let Some(stream) = &state.stream {
            *stream.progress.lock().map_err(|_| SdkError::PairingCode("Busy"))?
        } else {
            state.source_manifest.as_ref().map_or(Ok(FullProgress::default()), |manifest| {
                FullProgress::observed(manifest, 0)
            })?
        };
        let value = FullStatus {
            attachment_absent: U64(0),
            bytes_durable: U64(progress.durable),
            bytes_total: U64(progress.total),
            cut: U64(progress.cut),
            generation: c.generation,
            lease_expires_at: trust.lease_expires_at(),
            operation_id: c.operation_id.clone(),
            result: c.full_error,
            role: c.role.as_str().into(),
            // The current driver only proves disk durability. Semantic DV and all
            // subsequent publication/install stages have independent gates.
            stage: if state.stream.is_some() {
                FullStatusStage::Streaming
            } else {
                FullStatusStage::Snapshot
            },
            tail_status: FullTailStatus::None,
        };
        value.validate().map_err(|error| wire(&error))?;
        Ok(Some(value))
    }
}
