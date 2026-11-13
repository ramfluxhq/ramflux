// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native observation runs after frontend handback and before local signing work.
use crate::{
    SdkError,
    custody::pairing::{FullSourceCandidateObservation, PairingActor},
};
use ramflux_protocol::custody::Publication;
impl PairingActor {
    /// Observe the source native head with no participant database loan. The returned
    /// public evidence must return through this same live actor under a short local loan.
    /// # Errors
    /// Refuses missing confirmations, a still-borrowed writer, lock or invalid native evidence.
    pub async fn observe_full_source_candidate(
        &self,
        candidate: Publication,
    ) -> Result<FullSourceCandidateObservation, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let scope = self.full_source_approval_scope()?;
        self.observe_source_candidate(candidate, scope).await
    }
    pub(super) async fn observe_source_candidate(
        &self,
        candidate: Publication,
        scope: (String, u64, [u8; 32]),
    ) -> Result<FullSourceCandidateObservation, SdkError> {
        self.require_open()?;
        self.full_runtime.require_live()?;
        let participant = self.participant.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        if participant.db.lock().map_err(|_| SdkError::PairingCode("Busy"))?.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        let root = participant.root.clone();
        let account = participant.account_id.clone();
        let query = participant.query.clone();
        let runtime = self.full_runtime.clone();
        self.full_runtime
            .clone()
            .run_blocking(move || {
                runtime.require_live()?;
                let authority = query.current_authority(&candidate.record.body.account_anchor)?;
                runtime.require_live()?;
                let verified = ramflux_crypto::custody::verify_publication(
                    &authority,
                    crate::custody::network_now()?,
                )?;
                if verified.envelope().body.account_anchor != candidate.record.body.account_anchor {
                    return Err(SdkError::PairingCode("HeadChanged"));
                }
                Ok(FullSourceCandidateObservation { root, account, scope, candidate, authority })
            })
            .await
    }
}

impl PairingActor {
    pub(super) async fn prepare_refreshed_full_source(
        &mut self,
    ) -> Result<
        (ramflux_storage::PreparedFullSource, ramflux_storage::FullSourcePreparationCancel),
        SdkError,
    > {
        let source = self.prepare_live_full_source().await?;
        if let Err(error) = self.refresh_full_issue_head().await {
            source.1.cancel();
            return Err(error);
        }
        Ok(source)
    }
    async fn refresh_full_issue_head(&mut self) -> Result<(), SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let anchor = self.identity.local_ref.account_anchor.clone();
        let current = self
            .full_runtime
            .clone()
            .run_blocking(move || participant.full_native_head(&anchor))
            .await?;
        let own_key = self
            .load_public_keys(self.identity.local_ref.clone())
            .await?
            .ok_or(SdkError::PairingCode("HeadChanged"))?
            .0;
        let body = &current.envelope().body;
        let cert = current.authorize(
            &self.identity.local_ref,
            "message",
            crate::custody::network_now()?,
        )?;
        if body.master_certificate.body.primary_device_ref != self.identity.local_ref
            || self.identity.master_public_key.as_deref()
                != Some(body.master_certificate.body.master_public_key.as_str())
            || cert.branch_signing_public_key != own_key
        {
            return Err(SdkError::PairingCode("HeadChanged"));
        }
        self.full_runtime.require_live()?;
        self.identity.base_record_hash =
            ramflux_protocol::custody::object_hash(current.envelope())?;
        self.identity.base_epoch = body.device_set_epoch;
        Ok(())
    }
}
