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
