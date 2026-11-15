// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B's attended candidate is prepared off-loan, then committed through its actual frontend.
use super::{PairingActor, SdkError};
use crate::custody::pairing::FullPreparedTransferCandidate;
use ramflux_protocol::custody::pairing::local_dto::Prepare;
impl PairingActor {
    pub(super) async fn prepare_attended_full_candidate(
        &self,
        request: Prepare,
    ) -> Result<FullPreparedTransferCandidate, SdkError> {
        let participant = self.participant.clone().ok_or(SdkError::PairingCode("WrongContext"))?;
        let generation = self.frontend_generation;
        if let Some(writer) = &self.local_writer {
            let local = participant.clone();
            let work = writer
                .request(move |db| local.prepare_full_candidate_work(db, request, generation))
                .await?;
            let local = participant.clone();
            let draft =
                self.full_runtime.clone().run_blocking(move || work.prepare(&local)).await?;
            return writer.request(move |db| draft.finish(&participant, db)).await;
        }
        let runtime = self.full_runtime.clone();
        self.full_runtime
            .clone()
            .run_blocking(move || {
                let _local = runtime.local_work()?;
                let prepared = participant.prepare_full_transfer_candidate(&request, generation)?;
                runtime.require_live()?;
                Ok(prepared)
            })
            .await
    }
}
