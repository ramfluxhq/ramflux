// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Drain-before-terminal cleanup through the original frontend's short writer owner.
use super::{PairingActor, SdkError};
impl PairingActor {
    pub(super) async fn close_invalid_full_data<T>(
        &mut self,
        result: Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.note_background_error(&error);
                self.reject_invalid_full_head(&error).await?;
                Err(error)
            }
        }
    }

    pub(in crate::custody::pairing::coordinator) async fn persist_full_data_terminal(
        &self,
        operation: Option<(String, u64)>,
        phase: &str,
    ) -> Result<bool, SdkError> {
        let (Some((operation, generation)), Some(participant)) =
            (operation, self.participant.clone())
        else {
            return Ok(false);
        };
        let phase = phase.to_owned();
        if let Some(writer) = &self.local_writer {
            writer
                .request(move |db| {
                    participant.mark_full_data_terminal_in(db, &operation, generation, &phase)
                })
                .await
        } else {
            self.full_runtime
                .clone()
                .run_blocking(move || {
                    participant.mark_full_data_terminal(&operation, generation, &phase)
                })
                .await
        }
    }
    pub(in crate::custody::pairing::coordinator) async fn reject_invalid_full_head(
        &mut self,
        error: &SdkError,
    ) -> Result<(), SdkError> {
        if Self::background_error_code(error) != "HeadChanged" {
            return Ok(());
        }
        let unpublished =
            self.ceremony.as_ref().and_then(|c| c.full.as_ref()).is_some_and(|full| {
                full.candidate.is_none()
                    && !full.publication.is_publishing()
                    && !full.publication.destination_requested()
                    && !full.publication.destination_installed()
            });
        if unpublished {
            self.fail("rejected", "HeadChanged").await?;
        }
        Ok(())
    }
}
