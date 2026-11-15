// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Keep the initiating private input window alive until the recipient actually stages.
use super::{Join, LocalResult, PairingActor, SdkError, terminal};
impl PairingActor {
    pub(super) async fn join_attended(&mut self, join: Join) -> Result<LocalResult, SdkError> {
        let mut result = Box::pin(self.join(join)).await?;
        // Direct protocol-only actors have no local credential operation to complete.
        if self.recipient_stage.is_none() {
            return Ok(result);
        }
        let remaining = self.with_ceremony(|ceremony| {
            Ok(ceremony.invitation.expires_at.saturating_sub(crate::custody::network_now()?))
        })?;
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(remaining.min(300));
        loop {
            if self.with_ceremony(|ceremony| {
                Ok(ceremony.commitment_ref.is_some() || terminal(&ceremony.phase))
            })? {
                return Ok(result);
            }
            if tokio::time::Instant::now() >= deadline {
                return self.fail("expired", "Expired").await;
            }
            // The original peer may not have sent its Offer yet, or the relay can
            // temporarily refuse a poll. Neither event ends the private input owner.
            tokio::time::sleep_until(
                deadline.min(tokio::time::Instant::now() + std::time::Duration::from_millis(500)),
            )
            .await;
            result = Box::pin(self.sync_relay()).await?;
        }
    }
}
