// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit installed-B abandonment is distinct from ceremony cancellation.
use super::{PairingActor, PairingRole, SdkError, wrong};
use ramflux_protocol::custody::pairing::{
    PairingWire as _,
    local_dto::{Cancel, FullTailStatus, LocalResult, StatusRequest},
};
impl PairingActor {
    /// Abandon only B's incomplete installed tail, including after expiry.
    /// Native installation and ordinary account data remain usable.
    /// # Errors
    /// Refuses A, wrong generations, incomplete installation, merged tails or unavailable unlock.
    pub async fn tail_abandon(&mut self, request: &Cancel) -> Result<LocalResult, SdkError> {
        self.require_open()?;
        request.validate().map_err(|_| wrong())?;
        let status_request = StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: request.operation_id.clone(),
            generation: request.generation,
        };
        let (scope, role, _) =
            self.retained_tail_snapshot(&status_request).await?.ok_or_else(wrong)?;
        if role != PairingRole::Responder || scope.merged {
            return Err(wrong());
        }
        if let Some(job) = self.tail_jobs.get_mut(&request.operation_id) {
            if job.io.generation != request.generation {
                return Err(wrong());
            }
            job.io.cancelled.cancel();
            job.packet = None;
            if let Some(epoch) = job.epoch.take() {
                epoch.abort_and_drain().await;
            }
        }
        self.full_runtime.drain_local_jobs().await;
        self.full_runtime.drain_local_work();
        let op = request.operation_id.clone();
        let generation = request.generation;
        self.installation_loan(move |db| {
            Ok(db.abandon_full_tail(&op, generation, crate::custody::network_now()?)?)
        })
        .await?;
        if let Some(job) = self.tail_jobs.get_mut(&request.operation_id) {
            job.abandoned = true;
            job.error = None;
        }
        let mut status = super::super::installed_status::installed_progress(
            &status_request,
            scope.lease_expires_at,
            scope.bytes_total,
            scope.cut,
            None,
            FullTailStatus::Abandoned,
        );
        status.role = "responder".into();
        self.recovered_tail_status = Some(status.clone());
        super::resume::local_result(status)
    }
}
