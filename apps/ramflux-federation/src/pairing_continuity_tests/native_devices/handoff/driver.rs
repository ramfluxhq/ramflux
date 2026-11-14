// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary client writers drive actual encrypted DATA, installation and tail acknowledgements.
use super::*;
pub(super) async fn drive<T>(
    future: impl std::future::Future<Output = Result<T, SdkError>>,
    a: &mut PairingLocalWriterService,
    ac: &RamfluxClient,
    b: &mut PairingLocalWriterService,
    bc: &RamfluxClient,
) -> Result<T, SdkError> {
    let first = a.work_signal();
    let second = b.work_signal();
    tokio::pin!(future);
    loop {
        tokio::select! {
            result=&mut future=>return result,
            ()=first.notified()=>{a.try_apply_client(ac)?;},
            ()=second.notified()=>{b.try_apply_client(bc)?;},
        }
    }
}
impl Fixture {
    pub(super) async fn step(&mut self) -> TestResult {
        self.a.service_data(&mut self.wire.primary)?;
        self.b.service_data(&mut self.wire.recipient)?;
        for actor in [&mut self.wire.primary, &mut self.wire.recipient] {
            if !actor.full_data_worker_owns_relay() {
                self.wire.clock.advance_ms(1001);
            }
            drive(
                Box::pin(actor.sync_relay()),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
        }
        // Consume newly published epoch_ready before waiting on a peer that is
        // already polling DATA and cannot wake a foreground-only transition.
        self.a.service_data(&mut self.wire.primary)?;
        self.b.service_data(&mut self.wire.recipient)?;
        if self.wire.primary.full_data_worker_owns_relay()
            && self.wire.recipient.full_data_worker_owns_relay()
            && (self.wire.primary.has_pending_full_local_work()
                || self.wire.recipient.has_pending_full_local_work())
        {
            let a = self.wire.primary.local_work_signal();
            let b = self.wire.recipient.local_work_signal();
            let source = self.source.work_signal();
            let target = self.target.work_signal();
            tokio::select! {
                ()=a.notified()=>{}, ()=b.notified()=>{},
                ()=source.notified()=>{self.source.try_apply_client(&self.a.client)?;},
                ()=target.notified()=>{self.target.try_apply_client(&self.b.client)?;},
            }
        }
        Ok(())
    }
    async fn status(&mut self, primary: bool) -> TestResult<Option<FullStatus>> {
        let actor = if primary { &mut self.wire.primary } else { &mut self.wire.recipient };
        let request = StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: actor.actor_generation(),
        };
        let result = drive(
            Box::pin(actor.transfer_status(&request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        match result.outcome {
            Outcome::FullStatus { value } => Ok(Some(*value)),
            Outcome::Update { value }
                if !matches!(value.phase.as_str(), "cancelled" | "expired" | "rejected") =>
            {
                Ok(None)
            }
            _ => Err("test: TLS full operation refused before durable full status".into()),
        }
    }
    pub(super) async fn data(&mut self) -> TestResult {
        for _ in 0..512 {
            self.step().await?;
            if self
                .status(true)
                .await?
                .is_some_and(|value| value.stage == FullStatusStage::AwaitingPrepare)
                && self
                    .status(false)
                    .await?
                    .is_some_and(|value| value.stage == FullStatusStage::AwaitingPrepare)
            {
                return Ok(());
            }
        }
        Err("test: TLS full data never reached both semantic DV gates".into())
    }
    pub(super) async fn publish(&mut self) -> TestResult {
        let request = Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: self.wire.recipient.actor_generation(),
            transcript_hash: self.wire.recipient.displayed_transcript()?,
        };
        drive(
            Box::pin(self.wire.recipient.prepare_full_transfer(&request)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        let mut attended = false;
        for _ in 0..256 {
            self.a.service_data(&mut self.wire.primary)?;
            self.b.service_data(&mut self.wire.recipient)?;
            for actor in [&mut self.wire.recipient, &mut self.wire.primary] {
                self.wire.clock.advance_ms(1001);
                drive(
                    Box::pin(actor.poll_full_management_control()),
                    &mut self.source,
                    &self.a.client,
                    &mut self.target,
                    &self.b.client,
                )
                .await?;
            }
            // Candidate reception can queue the original attended approval locally.
            self.a.service_data(&mut self.wire.primary)?;
            self.b.service_data(&mut self.wire.recipient)?;
            self.affirm_source_if_displayed(&mut attended).await?;
            drive(
                Box::pin(self.wire.primary.advance_full_source_publication()),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
            self.wire
                .recipient
                .service_linked_installation(&mut self.b.client, &mut self.target)?;
            if self.b.vault.primary_entries()? == 1
                && ordinary_session_admitted(&self.b.client, &self.b.id)?
            {
                return Ok(());
            }
        }
        Err("test: TLS full handoff did not complete exact native/G3 installation".into())
    }
    async fn affirm_source_if_displayed(&mut self, attended: &mut bool) -> TestResult {
        if *attended || self.wire.primary.affirmed_full_source_preservation().is_ok() {
            *attended = true;
            return Ok(());
        }
        // displayed_proposal also carries the earlier SAS proposal hash. Wait for
        // the typed native-candidate phase before presenting a transfer approval.
        if !self
            .status(true)
            .await?
            .is_some_and(|status| status.stage == FullStatusStage::Candidate)
        {
            return Ok(());
        }
        let Ok(candidate) = self.wire.primary.displayed_proposal() else { return Ok(()) };
        let affirm = ramflux_protocol::custody::pairing::local_dto::TransferAffirm {
            schema: "ramflux.pairing.TransferAffirm.v2".into(),
            version: 2,
            operation_id: self.operation.clone(),
            generation: self.wire.primary.actor_generation(),
            transcript_hash: self.wire.primary.displayed_transcript()?,
            new_record_hash: candidate,
            approved: true,
        };
        drive(
            Box::pin(self.wire.primary.affirm_full_transfer(&affirm)),
            &mut self.source,
            &self.a.client,
            &mut self.target,
            &self.b.client,
        )
        .await?;
        *attended = true;
        self.a.service_data(&mut self.wire.primary)?;
        Ok(())
    }
    pub(super) async fn merge(&mut self) -> TestResult {
        self.complete_controls().await?;
        for _ in 0..512 {
            self.step().await?;
            if self
                .status(true)
                .await?
                .is_some_and(|value| value.tail_status == FullTailStatus::Merged)
                && self
                    .status(false)
                    .await?
                    .is_some_and(|value| value.tail_status == FullTailStatus::Merged)
            {
                return Ok(());
            }
        }
        Err("test: TLS full tail lacks both semantic acknowledgements".into())
    }
    pub(super) async fn complete_controls(&mut self) -> TestResult {
        for _ in 0..16 {
            let request = |generation| StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: self.operation.clone(),
                generation,
            };
            let a_request = request(self.wire.primary.actor_generation());
            let b_request = request(self.wire.recipient.actor_generation());
            let completed = |reply: LocalResult| {
                matches!(reply.outcome,
                Outcome::Update { value } if value.phase == "completed")
            };
            let a_done = completed(self.wire.primary.status(&a_request).await?);
            let b_done = completed(self.wire.recipient.status(&b_request).await?);
            if a_done && b_done {
                return Ok(());
            }
            for (actor, done) in
                [(&mut self.wire.recipient, b_done), (&mut self.wire.primary, a_done && b_done)]
            {
                if done {
                    continue;
                }
                self.wire.clock.advance_ms(1001);
                drive(
                    Box::pin(actor.poll_full_management_control()),
                    &mut self.source,
                    &self.a.client,
                    &mut self.target,
                    &self.b.client,
                )
                .await?;
            }
        }
        Err("test: Installed/Completed controls did not finish".into())
    }
}
