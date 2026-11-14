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
            self.wire.clock.advance_ms(1001);
            drive(
                Box::pin(actor.sync_relay()),
                &mut self.source,
                &self.a.client,
                &mut self.target,
                &self.b.client,
            )
            .await?;
        }
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
    async fn status(&mut self, primary: bool) -> TestResult<FullStatus> {
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
            Outcome::FullStatus { value } => Ok(*value),
            _ => Err("test: expected actual full status".into()),
        }
    }
    pub(super) async fn data(&mut self) -> TestResult {
        for _ in 0..512 {
            self.step().await?;
            if self.status(true).await?.stage == FullStatusStage::AwaitingPrepare
                && self.status(false).await?.stage == FullStatusStage::AwaitingPrepare
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
    pub(super) async fn merge(&mut self) -> TestResult {
        for _ in 0..512 {
            self.step().await?;
            if self.status(true).await?.tail_status == FullTailStatus::Merged
                && self.status(false).await?.tail_status == FullTailStatus::Merged
            {
                return Ok(());
            }
        }
        Err("test: TLS full tail lacks both semantic acknowledgements".into())
    }
}
