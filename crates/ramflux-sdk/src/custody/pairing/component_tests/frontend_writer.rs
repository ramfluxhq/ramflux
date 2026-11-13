// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original frontend services bootstrap while its actual writer stays outside native waits.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custody::pairing::PairingLocalWriterService;
    struct Registered(std::path::PathBuf, String);
    impl Drop for Registered {
        fn drop(&mut self) {
            let _ = crate::custody::pairing::remove_actor(&self.0, &self.1);
        }
    }
    async fn drive<T>(
        work: impl std::future::Future<Output = Result<T, SdkError>>,
        service: &mut PairingLocalWriterService,
        client: &crate::RamfluxClient,
    ) -> Result<T, SdkError> {
        let signal = service.work_signal();
        tokio::pin!(work);
        loop {
            tokio::select! {
                result=&mut work=>return result,
                ()=signal.notified()=>{service.try_apply(client.account_db()?).map_err(|error| SdkError::LocalBus(format!("test: frontend service: {error}")))?;}
            }
        }
    }
    async fn exchange(
        rig: &mut Rig,
        service: &mut PairingLocalWriterService,
        request: &ramflux_protocol::custody::pairing::local_dto::StatusRequest,
    ) -> TestResult {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.status(request)), service, &rig.source.client)
            .await
            .map_err(|error| format!("test: source status: {error}"))?;
        rig.clock.advance_ms(1001);
        rig.secondary
            .status(request)
            .await
            .map_err(|error| format!("test: target status: {error}"))?;
        Ok(())
    }
    async fn bootstrap(rig: &mut Rig, service: &mut PairingLocalWriterService) -> TestResult {
        let begun = drive(
            Box::pin(rig.primary.begin_full(full_begin(rig.now))),
            service,
            &rig.source.client,
        )
        .await
        .map_err(|error| format!("test: source begin: {error}"))?;
        let Outcome::Begin { value } = begun.outcome else {
            return Err("test: missing source invitation".into());
        };
        let request = ramflux_protocol::custody::pairing::local_dto::StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: value.operation_id,
            generation: value.generation,
        };
        rig.secondary
            .join(Join {
                schema: "ramflux.pairing.Join.v2".into(),
                version: 2,
                token: value.invite_token,
                display_name: "phone".into(),
            })
            .await
            .map_err(|error| format!("test: target join: {error}"))?;
        for _ in 0..32 {
            Box::pin(exchange(rig, service, &request)).await?;
            if rig.primary.displayed_transcript().is_ok()
                && rig.secondary.displayed_transcript().is_ok()
            {
                break;
            }
        }
        let th = rig.primary.displayed_transcript()?;
        assert_eq!(
            th,
            rig.secondary.displayed_transcript()?,
            "test: independently staged B did not share original SAS transcript"
        );
        let confirmation = Confirm {
            schema: "ramflux.pairing.Confirm.v2".into(),
            version: 2,
            operation_id: request.operation_id.clone(),
            generation: request.generation,
            transcript_hash: th,
            r#match: true,
        };
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.confirm(&confirmation)), service, &rig.source.client).await?;
        rig.clock.advance_ms(1001);
        rig.secondary.confirm(&confirmation).await?;
        for _ in 0..32 {
            Box::pin(exchange(rig, service, &request)).await?;
            let linked = rig
                .source
                .client
                .account_db()?
                .pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == request.operation_id)
                .is_some_and(|row| {
                    row.full_stage_reference().is_ok_and(|reference| reference.is_some())
                });
            if linked
                && rig.primary.full_epoch_ready_for_test()
                && rig.secondary.full_epoch_ready_for_test()
            {
                return Ok(());
            }
            settle_stream_work(rig).await;
        }
        Err("test: frontend writer bootstrap did not reach its own original-key A3".into())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_frontend_services_bootstrap_without_lending_writer_to_native_waits()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let mut rig = Box::pin(Rig::open_profile(true)).await?;
            rig.participant_a.return_client(&mut rig.source.client)?;
            let mut service = rig
                .primary
                .bind_frontend_writer(rig.source.client.account_db()?)
                .map_err(|error| format!("test: bind actual writer: {error}"))?;
            Box::pin(bootstrap(&mut rig, &mut service))
                .await
                .map_err(|error| format!("test: bootstrap: {error}"))?;
            assert!(
                rig.participant_a.db.lock().map_err(|_| "test: source participant")?.is_none(),
                "test: native bootstrap parked the actual frontend writer"
            );
            Box::pin(finish_owned_stream(&mut rig))
                .await
                .map_err(|error| format!("test: full data: {error}"))?;
            assert!(
                rig.primary.full_base_disk_complete_for_test()
                    && rig.secondary.full_base_disk_complete_for_test(),
                "test: source frontend service did not preserve durable duplex data verification"
            );
            assert!(
                rig.participant_a
                    .db
                    .lock()
                    .map_err(|_| "test: final source participant")?
                    .is_none(),
                "test: data job retained the original account writer"
            );
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        result
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_registered_frontend_services_local_work_while_bus_call_owns_actor()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let rig = Box::pin(Rig::open_profile(true)).await?;
            let mut actor = rig.primary;
            let mut source = rig.source;
            let participant = rig.participant_a;
            participant.return_client(&mut source.client)?;
            let service = actor.bind_frontend_writer(source.client.account_db()?)?;
            crate::custody::pairing::install_actor_with_writer(
                &participant.root,
                participant.account_id.clone(),
                actor,
                Some(service),
            )?;
            let _registered = Registered(participant.root.clone(), participant.account_id.clone());
            let signal =
                crate::custody::pairing::work_signal(&participant.root, &participant.account_id)
                    .ok_or("test: missing registered writer signal")?;
            let begin = crate::custody::pairing::handle_bus(
                &participant.root,
                &participant.account_id,
                "device.transfer.begin",
                serde_json::to_value(full_begin(rig.now))?,
            );
            tokio::pin!(begin);
            let result = loop {
                tokio::select! {
                    result = &mut begin => break result,
                    () = signal.notified() => {
                        crate::custody::pairing::service_full_transfer(
                            &participant.root, &participant.account_id, source.client.account_db()?,
                        )?;
                    }
                }
            };
            let begun = result?;
            let Outcome::Begin { value } = begun.outcome else {
                return Err("test: registered frontend did not issue invitation".into());
            };
            let live = source.client.account_db()?.pairing_live_rows()?;
            assert!(
                live.iter().any(|row| row.operation_id == value.operation_id),
                "test: bus invitation did not commit through the actual frontend writer"
            );
            assert!(
                participant.db.lock().map_err(|_| "test: participant mutex")?.is_none(),
                "test: registry took ownership of the frontend database"
            );
            crate::custody::pairing::remove_actor_and_drain(
                &participant.root,
                &participant.account_id,
            )
            .await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        result
    }
}
