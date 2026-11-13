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
                ()=signal.notified()=>{service.try_apply_client(client).map_err(|error| SdkError::LocalBus(format!("test: frontend service: {error}")))?;}
            }
        }
    }
    async fn exchange(
        rig: &mut Rig,
        service: &mut PairingLocalWriterService,
        request: &ramflux_protocol::custody::pairing::local_dto::StatusRequest,
    ) -> TestResult {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.sync_relay()), service, &rig.source.client)
            .await
            .map_err(|error| format!("test: source status: {error}"))?;
        rig.primary.status(request).await?;
        rig.clock.advance_ms(1001);
        rig.secondary.sync_relay().await.map_err(|error| format!("test: target relay: {error}"))?;
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
        let request = Box::pin(confirm_both(rig, service, begun)).await?;
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
    async fn confirm_both(
        rig: &mut Rig,
        service: &mut PairingLocalWriterService,
        begun: ramflux_protocol::custody::pairing::local_dto::LocalResult,
    ) -> Result<
        ramflux_protocol::custody::pairing::local_dto::StatusRequest,
        Box<dyn std::error::Error>,
    > {
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
        Ok(request)
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
                        crate::custody::pairing::service_frontend(
                            &participant.root, &participant.account_id, &mut source.client,
                        )?;
                    }
                }
            };
            let issued = result?;
            let Outcome::Begin { value } = issued.outcome else {
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
    #[tokio::test(start_paused = true)]
    async fn pairing_add_device_publishes_and_completes_without_parking_frontend_writer()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let mut rig = Box::pin(Rig::open()).await?;
            rig.participant_a.return_client(&mut rig.source.client)?;
            let mut service = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
            let begun = drive(
                Box::pin(rig.primary.begin(Begin {
                    schema: "ramflux.pairing.Begin.v2".into(),
                    version: 2,
                    capabilities: vec![
                        "group".into(),
                        "message".into(),
                        "register".into(),
                        "sync".into(),
                    ],
                    lease_not_before: rig.now,
                    lease_expires_at: rig.now + 86_400,
                    display_name: "source".into(),
                })),
                &mut service,
                &rig.source.client,
            )
            .await?;
            let request = Box::pin(confirm_both(&mut rig, &mut service, begun)).await?;
            for _ in 0..16 {
                Box::pin(exchange(&mut rig, &mut service, &request)).await?;
                if phase(rig.primary.status(&request).await?)? == "proposal_pending" {
                    break;
                }
            }
            assert!(
                !ordinary_session_admitted_for_participant(&rig.participant_b)?,
                "test: unapproved enrollment admitted ordinary recipient traffic"
            );
            let approval = Approve {
                schema: "ramflux.pairing.Approve.v2".into(),
                version: 2,
                operation_id: request.operation_id.clone(),
                generation: request.generation,
                transcript_hash: rig.primary.displayed_transcript()?,
                proposal_hash: rig.primary.displayed_proposal()?,
                approved: true,
            };
            drive(Box::pin(rig.primary.approve(&approval)), &mut service, &rig.source.client)
                .await?;
            for _ in 0..16 {
                Box::pin(exchange(&mut rig, &mut service, &request)).await?;
                if phase(rig.primary.status(&request).await?)? == "completed"
                    && phase(rig.secondary.status(&request).await?)? == "completed"
                {
                    break;
                }
            }
            assert_eq!(
                phase(rig.primary.status(&request).await?)?,
                "completed",
                "test: source short writer did not finish the native enrollment acknowledgement"
            );
            assert!(
                ordinary_session_admitted_for_participant(&rig.participant_b)?,
                "test: exact real native publication did not activate enrolled B"
            );
            assert!(
                rig.participant_a.db.lock().map_err(|_| "test: source owner")?.is_none(),
                "test: enrollment retained the actual frontend writer across native I/O"
            );
            assert!(
                rig.source.client.account_db()?.pairing_head()?.is_none(),
                "test: completed enrollment left a pending source head"
            );
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        result
    }
    async fn deliver_candidate_and_ready(rig: &mut Rig, operation: &str) -> TestResult {
        let request = ramflux_protocol::custody::pairing::local_dto::Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: 1,
            transcript_hash: rig.secondary.displayed_transcript()?,
        };
        Box::pin(rig.secondary.prepare_full_transfer(&request)).await?;
        let mut retained = false;
        for _ in 0..72 {
            rig.clock.advance_ms(1001);
            Box::pin(rig.secondary.poll_full_management_control()).await?;
            rig.clock.advance_ms(1001);
            Box::pin(rig.primary.poll_full_management_control()).await?;
            rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
            {
                let slot = rig.participant_b.db.lock().map_err(|_| "test: B ready writer")?;
                let db = slot.as_ref().ok_or("test: B ready writer missing")?;
                rig.secondary.service_full_transfer(db)?;
                let stage = db.open_full_transfer_stage(
                    operation,
                    ramflux_crypto::custody::pairing::PairingRole::Responder,
                    crate::custody::network_now()?,
                )?;
                let source = crate::custody::load_data_account(
                    &rig.participant_a.root,
                    &rig.participant_a.account_id,
                    crate::custody::network_now()?,
                )?;
                let head = db.pairing_head()?.ok_or("test: candidate head missing")?;
                let candidate: ramflux_protocol::custody::Publication =
                    ramflux_protocol::parse_i_json(&head.candidate)?;
                retained = stage
                    .retained_destination_after_native_ack(
                        source.record(),
                        &candidate.record,
                        crate::custody::network_now()?,
                    )?
                    .is_some();
            }
            if retained {
                break;
            }
        }
        assert!(retained, "test: encrypted source ready was not independently retained by B");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn pairing_full_frontend_publication_commits_j6_tail_cut_and_retires_only_old_primary()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            let mut rig = Box::pin(Rig::open_profile(true)).await?;
            let old = crate::custody::load_account(
                &rig.participant_a.root,
                &rig.participant_a.account_id,
                rig.now,
            )?;
            let source_ref = old.record().body.master_certificate.body.primary_device_ref.clone();
            let old_primary = old.primary_vault_ref().to_owned();
            let branch = rig.participant_a.public_keys(&source_ref)?;
            rig.participant_a.return_client(&mut rig.source.client)?;
            let original_path = rig.source.client.account_db()?.path.clone();
            let mut service = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
            Box::pin(bootstrap(&mut rig, &mut service)).await?;
            Box::pin(finish_owned_stream(&mut rig)).await?;
            let operation = rig
                .source
                .client
                .account_db()?
                .pairing_live_rows()?
                .into_iter()
                .next()
                .ok_or("test: source invitation row missing")?
                .operation_id;
            eprintln!("test: frontend publication data verified; delivering candidate and ready");
            Box::pin(deliver_candidate_and_ready(&mut rig, &operation)).await?;
            eprintln!("test: frontend publication ready retained; starting own native publication");
            assert!(
                drive(
                    Box::pin(rig.primary.advance_full_source_publication()),
                    &mut service,
                    &rig.source.client
                )
                .await?,
                "test: actual source writer never published its attended candidate"
            );
            assert!(
                !drive(
                    Box::pin(rig.primary.advance_full_source_publication()),
                    &mut service,
                    &rig.source.client
                )
                .await?,
                "test: completed source publication reused a consumed approval"
            );
            eprintln!("test: frontend source native J6/secondary retirement complete");
            let current = crate::custody::load_account(
                &rig.participant_a.root,
                &rig.participant_a.account_id,
                crate::custody::network_now()?,
            )?;
            assert_ne!(
                current.record().body.master_certificate.body.primary_device_ref,
                source_ref,
                "test: source retained native primary authority after exact J6"
            );
            assert_eq!(
                rig.participant_a.public_keys(&source_ref)?,
                branch,
                "test: source demotion changed its branch or agreement identity"
            );
            assert_eq!(
                rig.source.client.account_db()?.path,
                original_path,
                "test: source retirement replaced the ordinary data generation"
            );
            assert!(
                rig.participant_a.vault.load_primary(&old_primary).is_err(),
                "test: exact native handback retained the obsolete management key"
            );
            assert_eq!(
                rig.source
                    .client
                    .account_db()?
                    .full_source_retirement_owner(
                        &operation,
                        &ramflux_protocol::custody::object_hash(current.record())?,
                        crate::custody::network_now()?,
                    )?
                    .reference(),
                old_primary,
                "test: source retirement lost its independent positive cleanup receipt"
            );
            assert!(
                rig.participant_a.db.lock().map_err(|_| "test: source DB slot")?.is_none(),
                "test: native full publication parked the original account database"
            );
            Box::pin(complete_full_installation(&mut rig, &operation)).await?;
            rig.primary.lock().await?;
            Box::pin(handback_installed(rig.secondary, &rig.participant_b)).await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        result
    }
    async fn complete_full_installation(rig: &mut Rig, operation: &str) -> TestResult {
        rig.clock.advance_ms(1001);
        Box::pin(rig.primary.poll_full_management_control()).await?;
        eprintln!("test: full Published sent; destination obtaining own native/G1-G3 evidence");
        rig.clock.advance_ms(1001);
        Box::pin(rig.secondary.poll_full_management_control()).await?;
        eprintln!("test: destination own G3 complete; sending Installed");
        rig.clock.advance_ms(1001);
        Box::pin(rig.secondary.poll_full_management_control()).await?;
        rig.clock.advance_ms(1001);
        Box::pin(rig.primary.poll_full_management_control()).await?;
        rig.clock.advance_ms(1001);
        Box::pin(rig.primary.poll_full_management_control()).await?;
        rig.clock.advance_ms(1001);
        Box::pin(rig.secondary.poll_full_management_control()).await?;
        let request = ramflux_protocol::custody::pairing::local_dto::StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: 1,
        };
        assert_eq!(
            phase(rig.primary.status(&request).await?)?,
            "completed",
            "test: source did not close its exact full completion handshake"
        );
        assert_eq!(
            phase(rig.secondary.status(&request).await?)?,
            "completed",
            "test: installed destination did not close its exact full completion handshake"
        );
        assert!(
            ordinary_session_admitted_for_participant(&rig.participant_b)?,
            "test: own native publication plus actual G1/G2/G3 did not admit the new primary"
        );
        let native = crate::custody::load_account(
            &rig.participant_b.root,
            &rig.participant_b.account_id,
            crate::custody::network_now()?,
        )?;
        assert_eq!(
            native.local_device_id()?,
            native.record().body.master_certificate.body.primary_device_ref.device_id,
            "test: full destination installed a foreign primary reference"
        );
        assert!(
            native.group_primary(rig.participant_b.vault.as_ref()).is_ok(),
            "test: new primary cannot load its own locally generated management key"
        );
        let slot = rig.participant_b.db.lock().map_err(|_| "test: selected B writer")?;
        let db = slot.as_ref().ok_or("test: selected B writer missing")?;
        let selected = ramflux_storage::AccountIndex::open(&rig.participant_b.root)?
            .account(&rig.participant_b.account_id)?;
        assert_eq!(
            db.path,
            rig.participant_b.root.join(selected.db_relative_path),
            "test: recipient actor retained the pre-G2 database"
        );
        Ok(())
    }
    async fn handback_installed(
        actor: PairingActor,
        participant: &LocalPairingParticipant,
    ) -> TestResult {
        crate::custody::pairing::install_actor(
            &participant.root,
            participant.account_id.clone(),
            actor,
        )?;
        let _registered = Registered(participant.root.clone(), participant.account_id.clone());
        let frontend = crate::custody::pairing::take_installed_recipient(
            &participant.root,
            &participant.account_id,
        )?
        .ok_or("test: own G3 did not hand the selected writer to the ordinary frontend")?;
        assert!(
            crate::custody::pairing::ordinary_session_admitted(&frontend, &participant.account_id)?,
            "test: frontend handback bypassed or lost G3 admission"
        );
        assert!(
            participant.db.lock().map_err(|_| "test: recipient slot")?.is_none(),
            "test: handback retained another database owner in the pairing participant"
        );
        assert!(
            crate::custody::pairing::take_installed_recipient(
                &participant.root,
                &participant.account_id
            )?
            .is_none(),
            "test: a second frontend took the same selected database"
        );
        crate::custody::pairing::remove_actor_and_drain(&participant.root, &participant.account_id)
            .await?;
        assert!(
            crate::custody::pairing::ordinary_session_admitted(&frontend, &participant.account_id)?,
            "test: pairing shutdown closed the ordinary installed data owner"
        );
        assert_eq!(
            frontend.account_db()?.load_actor_state::<String>("account/node-id")?.as_deref(),
            Some("node"),
            "test: handback lost the independently pinned receiving node selection"
        );
        Ok(())
    }
}
