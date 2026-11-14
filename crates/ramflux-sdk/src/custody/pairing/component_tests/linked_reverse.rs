// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual two-frontend linked reverse data phase. Full publication/install acceptance is separate.
#[cfg(test)]
mod tests {
    use super::super::*;
    mod cooperative;
    mod head_change;
    mod races;
    mod third;
    use crate::custody::pairing::{PairingIdentity, PairingLocalWriterService};
    use ramflux_protocol::custody::{DeviceRef, object_hash};
    struct Linked {
        rig: Box<Rig>,
        target: Box<crate::RamfluxClient>,
        source_service: PairingLocalWriterService,
        target_service: PairingLocalWriterService,
        third: Option<third::Third>,
    }
    use crate::custody::pairing::component_tests::enrollment::enroll;
    async fn open() -> Result<Linked, Box<dyn std::error::Error>> {
        Box::pin(open_devices(false)).await
    }
    async fn open_devices(three: bool) -> Result<Linked, Box<dyn std::error::Error>> {
        let mut rig = Box::new(Box::pin(Rig::open_profile(true)).await?);
        Box::pin(enroll(&mut rig)).await?;
        let third = if three { Some(Box::pin(third::enroll(&mut rig)).await?) } else { None };
        let mut target = crate::RamfluxClient::new();
        rig.participant_b.return_client(&mut target)?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        if third.is_some() {
            let native = crate::custody::load_account(
                &rig.participant_b.root,
                &rig.participant_b.account_id,
                rig.now,
            )?;
            let authority = rig.node.current_authority(&native.record().body.account_anchor)?;
            refresh_authority(
                &rig.participant_b.root,
                target.account_db()?,
                rig.participant_b.vault.as_ref(),
                &rig.participant_b.account_id,
                &authority,
                rig.now,
            )?;
        }
        let native = crate::custody::load_account(
            &rig.participant_b.root,
            &rig.participant_b.account_id,
            rig.now,
        )?;
        let device = native
            .record()
            .body
            .devices
            .iter()
            .find(|device| Some(device.device_id.as_str()) == native.local_device_id().ok())
            .ok_or("test: original B reference")?;
        let reference = DeviceRef {
            account_anchor: native.record().body.account_anchor.clone(),
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        };
        let mut relay = None;
        rig.secondary.wrap_transport_for_test(|inner| {
            relay = Some(inner.clone());
            inner
        });
        let mut secondary = PairingActor::new(
            PairingIdentity {
                account_id: rig.participant_b.account_id.clone(),
                local_ref: reference,
                master_public_key: Some(
                    native.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(native.record())?,
                base_epoch: native.record().body.device_set_epoch,
                is_primary: false,
            },
            None,
            relay.ok_or("test: original relay owner")?,
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        secondary.set_participant(rig.participant_b.clone());
        secondary.set_full_node(
            crate::custody::network_tests::node(
                rig.now,
                ramflux_protocol::encode_base64url([29; 32]),
            )
            .map_err(|error| error.to_string())?,
        );
        rig.secondary = secondary;
        let source_service = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
        let target_service = rig.secondary.bind_frontend_writer(target.account_db()?)?;
        Ok(Linked { rig, target: Box::new(target), source_service, target_service, third })
    }
    async fn drive<T>(
        work: impl std::future::Future<Output = Result<T, SdkError>>,
        a: &mut PairingLocalWriterService,
        ac: &crate::RamfluxClient,
        b: &mut PairingLocalWriterService,
        bc: &crate::RamfluxClient,
    ) -> Result<T, SdkError> {
        let first = a.work_signal();
        let second = b.work_signal();
        tokio::pin!(work);
        loop {
            tokio::select! {result=&mut work=>return result,()=first.notified()=>{a.try_apply_client(ac)?;},()=second.notified()=>{b.try_apply_client(bc)?;}}
        }
    }
    async fn step(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        rig.primary
            .service_full_transfer(rig.source.client.account_db()?)
            .map_err(|error| format!("test: linked source local I/O: {error}"))?;
        rig.secondary
            .service_full_transfer(target.account_db()?)
            .map_err(|error| format!("test: linked B local I/O: {error}"))?;
        let position = format!(
            "A-SAS={} B-SAS={} A-epoch={} B-epoch={}",
            rig.primary.displayed_transcript().is_ok(),
            rig.secondary.displayed_transcript().is_ok(),
            rig.primary.full_epoch_in_flight_for_test(),
            rig.secondary.full_epoch_in_flight_for_test()
        );
        if !rig.primary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(
            Box::pin(rig.primary.sync_relay()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked source sync ({position}): {error}"))?;
        if !rig.secondary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(
            Box::pin(rig.secondary.sync_relay()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked B sync ({position}): {error}"))?;
        // The sync turn may have completed A3 or exposed a new stream request.
        // Service both actual writers before charging another relay poll interval.
        rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
        rig.secondary.service_full_transfer(target.account_db()?)?;
        settle_stream_work(rig).await;
        Ok(())
    }
    async fn bootstrap(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        let native = crate::custody::load_account(
            &rig.participant_b.root,
            &rig.participant_b.account_id,
            rig.now,
        )?;
        let mut request = full_begin(rig.now);
        request.recipient_mode = "existing".into();
        let id = native.local_device_id()?;
        let device = native
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == id)
            .ok_or("test: B branch")?;
        request.destination_ref = Some(DeviceRef {
            account_anchor: native.record().body.account_anchor.clone(),
            device_id: id.into(),
            device_epoch: device.device_epoch,
        });
        let begun = drive(
            Box::pin(rig.primary.begin_full(request)),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        let Outcome::Begin { value } = begun.outcome else {
            return Err("test: linked transfer invitation".into());
        };
        drive(
            Box::pin(rig.secondary.join(Join {
                schema: "ramflux.pairing.Join.v2".into(),
                version: 2,
                token: value.invite_token,
                display_name: "Existing phone".into(),
            })),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        for _ in 0..32 {
            step(fixture).await?;
            if fixture.rig.primary.displayed_transcript().is_ok()
                && fixture.rig.secondary.displayed_transcript().is_ok()
            {
                break;
            }
        }
        confirm(fixture, &value.operation_id).await
    }
    async fn confirm(fixture: &mut Linked, operation: &str) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        let th = rig.primary.displayed_transcript()?;
        assert_eq!(th, rig.secondary.displayed_transcript()?, "test: linked full SAS mismatch");
        for primary in [true, false] {
            rig.clock.advance_ms(1001);
            let actor = if primary { &mut rig.primary } else { &mut rig.secondary };
            let request = Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: operation.into(),
                generation: actor.actor_generation(),
                transcript_hash: th.clone(),
                r#match: true,
            };
            drive(
                Box::pin(actor.confirm(&request)),
                source_service,
                &rig.source.client,
                target_service,
                target,
            )
            .await?;
        }
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_linked_reverse_applies_original_b_veto_to_actual_a_before_duplex()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let mut fixture = Box::pin(run_data()).await?;
        fixture.rig.primary.lock().await?;
        fixture.rig.secondary.lock().await?;
        Ok(())
    }
    async fn run_data() -> Result<Linked, Box<dyn std::error::Error>> {
        Box::pin(run_data_with_change(false)).await
    }
    async fn run_data_with_change(rebind: bool) -> Result<Linked, Box<dyn std::error::Error>> {
        Box::pin(run_data_in(Box::pin(open()).await?, rebind)).await
    }
    async fn run_data_in(
        fixture: Linked,
        rebind: bool,
    ) -> Result<Linked, Box<dyn std::error::Error>> {
        Box::pin(run_data_change(
            fixture,
            if rebind { NativeChange::Profile } else { NativeChange::None },
        ))
        .await
    }
    #[derive(Clone, Copy)]
    enum NativeChange {
        None,
        Profile,
        Enrollment,
    }
    async fn run_data_change(
        mut fixture: Linked,
        change: NativeChange,
    ) -> Result<Linked, Box<dyn std::error::Error>> {
        fixture.rig.source.client.account_db()?.seed_full_transfer_object_veto_for_test(
            "source-veto",
            "source-manifest",
            3,
        )?;
        fixture.target.account_db()?.seed_full_transfer_object_veto_for_test(
            "target-veto",
            "target-manifest",
            7,
        )?;
        assert!(
            fixture
                .rig
                .source
                .client
                .account_db()?
                .check_object_identity("target-veto", "target-manifest")
                .is_ok(),
            "test: original A already contained B's veto"
        );
        Box::pin(bootstrap(&mut fixture)).await?;
        let mut complete = false;
        let mut revised = None;
        for _ in 0..256 {
            step(&mut fixture).await?;
            if !matches!(change, NativeChange::None)
                && revised.is_none()
                && fixture.rig.primary.full_base_stream_started_for_test()
                && fixture.rig.secondary.full_base_stream_started_for_test()
                && !(fixture.rig.primary.full_base_disk_complete_for_test()
                    && fixture.rig.secondary.full_base_disk_complete_for_test())
            {
                revised = Some(match change {
                    NativeChange::Profile => advance_profile(&fixture)?,
                    NativeChange::Enrollment => {
                        Box::pin(head_change::enroll_during_stream(&mut fixture)).await?
                    }
                    NativeChange::None => return Err("test: unexpected native change".into()),
                });
            }
            if fixture.rig.primary.full_base_disk_complete_for_test()
                && fixture.rig.secondary.full_base_disk_complete_for_test()
            {
                complete = true;
                break;
            }
        }
        assert!(complete, "test: linked original branches did not finish their durable duplex");
        let a = fixture.rig.source.client.account_db()?;
        assert!(
            matches!(
                a.check_object_identity("target-veto", "target-manifest"),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: A emitted reverse DV before its actual B veto became effective"
        );
        assert!(
            matches!(
                a.check_object_identity("source-veto", "source-manifest"),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: reverse union removed A's independent veto"
        );
        assert_eq!(
            a.privacy_erasure_generation()?,
            7,
            "test: reverse merge lost the maximum floor"
        );
        for participant in [&fixture.rig.participant_a, &fixture.rig.participant_b] {
            assert!(
                participant.db.lock().map_err(|_| "test: frontend owner")?.is_none(),
                "test: linked data work parked an ordinary frontend DB"
            );
        }
        if !matches!(change, NativeChange::None) {
            let expected =
                revised.ok_or("test: profile did not change during the actual stream")?;
            verify_rebound_stages(&fixture, &expected)?;
        }
        Ok(fixture)
    }
    fn advance_profile(fixture: &Linked) -> Result<String, Box<dyn std::error::Error>> {
        let rig = &fixture.rig;
        let account = crate::custody::load_data_account(
            &rig.participant_a.root,
            &rig.participant_a.account_id,
            crate::custody::network_now()?,
        )?;
        let primary = account.group_primary(rig.participant_a.vault.as_ref())?;
        let mut body = account.record().body.clone();
        let (range, revision) = ramflux_protocol::custody::decode_epoch(body.device_set_epoch)?;
        body.device_set_epoch = ramflux_protocol::custody::encode_epoch(range, revision + 1)?;
        body.previous_record_hash = Some(object_hash(account.record())?);
        body.profile.display_name = "Profile changed during original-branch duplex".into();
        let publication = Publication { record: primary.sign_record(body)?, compacted_ids: None };
        drop(primary);
        rig.node.persist_head(&publication, crate::custody::network_now()?)?;
        Ok(object_hash(&publication.record)?)
    }
    fn verify_rebound_stages(fixture: &Linked, expected: &str) -> TestResult {
        for (client, role) in [
            (&fixture.rig.source.client, ramflux_crypto::custody::pairing::PairingRole::Initiator),
            (&fixture.target, ramflux_crypto::custody::pairing::PairingRole::Responder),
        ] {
            let db = client.account_db()?;
            let row = db.pairing_live_rows()?.into_iter().next().ok_or("test: rebound live row")?;
            let stage = db.open_full_transfer_stage(
                &row.operation_id,
                role,
                crate::custody::network_now()?,
            )?;
            assert_eq!(
                stage.full_prepublication_record_hash()?,
                expected,
                "test: endpoint did not retain exact own-native Rebind"
            );
            let record = stage.resume_record()?;
            let manifest =
                stage.current_forward_manifest()?.ok_or("test: retained current manifest")?;
            assert_eq!(
                manifest.manifest.base_record_hash, record.base_record_hash,
                "test: Rebind rewrote historical provenance"
            );
            assert_ne!(
                manifest.manifest.base_record_hash, expected,
                "test: profile did not advance the native head"
            );
        }
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_rebind_preserves_historical_manifest_and_installs_current_native_candidate()
    -> TestResult {
        let hold = ClockHold::new();
        let result =
            crate::bus::credentials::contract_tests::deadline(Box::pin(run_install_case(true)))
                .await;
        hold.finish().await?;
        result
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_linked_frontend_installs_own_generation_and_keeps_original_credentials()
    -> TestResult {
        let hold = ClockHold::new();
        let result =
            crate::bus::credentials::contract_tests::deadline(Box::pin(run_install())).await;
        hold.finish().await?;
        result
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_linked_installation_rebases_three_target_writes_under_final_fence()
    -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(
            run_install_scenario(false, 3),
        ))
        .await;
        hold.finish().await?;
        result
    }
    async fn run_install() -> TestResult {
        Box::pin(run_install_case(false)).await
    }
    async fn run_install_case(rebind: bool) -> TestResult {
        Box::pin(run_install_scenario(rebind, 0)).await
    }
    async fn run_install_scenario(rebind: bool, races: u8) -> TestResult {
        let fixture = Box::pin(run_data_with_change(rebind)).await?;
        Box::pin(finish_install(fixture, races)).await
    }
    async fn finish_install(fixture: Linked, races: u8) -> TestResult {
        let mut fixture = Box::pin(install_in(fixture, races)).await?;
        fixture.target.account_db()?.persist_actor_state("test/installed-linked-write", &1_u64)?;
        fixture.rig.primary.lock().await?;
        fixture.rig.secondary.lock().await?;
        Ok(())
    }
    async fn install_in(
        mut fixture: Linked,
        races: u8,
    ) -> Result<Linked, Box<dyn std::error::Error>> {
        fixture
            .rig
            .secondary
            .set_install_races_for_test(races)
            .map_err(|error| format!("test: linked installation race owner: {error}"))?;
        let original = fixture.target.account_db()?.path.clone();
        let native = crate::custody::load_data_account(
            &fixture.rig.participant_b.root,
            &fixture.rig.participant_b.account_id,
            crate::custody::network_now()?,
        )?;
        let branch = native.branch_vault_ref().to_owned();
        let index = fixture.target.account_index()?;
        let wrapping = index.load_wrapped_db_key(&fixture.rig.participant_b.account_id)?;
        Box::pin(publish_linked(&mut fixture))
            .await
            .map_err(|error| format!("test: linked publish before handback: {error}"))?;
        for _ in 0..12 {
            poll_management(&mut fixture, true).await?;
            poll_management(&mut fixture, false).await?;
            let Linked { rig, target, target_service, .. } = &mut fixture;
            rig.secondary
                .service_linked_installation(target, target_service)
                .map_err(|error| format!("test: linked G3 handback: {error}"))?;
            if target.account_db()?.path != original {
                break;
            }
        }
        assert_ne!(
            fixture.target.account_db()?.path,
            original,
            "test: linked frontend retained retired G2 writer"
        );
        if races > 0 {
            assert_eq!(
                fixture.target.account_db()?.privacy_erasure_generation()?,
                13,
                "test: final rebase lost the maximum concurrent B floor"
            );
            for id in 1..=races {
                assert!(
                    matches!(
                        fixture.target.account_db()?.check_object_identity(
                            &format!("install-race-{id}"),
                            "install-race-manifest"
                        ),
                        Err(ramflux_storage::StorageError::ObjectErased)
                    ),
                    "test: G2 discarded an intervening B veto"
                );
            }
        }
        assert_eq!(
            fixture
                .target
                .account_index()?
                .load_wrapped_db_key(&fixture.rig.participant_b.account_id,)?,
            wrapping,
            "test: linked installation replaced B's original password wrapping"
        );
        let installed = crate::custody::load_account(
            &fixture.rig.participant_b.root,
            &fixture.rig.participant_b.account_id,
            crate::custody::network_now()?,
        )?;
        assert_eq!(
            installed.branch_vault_ref(),
            branch,
            "test: linked installation replaced B's device key"
        );
        require_installed_admission_and_vetoes(&fixture)?;
        assert!(
            !fixture
                .rig
                .secondary
                .service_linked_installation(&mut fixture.target, &mut fixture.target_service,)?,
            "test: linked generation was handed back twice"
        );
        if let Some(third) = &mut fixture.third {
            third::verify(&fixture.rig, &fixture.target, third).await?;
        }
        Ok(fixture)
    }
    fn require_installed_admission_and_vetoes(fixture: &Linked) -> TestResult {
        assert!(
            crate::custody::pairing::ordinary_session_admitted(
                &fixture.target,
                &fixture.rig.participant_b.account_id,
            )?,
            "test: linked frontend did not pass exact G3 admission"
        );
        assert!(
            fixture
                .target
                .account_db()?
                .check_object_identity("target-veto", "target-manifest")
                .is_err(),
            "test: own B veto was lost at installation"
        );
        assert!(
            fixture
                .target
                .account_db()?
                .check_object_identity("source-veto", "source-manifest")
                .is_err(),
            "test: A veto was lost at installation"
        );
        Ok(())
    }
    async fn poll_management(fixture: &mut Linked, primary: bool) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        rig.clock.advance_ms(1001);
        let actor = if primary { &mut rig.primary } else { &mut rig.secondary };
        drive(
            Box::pin(actor.poll_full_management_control()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked management primary={primary}: {error}"))?;
        Ok(())
    }
    async fn publish_linked(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        let operation = target
            .account_db()?
            .pairing_live_rows()?
            .into_iter()
            .next()
            .ok_or("test: linked live operation missing")?
            .operation_id;
        let prepare = ramflux_protocol::custody::pairing::local_dto::Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: operation,
            generation: rig.secondary.actor_generation(),
            transcript_hash: rig.secondary.displayed_transcript()?,
        };
        drive(
            Box::pin(rig.secondary.prepare_full_transfer(&prepare)),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked B attended prepare: {error}"))?;
        for _ in 0..72 {
            poll_management(fixture, false).await?;
            poll_management(fixture, true).await?;
            affirm_displayed_candidate(fixture, &prepare.operation_id)
                .await
                .map_err(|error| format!("test: linked source affirmation: {error}"))?;
            let Linked { rig, target, source_service, target_service, .. } = fixture;
            rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
            rig.secondary.service_full_transfer(target.account_db()?)?;
            if drive(
                Box::pin(rig.primary.advance_full_source_publication()),
                source_service,
                &rig.source.client,
                target_service,
                target,
            )
            .await
            .map_err(|error| format!("test: linked source publication: {error}"))?
            {
                return Ok(());
            }
        }
        Err("test: linked candidate did not reach actual native publication".into())
    }
    async fn affirm_displayed_candidate(fixture: &mut Linked, operation: &str) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        if rig.primary.affirmed_full_source_preservation().is_ok() {
            return Ok(());
        }
        let Ok(candidate) = rig.primary.displayed_proposal() else { return Ok(()) };
        let affirm = ramflux_protocol::custody::pairing::local_dto::TransferAffirm {
            schema: "ramflux.pairing.TransferAffirm.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: rig.primary.actor_generation(),
            transcript_hash: rig.primary.displayed_transcript()?,
            new_record_hash: candidate,
            approved: true,
        };
        drive(
            Box::pin(rig.primary.affirm_full_transfer(&affirm)),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
        Ok(())
    }
    fn resume_request(
        client: &crate::RamfluxClient,
    ) -> Result<
        ramflux_protocol::custody::pairing::local_dto::StatusRequest,
        Box<dyn std::error::Error>,
    > {
        let row = client
            .account_db()?
            .pairing_live_rows()?
            .into_iter()
            .next()
            .ok_or("test: retained live row")?;
        Ok(ramflux_protocol::custody::pairing::local_dto::StatusRequest {
            schema: "ramflux.pairing.StatusRequest.v2".into(),
            version: 2,
            operation_id: row.operation_id,
            generation: row.generation,
        })
    }
    async fn reopen_actor(
        actor: &mut PairingActor,
        participant: &std::sync::Arc<LocalPairingParticipant>,
        client: &mut crate::RamfluxClient,
        password: &'static [u8],
        primary: bool,
    ) -> Result<PairingLocalWriterService, Box<dyn std::error::Error>> {
        let retained = if primary { None } else { Some(resume_request(client)?) };
        let mut relay = None;
        actor.wrap_transport_for_test(|inner| {
            relay = Some(inner.clone());
            inner
        });
        actor.lock().await?;
        drop(client.active_account_db.take());
        if let Some(request) = retained {
            let provider = crate::custody::pairing::recipient::tests::Phrase::setup(password);
            client.active_account_db = Some(crate::bus::unlock_for_test(
                &participant.root,
                &participant.account_id,
                &request,
                &provider,
            )?);
        } else {
            client.unlock_account(&participant.account_id, password)?;
        }
        let now = crate::custody::network_now()?;
        let native =
            crate::custody::load_data_account(&participant.root, &participant.account_id, now)?;
        let id = native.local_device_id()?;
        let device = native
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == id)
            .ok_or("test: reopened branch")?;
        let mut reopened = PairingActor::new(
            PairingIdentity {
                account_id: participant.account_id.clone(),
                local_ref: DeviceRef {
                    account_anchor: native.record().body.account_anchor.clone(),
                    device_id: id.into(),
                    device_epoch: device.device_epoch,
                },
                master_public_key: Some(
                    native.record().body.master_certificate.body.master_public_key.clone(),
                ),
                base_record_hash: object_hash(native.record())?,
                base_epoch: native.record().body.device_set_epoch,
                is_primary: primary,
            },
            None,
            relay.ok_or("test: retained relay")?,
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        client.born_v3_account = Some(Box::new(native));
        reopened.set_participant(participant.clone());
        reopened.set_full_node(
            crate::custody::network_tests::node(now, ramflux_protocol::encode_base64url([29; 32]))
                .map_err(|error| error.to_string())?,
        );
        let service = reopened.bind_frontend_writer(client.account_db()?)?;
        *actor = reopened;
        Ok(service)
    }
    async fn cold_resume(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service, .. } = fixture;
        let a = resume_request(&rig.source.client)?;
        let b = resume_request(target)?;
        assert_eq!(a.operation_id, b.operation_id, "test: unrelated local stages");
        *source_service = reopen_actor(
            &mut rig.primary,
            &rig.participant_a,
            &mut rig.source.client,
            b"fresh-source-data",
            true,
        )
        .await?;
        *target_service = reopen_actor(
            &mut rig.secondary,
            &rig.participant_b,
            target,
            b"component-recipient-passphrase",
            false,
        )
        .await?;
        // The cold owners discarded their bearer tokens; wait for the specified
        // ten-second native epoch idle expiry before requesting fresh A3 keys.
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        drive(
            Box::pin(rig.primary.resume_full_data(&a)),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        drive(
            Box::pin(rig.secondary.resume_full_data(&b)),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        for (actor, request) in [(&mut rig.primary, &a), (&mut rig.secondary, &b)] {
            let stale = Confirm {
                schema: "ramflux.pairing.Confirm.v2".into(),
                version: 2,
                operation_id: request.operation_id.clone(),
                generation: request.generation,
                transcript_hash: actor.displayed_transcript()?,
                r#match: true,
            };
            assert!(
                actor.confirm(&stale).await.is_err(),
                "test: data resume accepted a stale SAS callback"
            );
            assert!(
                actor.displayed_proposal().is_err(),
                "test: data resume restored publication approval"
            );
        }
        Ok(())
    }
    fn retained_current(fixture: &Linked) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let db = fixture.rig.source.client.account_db()?;
        let request = resume_request(&fixture.rig.source.client)?;
        let stage = match db.open_full_transfer_stage(
            &request.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            crate::custody::network_now()?,
        ) {
            Ok(stage) => stage,
            Err(ramflux_storage::StorageError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        if let ramflux_storage::FullForwardResumePosition::Streaming {
            manifest,
            last_verified: Some(previous),
        } = stage.forward_resume_position()?
        {
            assert_eq!(
                manifest.manifest.snapshot_cut.0,
                previous.manifest.snapshot_cut.0 + 1,
                "test: retained CURRENT skipped a cut"
            );
            return Ok(Some(ramflux_protocol::encode_base64url(
                ramflux_protocol::custody::pairing::full_transfer::manifest_hash(&manifest)?,
            )));
        }
        Ok(None)
    }
    fn assert_fresh_resume_keys(fixture: &Linked) -> TestResult {
        let seen = fixture.rig.full_hellos.lock().map_err(|_| "test: hello observations")?;
        assert_eq!(seen.len(), 4, "test: missing original-branch reconnect proofs");
        for role in ["initiator", "responder"] {
            let mut own = seen.iter().filter(|hello| hello.role == role);
            let old = own.next().ok_or("test: initial proof")?;
            let new = own.next().ok_or("test: resumed proof")?;
            assert_ne!(old.epoch, new.epoch, "test: reconnect reused epoch");
            assert_ne!(old.hpke_key, new.hpke_key, "test: reconnect reused HPKE key");
            assert_eq!(
                old.lease.body.lease_id, new.lease.body.lease_id,
                "test: reconnect changed retained lease"
            );
        }
        Ok(())
    }
    async fn finish_resumed_data(fixture: &mut Linked) -> TestResult {
        let publications =
            fixture.rig.node.persist_calls.load(std::sync::atomic::Ordering::Acquire);
        for _ in 0..256 {
            step(fixture).await?;
            if fixture.rig.primary.full_base_disk_complete_for_test()
                && fixture.rig.secondary.full_base_disk_complete_for_test()
            {
                assert_fresh_resume_keys(fixture)?;
                assert_eq!(
                    fixture.rig.node.persist_calls.load(std::sync::atomic::Ordering::Acquire),
                    publications,
                    "test: data resume published authority without fresh attendance"
                );
                return Ok(());
            }
        }
        Err("test: cold data resume did not reach durable duplex".into())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_resume_first_object_is_current_manifest() -> TestResult {
        let hold = ClockHold::new();
        let result =
            crate::bus::credentials::contract_tests::deadline(Box::pin(resume_current())).await;
        hold.finish().await?;
        result
    }
    async fn resume_current() -> TestResult {
        let mut fixture = Box::pin(open()).await?;
        Box::pin(bootstrap(&mut fixture)).await?;
        let mut current = None;
        for _ in 0..256 {
            step(&mut fixture).await?;
            current = retained_current(&fixture)?;
            if current.is_some() {
                break;
            }
        }
        let hash = current.ok_or("test: no unverified retained CURRENT after base DV")?;
        Box::pin(cold_resume(&mut fixture)).await?;
        Box::pin(finish_resumed_data(&mut fixture)).await?;
        assert_eq!(
            fixture.rig.secondary.first_forward_position_for_test(),
            Some(crate::custody::pairing::full_epoch::FirstForwardPosition::Manifest {
                hash,
                counter: 0
            }),
            "test: reconnect restarted from historical base"
        );
        fixture.rig.primary.lock().await?;
        fixture.rig.secondary.lock().await?;
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_full_resume_idle_uses_own_dv_without_recutting_b_reverse() -> TestResult {
        let hold = ClockHold::new();
        let result =
            crate::bus::credentials::contract_tests::deadline(Box::pin(resume_idle())).await;
        hold.finish().await?;
        result
    }
    async fn resume_idle() -> TestResult {
        let mut fixture = Box::pin(run_data()).await?;
        let hash = {
            let db = fixture.rig.source.client.account_db()?;
            let request = resume_request(&fixture.rig.source.client)?;
            let stage = db.open_full_transfer_stage(
                &request.operation_id,
                ramflux_crypto::custody::pairing::PairingRole::Initiator,
                crate::custody::network_now()?,
            )?;
            let ramflux_storage::FullForwardResumePosition::Idle { manifest } =
                stage.forward_resume_position()?
            else {
                return Err("test: completed cut lacks own signed DV".into());
            };
            ramflux_protocol::encode_base64url(
                ramflux_protocol::custody::pairing::full_transfer::manifest_hash(&manifest)?,
            )
        };
        fixture.target.account_db()?.seed_full_transfer_object_veto_for_test(
            "later-b-veto",
            "later-b-manifest",
            9,
        )?;
        Box::pin(cold_resume(&mut fixture)).await?;
        Box::pin(finish_resumed_data(&mut fixture)).await?;
        assert_eq!(
            fixture.rig.secondary.first_forward_position_for_test(),
            Some(crate::custody::pairing::full_epoch::FirstForwardPosition::Idle {
                last_verified: hash,
                counter: 0
            }),
            "test: completed forward input was retransmitted"
        );
        assert_eq!(
            fixture.rig.source.client.account_db()?.privacy_erasure_generation()?,
            7,
            "test: reconnect recut B reverse after its original signed manifest"
        );
        assert_eq!(
            fixture.target.account_db()?.privacy_erasure_generation()?,
            9,
            "test: data resume lost B's newer ordinary veto"
        );
        fixture.rig.primary.lock().await?;
        fixture.rig.secondary.lock().await?;
        Ok(())
    }
}
