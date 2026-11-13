// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual two-frontend linked reverse data phase. Full publication/install acceptance is separate.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custody::pairing::{PairingIdentity, PairingLocalWriterService};
    use ramflux_protocol::custody::{DeviceRef, object_hash};
    struct Linked {
        rig: Rig,
        target: crate::RamfluxClient,
        source_service: PairingLocalWriterService,
        target_service: PairingLocalWriterService,
    }
    async fn exchange(rig: &mut Rig) -> Result<(String, String), SdkError> {
        rig.clock.advance_ms(1001);
        let a = phase(rig.primary.sync_relay().await?)?;
        rig.clock.advance_ms(1001);
        let b = phase(rig.secondary.sync_relay().await?)?;
        Ok((a, b))
    }
    async fn enroll(rig: &mut Rig) -> TestResult {
        let begun = rig
            .primary
            .begin(Begin {
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
                display_name: "Source phone".into(),
            })
            .await?;
        let Outcome::Begin { value } = begun.outcome else {
            return Err("test: enrollment invitation".into());
        };
        rig.secondary
            .join(Join {
                schema: "ramflux.pairing.Join.v2".into(),
                version: 2,
                token: value.invite_token,
                display_name: "Linked phone".into(),
            })
            .await?;
        for _ in 0..24 {
            exchange(rig).await?;
            if rig.primary.displayed_transcript().is_ok()
                && rig.secondary.displayed_transcript().is_ok()
            {
                break;
            }
        }
        let th = rig.primary.displayed_transcript()?;
        assert_eq!(th, rig.secondary.displayed_transcript()?, "test: enrollment SAS mismatch");
        for actor in [&mut rig.primary, &mut rig.secondary] {
            rig.clock.advance_ms(1001);
            actor
                .confirm(&Confirm {
                    schema: "ramflux.pairing.Confirm.v2".into(),
                    version: 2,
                    operation_id: value.operation_id.clone(),
                    generation: actor.actor_generation(),
                    transcript_hash: th.clone(),
                    r#match: true,
                })
                .await?;
        }
        for _ in 0..24 {
            if exchange(rig).await?.0 == "proposal_pending" {
                break;
            }
        }
        rig.clock.advance_ms(1001);
        rig.primary
            .approve(&Approve {
                schema: "ramflux.pairing.Approve.v2".into(),
                version: 2,
                operation_id: value.operation_id,
                generation: rig.primary.actor_generation(),
                transcript_hash: th,
                proposal_hash: rig.primary.displayed_proposal()?,
                approved: true,
            })
            .await?;
        for _ in 0..24 {
            if exchange(rig).await? == ("completed".into(), "completed".into()) {
                return Ok(());
            }
        }
        Err("test: original linked enrollment did not complete".into())
    }
    async fn open() -> Result<Linked, Box<dyn std::error::Error>> {
        let mut rig = Box::pin(Rig::open_profile(true)).await?;
        Box::pin(enroll(&mut rig)).await?;
        let mut target = crate::RamfluxClient::new();
        rig.participant_b.return_client(&mut target)?;
        rig.participant_a.return_client(&mut rig.source.client)?;
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
        Ok(Linked { rig, target, source_service, target_service })
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
        let Linked { rig, target, source_service, target_service } = fixture;
        rig.primary
            .service_full_transfer(rig.source.client.account_db()?)
            .map_err(|error| format!("test: linked source local I/O: {error}"))?;
        rig.secondary
            .service_full_transfer(target.account_db()?)
            .map_err(|error| format!("test: linked B local I/O: {error}"))?;
        rig.clock.advance_ms(1001);
        drive(
            Box::pin(rig.primary.sync_relay()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked source sync: {error}"))?;
        rig.clock.advance_ms(1001);
        drive(
            Box::pin(rig.secondary.sync_relay()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await
        .map_err(|error| format!("test: linked B sync: {error}"))?;
        settle_stream_work(rig).await;
        Ok(())
    }
    async fn bootstrap(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service } = fixture;
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
        let Linked { rig, target, source_service, target_service } = fixture;
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
        let mut fixture = Box::pin(open()).await?;
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
            if rebind
                && revised.is_none()
                && fixture.rig.primary.full_base_stream_started_for_test()
                && fixture.rig.secondary.full_base_stream_started_for_test()
                && !(fixture.rig.primary.full_base_disk_complete_for_test()
                    && fixture.rig.secondary.full_base_disk_complete_for_test())
            {
                revised = Some(advance_profile(&fixture)?);
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
        if rebind {
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
    async fn run_install() -> TestResult {
        Box::pin(run_install_case(false)).await
    }
    async fn run_install_case(rebind: bool) -> TestResult {
        let mut fixture = Box::pin(run_data_with_change(rebind)).await?;
        let original = fixture.target.account_db()?.path.clone();
        let native = crate::custody::load_account(
            &fixture.rig.participant_b.root,
            &fixture.rig.participant_b.account_id,
            crate::custody::network_now()?,
        )?;
        let branch = native.branch_vault_ref().to_owned();
        let index = fixture.target.account_index()?;
        let wrapping = index.load_wrapped_db_key(&fixture.rig.participant_b.account_id)?;
        Box::pin(publish_linked(&mut fixture)).await?;
        for _ in 0..12 {
            poll_management(&mut fixture, true).await?;
            poll_management(&mut fixture, false).await?;
            let Linked { rig, target, target_service, .. } = &mut fixture;
            rig.secondary.service_linked_installation(target, target_service)?;
            if target.account_db()?.path != original {
                break;
            }
        }
        assert_ne!(
            fixture.target.account_db()?.path,
            original,
            "test: linked frontend retained retired G2 writer"
        );
        assert!(
            crate::custody::pairing::ordinary_session_admitted(
                &fixture.target,
                &fixture.rig.participant_b.account_id,
            )?,
            "test: linked frontend did not pass exact G3 admission"
        );
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
        assert!(
            !fixture
                .rig
                .secondary
                .service_linked_installation(&mut fixture.target, &mut fixture.target_service,)?,
            "test: linked generation was handed back twice"
        );
        fixture.target.account_db()?.persist_actor_state("test/installed-linked-write", &1_u64)?;
        fixture.rig.primary.lock().await?;
        fixture.rig.secondary.lock().await?;
        Ok(())
    }
    async fn poll_management(fixture: &mut Linked, primary: bool) -> TestResult {
        let Linked { rig, target, source_service, target_service } = fixture;
        rig.clock.advance_ms(1001);
        let actor = if primary { &mut rig.primary } else { &mut rig.secondary };
        drive(
            Box::pin(actor.poll_full_management_control()),
            source_service,
            &rig.source.client,
            target_service,
            target,
        )
        .await?;
        Ok(())
    }
    async fn publish_linked(fixture: &mut Linked) -> TestResult {
        let Linked { rig, target, source_service, target_service } = fixture;
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
        .await?;
        for _ in 0..72 {
            poll_management(fixture, false).await?;
            poll_management(fixture, true).await?;
            let Linked { rig, target, source_service, target_service } = fixture;
            rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
            rig.secondary.service_full_transfer(target.account_db()?)?;
            if drive(
                Box::pin(rig.primary.advance_full_source_publication()),
                source_service,
                &rig.source.client,
                target_service,
                target,
            )
            .await?
            {
                return Ok(());
            }
        }
        Err("test: linked candidate did not reach actual native publication".into())
    }
}
