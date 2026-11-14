// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Both original data owners reconnect after B prepared and A's short approval expired.
use super::*;
use ramflux_protocol::custody::pairing::local_dto::{StatusRequest, TransferAffirm};
#[tokio::test(start_paused = true)]
async fn pairing_full_prepared_restart_requires_fresh_affirmation_before_expired_ready_renewal()
-> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let mut rig = Box::pin(Rig::open_profile(true)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
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
        .ok_or("test: full operation missing")?
        .operation_id;
    Box::pin(deliver_candidate_and_ready(&mut rig, &operation)).await?;
    let original = rig.primary.affirmed_full_source_preservation()?.clone();
    let source_relay = relay(&mut rig.primary)?;
    let target_relay = relay(&mut rig.secondary)?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    rig.source.client = crate::RamfluxClient::new();
    let mut old = crate::RamfluxClient::new();
    rig.participant_b.return_data_client(&mut old)?;
    drop(old);
    rig.now = original.body.expires_at;
    rig.clock.set_wall(rig.now);
    crate::time::FixedClock::advance_to(i64::try_from(rig.now)?);
    rig.source.client = reopen(&rig.participant_a, b"fresh-source-data")?;
    let target = reopen_staged(&rig.participant_b, &operation)?;
    rig.primary = actor(&rig.participant_a, &rig.source.client, source_relay, &operation, rig.now)?;
    rig.secondary = actor(&rig.participant_b, &target, target_relay, &operation, rig.now)?;
    let request = StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: operation,
        generation: 1,
    };
    let mut a = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
    let mut b = rig.secondary.bind_frontend_writer(target.account_db()?)?;
    assert!(
        drive(Box::pin(rig.secondary.recover_full_installation(&request)), &mut b, &target)
            .await?
            .is_none(),
        "test: positively unpublished prepared B was mistaken for installation"
    );
    drive(Box::pin(rig.primary.resume_full_data(&request)), &mut a, &rig.source.client).await?;
    drive(Box::pin(rig.secondary.resume_full_data(&request)), &mut b, &target).await?;
    Box::pin(pump(&mut rig, &mut a, &mut b, &target)).await?;
    Box::pin(review_and_renew(&mut rig, &mut a, &mut b, &target, &request, &original)).await?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
fn relay(
    actor: &mut PairingActor,
) -> Result<Arc<dyn crate::custody::pairing::PairingTransport>, Box<dyn std::error::Error>> {
    let mut saved = None;
    actor.wrap_transport_for_test(|relay| {
        saved = Some(relay.clone());
        relay
    });
    saved.ok_or_else(|| "test: original relay missing".into())
}
fn reopen(
    participant: &LocalPairingParticipant,
    password: &[u8],
) -> Result<crate::RamfluxClient, SdkError> {
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(&participant.root)?;
    client.unlock_account(&participant.account_id, password)?;
    Ok(client)
}
fn actor(
    participant: &Arc<LocalPairingParticipant>,
    client: &crate::RamfluxClient,
    relay: Arc<dyn crate::custody::pairing::PairingTransport>,
    operation: &str,
    now: u64,
) -> Result<PairingActor, Box<dyn std::error::Error>> {
    let db = client.account_db()?;
    let live = db
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == operation)
        .ok_or("test: retained operation missing")?;
    let role = if live.role == "initiator" {
        ramflux_crypto::custody::pairing::PairingRole::Initiator
    } else {
        ramflux_crypto::custody::pairing::PairingRole::Responder
    };
    let stage = db.open_full_transfer_stage(operation, role, now)?;
    let record = stage.resume_record()?;
    let local_ref = if live.role == "initiator" {
        record.grant.source_ref
    } else {
        record.grant.destination_ref
    };
    let native = participant.query.current_authority(&local_ref.account_anchor)?;
    let body = &native.publication.record.body;
    let mut actor = PairingActor::new(
        crate::custody::pairing::PairingIdentity {
            account_id: participant.account_id.clone(),
            is_primary: local_ref == body.master_certificate.body.primary_device_ref,
            local_ref,
            master_public_key: Some(body.master_certificate.body.master_public_key.clone()),
            base_record_hash: object_hash(&native.publication.record)?,
            base_epoch: body.device_set_epoch,
        },
        None,
        relay,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    actor.set_participant(participant.clone());
    actor.set_full_node(
        crate::custody::network_tests::node(now, ramflux_protocol::encode_base64url([29; 32]))
            .map_err(|error| error.to_string())?,
    );
    Ok(actor)
}
async fn pump(
    rig: &mut Rig,
    a: &mut PairingLocalWriterService,
    b: &mut PairingLocalWriterService,
    target: &crate::RamfluxClient,
) -> TestResult {
    for _ in 0..96 {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.sync_relay()), a, &rig.source.client).await?;
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.secondary.sync_relay()), b, target).await?;
        a.try_apply_client(&rig.source.client)?;
        b.try_apply_client(target)?;
        if rig.primary.full_base_disk_complete_for_test()
            && rig.secondary.full_base_disk_complete_for_test()
        {
            return Ok(());
        }
        settle_stream_work(rig).await;
    }
    Err("test: prepared cold data owners never reconstructed durable duplex".into())
}
async fn review_and_renew(
    rig: &mut Rig,
    a: &mut PairingLocalWriterService,
    b: &mut PairingLocalWriterService,
    target: &crate::RamfluxClient,
    request: &StatusRequest,
    original: &ramflux_protocol::custody::Envelope<
        ramflux_protocol::custody::pairing::full_transfer::PreservationFull,
    >,
) -> TestResult {
    for _ in 0..72 {
        drive(Box::pin(rig.secondary.poll_full_management_control()), b, target).await?;
        drive(Box::pin(rig.primary.poll_full_management_control()), a, &rig.source.client).await?;
        if rig.primary.displayed_proposal().is_ok() {
            break;
        }
    }
    assert_eq!(
        rig.primary.displayed_proposal()?,
        original.body.new_record_hash,
        "test: restarted candidate changed before fresh affirmation"
    );
    assert!(
        rig.primary.affirmed_full_source_preservation().is_err(),
        "test: restart restored signing approval"
    );
    let affirm = TransferAffirm {
        schema: "ramflux.pairing.TransferAffirm.v2".into(),
        version: 2,
        operation_id: request.operation_id.clone(),
        generation: request.generation,
        transcript_hash: original.body.transcript_hash.clone(),
        new_record_hash: original.body.new_record_hash.clone(),
        approved: true,
    };
    drive(Box::pin(rig.primary.affirm_full_transfer(&affirm)), a, &rig.source.client).await?;
    assert!(
        rig.primary.service_full_transfer(rig.source.client.account_db()?)?,
        "test: fresh affirmation did not reach original writer"
    );
    let renewed = rig.primary.affirmed_full_source_preservation()?.clone();
    assert!(
        renewed.body.expires_at > original.body.expires_at,
        "test: expired statement was not renewed"
    );
    let mut expected = original.body.clone();
    expected.expires_at = renewed.body.expires_at;
    assert!(
        expected == renewed.body,
        "test: renewal changed immutable candidate or transfer operands"
    );
    drive(Box::pin(rig.primary.poll_full_management_control()), a, &rig.source.client).await?;
    drive(Box::pin(rig.secondary.poll_full_management_control()), b, target).await?;
    assert!(
        rig.secondary.service_full_transfer(target.account_db()?)?,
        "test: renewed ready was not durably accepted by B"
    );
    Ok(())
}
