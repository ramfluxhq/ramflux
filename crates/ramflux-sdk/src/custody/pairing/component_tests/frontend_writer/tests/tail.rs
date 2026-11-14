// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full production tail driver with two actual frontend owners and the native relay.
use super::*;
use ramflux_protocol::custody::pairing::local_dto::{FullTailStatus, Outcome, StatusRequest};
#[tokio::test(start_paused = true)]
async fn primary_transfer_full_catch_up_and_tail_cover_post_cut() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let (mut rig, mut source, client, mut target, request) = Box::pin(setup()).await?;
    Box::pin(merge(&mut rig, &mut source, &client, &mut target, &request)).await?;
    let db = client.account_db()?;
    for key in ["driver-tail", "driver-independent-b"] {
        assert!(
            matches!(
                db.check_object_identity(key, "driver-manifest"),
                Err(ramflux_storage::StorageError::ObjectErased)
            ),
            "test: full tail lost source or independent B veto {key}"
        );
    }
    db.check_object_identity("driver-later", "driver-manifest")?;
    assert_eq!(
        db.privacy_erasure_generation()?,
        500,
        "test: tail rolled back independent B generation"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(&client, &rig.participant_b.account_id)?,
        "test: tail shutdown revoked ordinary installed B"
    );
    Ok(())
}
fn is_merged(result: &ramflux_protocol::custody::pairing::local_dto::LocalResult) -> bool {
    matches!(&result.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Merged)
}

type TailFixture = (
    Rig,
    PairingLocalWriterService,
    crate::RamfluxClient,
    PairingLocalWriterService,
    StatusRequest,
);
async fn setup() -> Result<TailFixture, Box<dyn std::error::Error>> {
    Box::pin(setup_with_source(|_, _| Ok(()))).await
}
async fn setup_with_source(
    seed: impl FnOnce(&crate::RamfluxClient, &Arc<full_relay::NodeEvidence>) -> TestResult,
) -> Result<TailFixture, Box<dyn std::error::Error>> {
    Box::pin(setup_with_hooks(seed, |_| Ok(()))).await
}
async fn setup_with_hooks(
    seed: impl FnOnce(&crate::RamfluxClient, &Arc<full_relay::NodeEvidence>) -> TestResult,
    before_publication: impl FnOnce(&mut crate::RamfluxClient) -> TestResult,
) -> Result<TailFixture, Box<dyn std::error::Error>> {
    let mut rig = Box::pin(Rig::open_profile(true)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    seed(&rig.source.client, &rig.wire_evidence)?;
    let mut source = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
    Box::pin(bootstrap(&mut rig, &mut source)).await?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let operation = rig
        .source
        .client
        .account_db()?
        .pairing_live_rows()?
        .into_iter()
        .next()
        .ok_or("test: full source invitation missing")?
        .operation_id;
    rig.source.client.account_db()?.seed_full_transfer_object_veto_for_test(
        "driver-tail",
        "driver-manifest",
        400,
    )?;
    Box::pin(deliver_candidate_and_ready(&mut rig, &operation)).await?;
    before_publication(&mut rig.source.client)?;
    assert!(
        drive(
            Box::pin(rig.primary.advance_full_source_publication()),
            &mut source,
            &rig.source.client
        )
        .await?,
        "test: tail fixture failed to publish J6"
    );
    rig.source.client.account_db()?.seed_full_transfer_object_veto_for_test(
        "driver-later",
        "driver-manifest",
        401,
    )?;
    Box::pin(complete_full_installation(&mut rig, &operation)).await?;
    let mut client = crate::RamfluxClient::new();
    rig.participant_b.return_client(&mut client)?;
    let target = rig.secondary.bind_frontend_writer(client.account_db()?)?;
    client.account_db()?.seed_full_transfer_object_veto_for_test(
        "driver-independent-b",
        "driver-manifest",
        500,
    )?;
    let request = StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: operation,
        generation: 1,
    };
    Ok((rig, source, client, target, request))
}

#[tokio::test(start_paused = true)]
async fn pairing_full_tail_lease_margin_and_head_change_outcome() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(unavailable())).await;
    hold.finish().await?;
    result
}
async fn unavailable() -> TestResult {
    use ramflux_protocol::custody::pairing::{full_transfer::FullError, local_dto::Cancel};
    let (mut rig, mut source, mut client, mut target, request) = Box::pin(setup()).await?;
    let before = rig.source.client.account_db()?.privacy_erasure_generation()?;
    let native = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        rig.now,
    )?;
    let source_id = native.local_device_id()?.to_owned();
    let anchor = native.record().body.account_anchor.clone();
    rig.participant_b.take_client(&mut client)?;
    let current = rig.node.current_authority(&anchor)?;
    rig.now = rig
        .now
        .max(current.publication.record.body.issued_at)
        .checked_add(1)
        .ok_or("test: head timestamp overflow")?;
    crate::time::FixedClock::advance_to(i64::try_from(rig.now)?);
    super::super::super::generation::revocation::revoke_source(&rig, &source_id)?;
    rig.participant_b.return_client(&mut client)?;
    rig.clock.advance_ms(1001);
    assert!(
        drive(Box::pin(rig.secondary.sync_relay()), &mut target, &client).await.is_err(),
        "test: revoked original A admitted a new tail"
    );
    let status = rig.secondary.transfer_status(&request).await?;
    let Outcome::FullStatus { value } = status.outcome else {
        return Err("test: full pending status missing".into());
    };
    assert_eq!(
        value.tail_status,
        FullTailStatus::Pending,
        "test: native head change auto-abandoned data"
    );
    assert_eq!(
        value.result,
        Some(FullError::HeadChanged),
        "test: tail head-change reason was lost"
    );
    crate::time::FixedClock::advance_to(i64::try_from(value.lease_expires_at)?);
    let status = rig.secondary.transfer_status(&request).await?;
    let Outcome::FullStatus { value } = status.outcome else {
        return Err("test: expired full status missing".into());
    };
    assert_eq!(
        value.tail_status,
        FullTailStatus::Pending,
        "test: expiry auto-completed an incomplete tail"
    );
    assert_eq!(value.result, Some(FullError::LeaseExpired), "test: tail expiry reason was lost");
    let cancel = Cancel {
        schema: "ramflux.pairing.Cancel.v2".into(),
        version: 2,
        operation_id: request.operation_id.clone(),
        generation: request.generation,
    };
    assert!(
        rig.secondary.cancel(&cancel).await.is_err(),
        "test: ordinary post-J6 cancel abandoned data"
    );
    let result = drive(Box::pin(rig.secondary.tail_abandon(&cancel)), &mut target, &client).await?;
    assert!(
        matches!(result.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Abandoned),
        "test: explicit B abandonment lost terminal state"
    );
    assert!(
        drive(Box::pin(rig.primary.tail_abandon(&cancel)), &mut source, &rig.source.client)
            .await
            .is_err(),
        "test: A was allowed to abandon B's tail"
    );
    assert_eq!(
        rig.source.client.account_db()?.privacy_erasure_generation()?,
        before,
        "test: B abandonment changed A's ordinary data"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}

async fn merge(
    rig: &mut Rig,
    source: &mut PairingLocalWriterService,
    client: &crate::RamfluxClient,
    target: &mut PairingLocalWriterService,
    request: &StatusRequest,
) -> TestResult {
    let mut merged = false;
    for turn in 0..96 {
        eprintln!("test: tail merge turn={turn} source step");
        if !rig.primary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(Box::pin(rig.primary.sync_relay()), source, &rig.source.client).await?;
        eprintln!("test: tail merge turn={turn} target step");
        if !rig.secondary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(Box::pin(rig.secondary.sync_relay()), target, client).await?;
        eprintln!("test: tail merge turn={turn} status step");
        let a = rig.primary.transfer_status(request).await?;
        let b = rig.secondary.transfer_status(request).await?;
        if is_merged(&a) && is_merged(&b) {
            merged = true;
            break;
        }
        // Advance a protocol turn only for a fresh cold epoch. Normal tail work is
        // directly pumped above; it must not consume virtual time while copying data.
        if rig.primary.full_tail_epoch_in_flight_for_test()
            || rig.secondary.full_tail_epoch_in_flight_for_test()
        {
            settle_stream_work(rig).await;
        } else {
            tokio::task::yield_now().await;
            rig.primary.settle_full_local_jobs_for_test().await;
            rig.secondary.settle_full_local_jobs_for_test().await;
        }
    }
    assert!(
        merged,
        "test: bounded full production driver never committed both tail acknowledgements: A={:?} B={:?}",
        tail_progress(&rig.primary.transfer_status(request).await?),
        tail_progress(&rig.secondary.transfer_status(request).await?)
    );
    Ok(())
}
fn tail_progress(reply: &LocalResult) -> String {
    match &reply.outcome {
        Outcome::FullStatus { value } => format!(
            "stage={:?} tail={:?} error={:?} bytes={}/{} cut={}",
            value.stage,
            value.tail_status,
            value.result,
            value.bytes_durable.0,
            value.bytes_total.0,
            value.cut.0
        ),
        _ => "test: full status absent".into(),
    }
}
#[tokio::test(start_paused = true)]
async fn pairing_stage_unlock_snapshot_resume_and_cleanup() -> TestResult {
    let hold = ClockHold::new();
    let result =
        crate::bus::credentials::contract_tests::deadline(Box::pin(cold_cleanup(false))).await;
    hold.finish().await?;
    result
}
async fn cold_cleanup(replay: bool) -> TestResult {
    let (mut rig, mut source, client, mut target, request) = Box::pin(setup()).await?;
    let replay = if replay { Some(replay::original(&rig, &request)?) } else { None };
    Box::pin(merge(&mut rig, &mut source, &client, &mut target, &request)).await?;
    for (participant, db) in [
        (&rig.participant_a, rig.source.client.account_db()?),
        (&rig.participant_b, client.account_db()?),
    ] {
        let row = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == request.operation_id)
            .ok_or("test: terminal operation missing")?;
        let reference = row.full_stage_reference()?.ok_or("test: terminal stage link missing")?;
        let path = participant
            .root
            .join("custody_accounts")
            .join(&participant.account_id)
            .join("full-transfer")
            .join(reference.stage_id);
        assert!(
            !path.try_exists()?,
            "test: merged operation retained its stage files and wrapped data key"
        );
    }
    let mut source_relay = None;
    let mut target_relay = None;
    rig.primary.wrap_transport_for_test(|relay| {
        source_relay = Some(relay.clone());
        relay
    });
    rig.secondary.wrap_transport_for_test(|relay| {
        target_relay = Some(relay.clone());
        relay
    });
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    if let Some((hello, origin)) = replay {
        // The data-only node can forget its idle epoch while durable endpoint
        // completion remains authoritative. A replayed live lease is no resume proof.
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        source_relay
            .as_ref()
            .ok_or("test: original replay transport")?
            .full_transport()
            .ok_or("test: original full relay port")?
            .hello_full(&origin, &hello)
            .await?;
    }
    rig.source.client = crate::RamfluxClient::new();
    drop(client);
    let source_client = reopen(&rig.participant_a, b"fresh-source-data")?;
    let target_client = reopen(&rig.participant_b, b"component-recipient-passphrase")?;
    Box::pin(cold_status(
        rig.participant_a.clone(),
        &source_client,
        source_relay.ok_or("test: source relay")?,
        &request,
    ))
    .await?;
    Box::pin(cold_status(
        rig.participant_b.clone(),
        &target_client,
        target_relay.ok_or("test: target relay")?,
        &request,
    ))
    .await?;
    assert_eq!(
        source_client.account_db()?.privacy_erasure_generation()?,
        401,
        "test: source cleanup changed its ordinary data"
    );
    assert_eq!(
        target_client.account_db()?.privacy_erasure_generation()?,
        500,
        "test: target cleanup changed independent B data"
    );
    Ok(())
}
fn reopen(
    participant: &LocalPairingParticipant,
    password: &[u8],
) -> Result<crate::RamfluxClient, Box<dyn std::error::Error>> {
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(&participant.root)?;
    assert!(
        client.unlock_account(&participant.account_id, b"wrong-stage-reopen-password").is_err(),
        "test: removed stage bypassed original data wrapping"
    );
    client.unlock_account(&participant.account_id, password)?;
    Ok(client)
}
async fn cold_status(
    participant: Arc<LocalPairingParticipant>,
    client: &crate::RamfluxClient,
    relay: Arc<dyn PairingTransport>,
    request: &StatusRequest,
) -> TestResult {
    let native = crate::custody::load_data_account(
        &participant.root,
        &participant.account_id,
        crate::custody::network_now()?,
    )?;
    let adoption =
        client.account_db()?.pairing_adoption()?.ok_or("test: terminal adoption missing")?;
    let reference: ramflux_protocol::custody::DeviceRef =
        ramflux_protocol::parse_i_json(&adoption.local_ref)?;
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: participant.account_id.clone(),
            is_primary: reference
                == native.record().body.master_certificate.body.primary_device_ref,
            local_ref: reference,
            master_public_key: Some(
                native.record().body.master_certificate.body.master_public_key.clone(),
            ),
            base_record_hash: object_hash(native.record())?,
            base_epoch: native.record().body.device_set_epoch,
        },
        None,
        relay,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    actor.set_participant(participant);
    actor.set_full_node(
        crate::custody::network_tests::node(
            crate::custody::network_now()?,
            encode_base64url([29; 32]),
        )
        .map_err(|error| error.to_string())?,
    );
    let mut service = actor.bind_frontend_writer(client.account_db()?)?;
    let result = drive(Box::pin(actor.transfer_status(request)), &mut service, client).await?;
    assert!(is_merged(&result), "test: removed stage lost durable terminal status");
    assert!(
        actor.displayed_transcript().is_err(),
        "test: terminal cold status restored SAS context"
    );
    assert!(actor.displayed_proposal().is_err(), "test: terminal cold status restored approval");
    assert!(
        matches!(
            drive(Box::pin(actor.resume_full_data(request)), &mut service, client).await,
            Err(SdkError::PairingCode("PublicationPending"))
        ),
        "test: a completed endpoint did not enforce its durable terminal phase"
    );
    let repeated = drive(Box::pin(actor.transfer_status(request)), &mut service, client).await?;
    assert!(is_merged(&repeated), "test: replay changed durable completion");
    actor.lock().await?;
    Ok(())
}

mod privacy;
mod source_data;

mod hostile;

mod attachment;

mod hostile_context;
mod replay;
