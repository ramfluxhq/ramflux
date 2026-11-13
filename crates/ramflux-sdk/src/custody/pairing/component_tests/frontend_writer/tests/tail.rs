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
    let (mut rig, mut source, client, mut target, request) = setup().await?;
    let mut merged = false;
    for _ in 0..96 {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.sync_relay()), &mut source, &rig.source.client).await?;
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.secondary.sync_relay()), &mut target, &client).await?;
        let a = rig.primary.transfer_status(&request).await?;
        let b = rig.secondary.transfer_status(&request).await?;
        if is_merged(&a) && is_merged(&b) {
            merged = true;
            break;
        }
    }
    assert!(
        merged,
        "test: bounded full production driver never committed both tail acknowledgements"
    );
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

async fn setup() -> Result<
    (
        Rig,
        PairingLocalWriterService,
        crate::RamfluxClient,
        PairingLocalWriterService,
        StatusRequest,
    ),
    Box<dyn std::error::Error>,
> {
    let mut rig = Box::pin(Rig::open_profile(true)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
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
    let (mut rig, mut source, mut client, mut target, request) = setup().await?;
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
