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
    let mut target = rig.secondary.bind_frontend_writer(client.account_db()?)?;
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
