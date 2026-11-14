// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A lost Rebind send is replayed after fresh A3 without recutting data or restoring approval.
use super::*;
use ed25519_dalek::Signer as _;
use ramflux_crypto::custody::{VerifiedRecord, pairing::PairingRole};
use ramflux_protocol::custody::pairing::full_transfer::DataPacket;

#[tokio::test(start_paused = true)]
async fn pairing_full_resume_replays_retained_native_rebind_before_current_candidate() -> TestResult
{
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let mut fixture = Box::pin(run_data()).await?;
    let expected = advance_profile(&fixture)?;
    let anchor = fixture
        .rig
        .source
        .client
        .account_index()?
        .account(&fixture.rig.participant_a.account_id)?
        .principal_commitment;
    let current = fixture.rig.participant_a.full_native_head(&anchor)?;
    retain_without_send(&fixture, &current)?;
    // Only A has committed the exact signed frame; no relay send or B observation occurred.
    let request = resume_request(&fixture.target)?;
    let stage = fixture.target.account_db()?.open_full_transfer_stage(
        &request.operation_id,
        PairingRole::Responder,
        crate::custody::network_now()?,
    )?;
    assert_ne!(
        stage.full_prepublication_record_hash()?,
        expected,
        "test: lost-send setup already changed B's independent native binding"
    );
    drop(stage);
    Box::pin(cold_resume(&mut fixture)).await?;
    Box::pin(finish_resumed_data(&mut fixture)).await?;
    verify_rebound_stages(&fixture, &expected)?;
    Box::pin(finish_install(fixture, 0)).await
}
fn retain_without_send(
    fixture: &Linked,
    current: &VerifiedRecord,
) -> Result<DataPacket, Box<dyn std::error::Error>> {
    let request = resume_request(&fixture.rig.source.client)?;
    let now = crate::custody::network_now()?;
    let db = fixture.rig.source.client.account_db()?;
    let (mut packet, grant) = {
        let mut stage =
            db.open_full_transfer_stage(&request.operation_id, PairingRole::Initiator, now)?;
        (stage.prepare_full_rebind(current, now)?, stage.resume_record()?.grant)
    };
    let signature = fixture.rig.participant_a.with_full_branch_vault(
        &grant.source_ref,
        &grant.branch_keys.source,
        |branch| {
            Ok(ramflux_protocol::encode_base64url(
                branch
                    .signing
                    .signing_key
                    .sign(
                        &packet
                            .rebind_signing_bytes()
                            .map_err(|error| crate::custody::pairing::transport::wire(&error))?,
                    )
                    .to_bytes(),
            ))
        },
    )?;
    let DataPacket::Rebind { source_signature, .. } = &mut packet else {
        return Err("test: actual native rebind draft changed arm".into());
    };
    *source_signature = signature;
    db.open_full_transfer_stage(&request.operation_id, PairingRole::Initiator, now)?
        .retain_full_rebind(current, &packet, now)?;
    Ok(packet)
}

#[tokio::test(start_paused = true)]
async fn pairing_full_prepared_rebind_retry_cannot_change_candidate_head() -> TestResult {
    let hold = ClockHold::new();
    let result =
        crate::bus::credentials::contract_tests::deadline(Box::pin(prepared_retry())).await;
    hold.finish().await?;
    result
}
async fn prepared_retry() -> TestResult {
    let mut fixture = Box::pin(run_data()).await?;
    let expected = advance_profile(&fixture)?;
    let anchor = fixture
        .rig
        .source
        .client
        .account_index()?
        .account(&fixture.rig.participant_a.account_id)?
        .principal_commitment;
    let current = fixture.rig.participant_a.full_native_head(&anchor)?;
    let packet = retain_without_send(&fixture, &current)?;
    let request = resume_request(&fixture.target)?;
    let now = crate::custody::network_now()?;
    fixture
        .target
        .account_db()?
        .open_full_transfer_stage(&request.operation_id, PairingRole::Responder, now)?
        .retain_full_rebind(&current, &packet, now)?;
    let prepare = ramflux_protocol::custody::pairing::local_dto::Prepare {
        schema: "ramflux.pairing.Prepare.v2".into(),
        version: 2,
        operation_id: request.operation_id.clone(),
        generation: request.generation,
        transcript_hash: fixture.rig.secondary.displayed_transcript()?,
    };
    drive(
        Box::pin(fixture.rig.secondary.prepare_full_transfer(&prepare)),
        &mut fixture.source_service,
        &fixture.rig.source.client,
        &mut fixture.target_service,
        &fixture.target,
    )
    .await?;
    let before =
        fixture.target.account_db()?.pairing_head()?.ok_or("test: real J3 head missing")?;
    fixture
        .target
        .account_db()?
        .open_full_transfer_stage(&request.operation_id, PairingRole::Responder, now)?
        .retain_full_rebind(&current, &packet, now)?;
    assert_eq!(
        fixture.target.account_db()?.pairing_head()?,
        Some(before.clone()),
        "test: identical authenticated rebind retry mutated J3"
    );
    advance_profile(&fixture)?;
    let changed = fixture.rig.participant_a.full_native_head(&anchor)?;
    let changed_packet = retain_without_send(&fixture, &changed)?;
    let mut stage = fixture.target.account_db()?.open_full_transfer_stage(
        &request.operation_id,
        PairingRole::Responder,
        now,
    )?;
    assert!(
        matches!(
            stage.retain_full_rebind(&changed, &changed_packet, now),
            Err(ramflux_storage::StorageError::PairingField("HeadChanged"))
        ),
        "test: an original-A signed new native head rebound the prepared B candidate"
    );
    assert_eq!(
        stage.full_prepublication_record_hash()?,
        expected,
        "test: refused post-J3 native change replaced its immutable binding"
    );
    drop(stage);
    assert_eq!(
        fixture.target.account_db()?.pairing_head()?,
        Some(before),
        "test: refused post-J3 native change erased candidate uncertainty"
    );
    fixture.rig.primary.lock().await?;
    fixture.rig.secondary.lock().await?;
    Ok(())
}
