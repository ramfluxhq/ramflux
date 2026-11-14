// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live local ciphertext pauses data completion and stays present; no upload or absence is invented.
//! Portable object owners remain separately closed until their typed codecs are implemented.
use super::*;
use ramflux_protocol::custody::pairing::{full_transfer::FullError, local_dto::Cancel};
const MEDIA: &str = "local-media-after-cut";
const PLAINTEXT: &[u8] = b"present private local media must not become an absence row";
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_local_attachment_is_not_silent_absence() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        Box::pin(after_base()).await?;
        Box::pin(after_candidate()).await
    }))
    .await;
    hold.finish().await?;
    result
}
async fn after_base() -> TestResult {
    let mut rig = Box::pin(Rig::open_profile(true)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    let mut source = rig.primary.bind_frontend_writer(rig.source.client.account_db()?)?;
    Box::pin(bootstrap(&mut rig, &mut source))
        .await
        .map_err(|error| format!("test: local-media original bootstrap: {error}"))?;
    let base = Box::pin(hold_base_application(&mut rig, &mut source))
        .await
        .map_err(|error| format!("test: local-media base barrier: {error}"))?;
    rig.source.client.put_encrypted_object(MEDIA, PLAINTEXT)?;
    {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: held base target owner")?;
        base.apply(slot.as_ref().ok_or("test: held base writer absent")?)
            .map_err(|error| format!("test: actual held base application: {error}"))?;
    }
    let mut refused = false;
    for _ in 0..128 {
        rig.primary.service_full_transfer(rig.source.client.account_db()?)?;
        {
            let slot = rig.participant_b.db.lock().map_err(|_| "test: source cut target owner")?;
            rig.secondary
                .service_full_transfer(slot.as_ref().ok_or("test: target writer absent")?)?;
        }
        rig.clock.advance_ms(1001);
        let result =
            drive(Box::pin(rig.primary.sync_relay()), &mut source, &rig.source.client).await;
        if matches!(
            &result,
            Err(SdkError::PairingCode("AttachmentNotRemote")
                | SdkError::PairingField("AttachmentNotRemote"))
        ) {
            refused = true;
            break;
        }
        result.map_err(|error| format!("test: source post-base media refusal: {error}"))?;
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.secondary.sync_relay()), &mut source, &rig.source.client)
            .await
            .map_err(|error| format!("test: target post-base media: {error}"))?;
        settle_stream_work(&rig).await;
        if rig.primary.full_background_error() == Some(FullError::AttachmentNotRemote) {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "test: local-only object introduced after base did not refuse final data completion"
    );
    assert!(
        !rig.secondary.full_base_disk_complete_for_test(),
        "test: unresolved local ciphertext reached final semantic DV"
    );
    assert!(
        rig.source.client.account_db()?.pairing_head()?.is_none(),
        "test: unresolved local media entered J3 publication"
    );
    assert_present(&rig.source.client)?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
async fn hold_base_application(
    rig: &mut Rig,
    source: &mut PairingLocalWriterService,
) -> Result<FullLocalIoLoan, Box<dyn std::error::Error>> {
    for _ in 0..96 {
        rig.primary
            .service_full_transfer_client(&rig.source.client)
            .map_err(|error| format!("test: base barrier source local service: {error}"))?;
        {
            let slot = rig.participant_b.db.lock().map_err(|_| "test: base target owner")?;
            if let Some(loan) = rig
                .secondary
                .hold_receiver_application_for_test(
                    slot.as_ref().ok_or("test: base target writer absent")?,
                )
                .map_err(|error| format!("test: base barrier target loan: {error}"))?
            {
                return Ok(loan);
            }
        }
        if !rig.primary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(Box::pin(rig.primary.sync_relay()), source, &rig.source.client).await?;
        if !rig.secondary.full_data_worker_owns_relay() {
            rig.clock.advance_ms(1001);
        }
        drive(Box::pin(rig.secondary.sync_relay()), source, &rig.source.client).await?;
        settle_stream_work(rig).await;
    }
    Err("test: original base never reached actual semantic application".into())
}
async fn after_candidate() -> TestResult {
    let (mut rig, mut source, client, mut target, request) = Box::pin(setup_with_hooks(
        |_, _| Ok(()),
        |client| {
            client.put_encrypted_object(MEDIA, PLAINTEXT)?;
            Ok(())
        },
    ))
    .await?;
    let mut pending = false;
    for _ in 0..96 {
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.primary.sync_relay()), &mut source, &rig.source.client).await?;
        rig.clock.advance_ms(1001);
        drive(Box::pin(rig.secondary.sync_relay()), &mut target, &client).await?;
        let status = rig.primary.transfer_status(&request).await?;
        if matches!(status.outcome, Outcome::FullStatus { value } if value.result == Some(FullError::AttachmentNotRemote) && value.tail_status == FullTailStatus::Pending)
        {
            pending = true;
            break;
        }
    }
    assert!(pending, "test: J3-to-J6 local object was silently reported copied or missing");
    assert!(
        !is_merged(&rig.secondary.transfer_status(&request).await?),
        "test: B marked an unresolved source media tail merged"
    );
    assert_present(&rig.source.client)?;
    assert!(
        client.decrypt_object(MEDIA).is_err(),
        "test: B claimed readable content absent from its supported union"
    );
    assert!(
        crate::custody::pairing::ordinary_session_admitted(&client, &rig.participant_b.account_id)?,
        "test: incomplete data tail revoked positively installed B authority"
    );
    let cancel = Cancel {
        schema: "ramflux.pairing.Cancel.v2".into(),
        version: 2,
        operation_id: request.operation_id.clone(),
        generation: request.generation,
    };
    let result = drive(Box::pin(rig.secondary.tail_abandon(&cancel)), &mut target, &client).await?;
    assert!(
        matches!(result.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Abandoned),
        "test: explicit incomplete-copy abandonment became merged"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
fn assert_present(client: &crate::RamfluxClient) -> TestResult {
    assert_eq!(
        client.decrypt_object(MEDIA)?,
        PLAINTEXT,
        "test: availability refusal discarded original A media"
    );
    let db = client.account_db()?;
    assert_eq!(
        db.backup_missing_count()?,
        0,
        "test: present local ciphertext became a missing reference"
    );
    let tables = db.test_table_fingerprints(&[])?;
    assert!(
        tables.get("backup_missing_attachment").is_none_or(Vec::is_empty),
        "test: pairing invented an absence row for present ciphertext"
    );
    assert!(
        tables.get("object_transfer_state").is_some_and(Vec::is_empty),
        "test: pairing started an ordinary upload without authorization"
    );
    Ok(())
}
