// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-side cancellation of an already escaped exact candidate, without claiming B resume.
use super::{ClockHold, TestResult, bootstrap_full_rig, finish_owned_stream, prepare_candidate};
use ramflux_protocol::custody::{object_hash, pairing::local_dto::Cancel};
use std::sync::atomic::Ordering;
#[tokio::test(start_paused = true)]
async fn pairing_full_source_cancel_fences_off_loan_submission_and_retains_uncertain_candidate()
-> TestResult {
    let hold = ClockHold::new();
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let prepared = prepare_candidate(&mut rig, &operation).await?;
    rig.node.lose_next_reply.store(true, Ordering::Release);
    assert!(prepared.source_submission.submit().is_err());
    let count = rig.node.persist_calls.load(Ordering::Acquire);
    rig.participant_a.take_client(&mut rig.source.client)?;
    let before = rig
        .participant_a
        .db
        .lock()
        .map_err(|_| "source before cancel")?
        .as_ref()
        .ok_or("writer")?
        .pairing_head()?
        .ok_or("intent")?;
    assert_eq!(before.state, "submitted");
    rig.primary
        .cancel(&Cancel {
            schema: "ramflux.pairing.Cancel.v2".into(),
            version: 2,
            operation_id: operation.clone(),
            generation: before.generation,
        })
        .await?;
    let after = rig
        .participant_a
        .db
        .lock()
        .map_err(|_| "source after cancel")?
        .as_ref()
        .ok_or("writer")?
        .pairing_head()?
        .ok_or("retained intent")?;
    assert_eq!(before, after, "cancel erased an uncertain native candidate");
    rig.participant_a.return_client(&mut rig.source.client)?;
    assert!(
        prepared.source_submission.submit().is_err(),
        "cancelled ceremony revived an off-loan native submission"
    );
    assert_eq!(
        rig.node.persist_calls.load(Ordering::Acquire),
        count,
        "cancelled source reached native persistence"
    );
    let authority = rig.participant_b.query.current_authority(&prepared.install.account_anchor)?;
    assert_eq!(object_hash(&authority.publication.record)?, before.candidate_hash);
    let key = rig.participant_b.vault.load_primary(
        prepared.install.primary_vault_ref.as_deref().ok_or("B primary reference")?,
    )?;
    assert_eq!(
        key.public_key(),
        prepared.publication.record.body.master_certificate.body.self_signing_public_key,
        "source cancel removed B's possibly published primary"
    );
    drop(key);
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    hold.finish().await?;
    Ok(())
}
