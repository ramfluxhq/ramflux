// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real SAS enrollment followed by ordinary local history/group restoration, without wire claims.
use super::*;
#[tokio::test(start_paused = true)]
async fn pairing_enrollment_restores_existing_history_with_a_fresh_group_sender() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    use crate::client::native_test_support::{Fixture, pairing_history};
    let mut rig = Box::pin(Rig::open()).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    let source_native = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        crate::custody::network_now()?,
    )?;
    let source_device = source_native.local_device_id()?.to_owned();
    rig.source
        .client
        .initialize_born_v3_branch(&source_device, rig.participant_a.vault.clone())
        .await?;
    let mut seeding = Fixture::adopt(
        std::mem::take(&mut rig.source.client),
        &rig.participant_a.account_id,
        &source_device,
        source_native.record().clone(),
    )
    .map_err(|error| format!("test: adopt source: {error}"))?;
    let seeded = Box::pin(pairing_history::seed(&mut seeding, rig.source.vault.as_ref()))
        .await
        .map_err(|error| format!("test: seed: {error}"))?;
    rig.source.client = seeding.into_client();
    rig.participant_a.take_client(&mut rig.source.client)?;
    Box::pin(super::enrollment::enroll(&mut rig)).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    let mut target = crate::RamfluxClient::new();
    rig.participant_b.return_client(&mut target)?;
    for (client, participant) in
        [(&mut rig.source.client, &rig.participant_a), (&mut target, &rig.participant_b)]
    {
        let native = crate::custody::load_account(
            &participant.root,
            &participant.account_id,
            crate::custody::network_now()?,
        )?;
        client
            .initialize_born_v3_branch(native.local_device_id()?, participant.vault.clone())
            .await?;
        assert!(
            ordinary_session_admitted(client, &participant.account_id)?,
            "test: enrolled history participant remained fenced"
        );
    }
    let mut fixtures = Vec::new();
    for (client, participant) in
        [(std::mem::take(&mut rig.source.client), &rig.participant_a), (target, &rig.participant_b)]
    {
        let native = crate::custody::load_account(
            &participant.root,
            &participant.account_id,
            crate::custody::network_now()?,
        )?;
        fixtures.push(
            Fixture::adopt(
                client,
                &participant.account_id,
                native.local_device_id()?,
                native.record().clone(),
            )
            .map_err(|error| format!("test: adopt after enrollment: {error}"))?,
        );
    }
    let mut target = fixtures.pop().ok_or("test: target fixture")?;
    let source = fixtures.pop().ok_or("test: source fixture")?;
    Box::pin(pairing_history::verify(&source, &mut target, &seeded))
        .await
        .map_err(|error| format!("test: verify: {error}"))?;
    rig.source.client = source.into_client();
    branch_traffic::participants(&rig, &[rig.participant_a.as_ref(), rig.participant_b.as_ref()])?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pairing_history_step_refuses_while_the_head_publication_is_pending() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(pending_gate())).await;
    hold.finish().await?;
    result
}
async fn pending_gate() -> TestResult {
    let mut rig = Box::pin(Rig::open()).await?;
    Box::pin(super::enrollment::enroll(&mut rig)).await?;
    let mut target = crate::RamfluxClient::new();
    rig.participant_b.return_client(&mut target)?;
    let native = crate::custody::load_account(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
        crate::custody::network_now()?,
    )?;
    target
        .initialize_born_v3_branch(native.local_device_id()?, rig.participant_b.vault.clone())
        .await?;
    let root = target.own_account_anchor()?;
    target
        .require_native_publication_settled(&root)
        .map_err(|error| format!("test: admitted device was refused: {error}"))?;
    // Losing the installed marker while the adoption row remains is exactly an unsettled head.
    std::fs::remove_file(super::super::install_store::installed_path(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
    ))?;
    assert!(
        matches!(
            target.require_native_publication_settled(&root),
            Err(SdkError::PairingCode("PublicationPending"))
        ),
        "test: a history step ran while the head publication was pending"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
