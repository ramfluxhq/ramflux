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
    let mut rig = Box::pin(Rig::open()).await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    crate::client::native_test_support::pairing_history::seed(
        &rig.source.client,
        rig.participant_a.vault.as_ref(),
    )?;
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
    crate::client::native_test_support::pairing_history::verify(&rig.source.client, &target)?;
    branch_traffic::participants(&rig, &[rig.participant_a.as_ref(), rig.participant_b.as_ref()])?;
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
