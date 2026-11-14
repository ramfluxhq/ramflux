// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An unrelated enrollment rebinds retained data, while revoking B cannot resume DATA.
use super::*;
pub(super) async fn enroll_during_stream(
    fixture: &mut Linked,
) -> Result<String, Box<dyn std::error::Error>> {
    let rig = &mut fixture.rig;
    let mut management = rig.primary.ordinary_peer_for_test();
    rig.participant_a.take_client(&mut rig.source.client)?;
    std::mem::swap(&mut rig.primary, &mut management);
    let result = Box::pin(third::enroll(rig)).await;
    std::mem::swap(&mut rig.primary, &mut management);
    rig.participant_a.return_client(&mut rig.source.client)?;
    fixture.third = Some(result?);
    management.lock().await?;
    // The separate attended enrollment held A's ordinary writer and advanced the
    // relay clock beyond its ten-second idle window. Reconnect the retained DATA
    // owners through fresh original-branch A3 instead of reusing expired tokens.
    Box::pin(cold_resume(fixture)).await?;
    let rig = &fixture.rig;
    let native = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        crate::custody::network_now()?,
    )?;
    Ok(object_hash(native.record())?)
}
#[tokio::test(start_paused = true)]
async fn primary_transfer_full_head_change_mid_stream() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let fixture = Box::pin(open()).await?;
        let fixture = Box::pin(run_data_change(fixture, NativeChange::Enrollment)).await?;
        Box::pin(finish_install(fixture, 0))
            .await
            .map_err(|error| format!("test: compatible native-change installation: {error}"))?;
        Box::pin(revoked_target())
            .await
            .map_err(|error| format!("test: revoked-target DATA refusal: {error}").into())
    }))
    .await;
    hold.finish().await?;
    result
}
async fn revoked_target() -> TestResult {
    let mut fixture = Box::pin(open()).await?;
    Box::pin(bootstrap(&mut fixture)).await?;
    // Confirmation precedes the first Manifest; wait for actual B stage admission.
    let mut staged = false;
    for _ in 0..32 {
        step(&mut fixture).await?;
        for row in fixture.target.account_db()?.pairing_live_rows()? {
            if row.full_stage_reference()?.is_some() {
                staged = true;
                break;
            }
        }
        if staged {
            break;
        }
    }
    assert!(staged, "test: B never admitted its prepublication DATA stage");
    let b = crate::custody::load_data_account(
        &fixture.rig.participant_b.root,
        &fixture.rig.participant_b.account_id,
        fixture.rig.now,
    )?;
    let a = crate::custody::load_data_account(
        &fixture.rig.participant_a.root,
        &fixture.rig.participant_a.account_id,
        fixture.rig.now,
    )?;
    let primary = a.group_primary(fixture.rig.participant_a.vault.as_ref())?;
    let publication = Publication {
        record: primary.revoke_device(a.verified(), b.local_device_id()?, fixture.rig.now)?,
        compacted_ids: None,
    };
    fixture.rig.node.persist_head(&publication, fixture.rig.now)?;
    let request = resume_request(&fixture.target)?;
    let reference = fixture
        .target
        .account_db()?
        .pairing_live_rows()?
        .into_iter()
        .find(|row| row.operation_id == request.operation_id)
        .ok_or("test: B stage link missing")?
        .full_stage_reference()?
        .ok_or("test: B full stage absent")?;
    let path = fixture
        .rig
        .participant_b
        .root
        .join("custody_accounts")
        .join(&fixture.rig.participant_b.account_id)
        .join("full-transfer")
        .join(reference.stage_id);
    let mut refused = false;
    for _ in 0..16 {
        if step(&mut fixture).await.is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "test: revoked B continued full data exchange");
    assert!(
        !fixture.rig.secondary.full_base_disk_complete_for_test(),
        "test: revoked B reached semantic data completion"
    );
    let Linked { rig, target, source_service, target_service, .. } = &mut fixture;
    assert!(
        drive(
            Box::pin(rig.secondary.resume_full_data(&request)),
            source_service,
            &rig.source.client,
            target_service,
            target
        )
        .await
        .is_err(),
        "test: revoked B resumed with retained SAS keys"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    assert!(!path.try_exists()?, "test: revoked prepublication B retained its private DATA stage");
    Ok(())
}
