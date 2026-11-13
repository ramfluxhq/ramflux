// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full handover's new primary revokes only A; stale observations cannot revive A on restart.
use super::{
    ClockHold, Rig, TestResult, bootstrap_full_rig, finish_owned_stream, install_live_generation,
    publication,
};
use crate::custody::{
    self,
    pairing::{
        HeadKind, HeadWrite, PairingAuthorityQuery, ordinary_session_admitted, publish_head,
    },
};
use ramflux_protocol::custody::{CustodyAuthority, object_hash};

#[tokio::test(start_paused = true)]
async fn pairing_revocation_survives_stale_node_and_restart() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
    rig.primary.sync_relay().await?;
    rig.participant_a.return_client(&mut rig.source.client)?;
    Box::pin(finish_owned_stream(&mut rig)).await?;
    let published = Box::pin(publication(&mut rig, &operation)).await?;
    let before = published.authority.clone();
    install_live_generation(&rig, &operation, published)?;
    rig.now = rig
        .now
        .max(before.publication.record.body.issued_at)
        .checked_add(1)
        .ok_or("test: revocation timestamp overflow")?;
    crate::time::FixedClock::advance_to(i64::try_from(rig.now)?);
    let old_source =
        custody::load_account(&rig.participant_a.root, &rig.participant_a.account_id, rig.now)?;
    let source_id = old_source.local_device_id()?.to_owned();
    let head = revoke_source(&rig, &source_id)?;
    let observed = rig.node.current_authority(&before.publication.record.body.account_anchor)?;
    assert_eq!(
        object_hash(&observed.publication.record)?,
        head,
        "test: revoke acknowledgement differed from independent own native query"
    );
    assert_eq!(
        observed.publication.record.body.devices.len(),
        before.publication.record.body.devices.len(),
        "test: revocation deleted retained device entries"
    );
    for old in &before.publication.record.body.devices {
        let current = observed
            .publication
            .record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == old.device_id)
            .ok_or("test: revoked roster entry missing")?;
        if old.device_id == source_id {
            assert_eq!(
                current.status,
                ramflux_protocol::DeviceSetStatus::Revoked,
                "test: new primary failed to revoke the old secondary"
            );
        } else {
            assert_eq!(current, old, "test: revoking A changed the new primary's branch");
        }
    }
    custody::accept_publication(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        &observed,
        rig.now,
    )?;
    refuse_stale(&rig, &before, &observed)?;
    assert!(
        !ordinary_session_admitted(&rig.source.client, &rig.participant_a.account_id)?,
        "test: cached frontend retained admission after own revocation observation"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    // Drop the actual ordinary data worker and every frontend identity cache.
    rig.source.client = crate::RamfluxClient::new();
    let mut reopened = crate::RamfluxClient::new();
    reopened.open_account_index(&rig.participant_a.root)?;
    reopened.unlock_account(&rig.participant_a.account_id, b"component-source-passphrase")?;
    assert!(
        !ordinary_session_admitted(&reopened, &rig.participant_a.account_id)?,
        "test: original data password revived revoked networking after restart"
    );
    assert!(
        reopened
            .initialize_born_v3_branch(&source_id, rig.participant_a.vault.clone())
            .await
            .is_err(),
        "test: restarted revoked device reacquired an ordinary branch session"
    );
    refuse_stale(&rig, &before, &observed)?;
    assert!(
        !ordinary_session_admitted(&reopened, &rig.participant_a.account_id)?,
        "test: stale node head revived restarted revocation"
    );
    Ok(())
}
fn refuse_stale(rig: &Rig, stale: &CustodyAuthority, current: &CustodyAuthority) -> TestResult {
    let outcome = custody::accept_publication(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        stale,
        rig.now,
    );
    assert!(
        outcome.is_err() || matches!(outcome, Ok(ramflux_crypto::custody::PinOutcome::Fenced(_))),
        "test: rollback node authority was accepted after revocation"
    );
    let durable = custody::load_data_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        rig.now,
    )?;
    assert_eq!(
        object_hash(durable.record())?,
        object_hash(&current.publication.record)?,
        "test: stale native response overwrote the durable revoked roster"
    );
    Ok(())
}
fn revoke_source(rig: &Rig, source_id: &str) -> Result<String, crate::SdkError> {
    let account =
        custody::load_account(&rig.participant_b.root, &rig.participant_b.account_id, rig.now)?;
    let reference = account.record().body.master_certificate.body.primary_device_ref.clone();
    let write = HeadWrite {
        account_id: rig.participant_b.account_id.clone(),
        operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::Revoke,
        publisher_ref: reference.clone(),
        local_ref: reference,
        recipient_ref: None,
        revoked_id: Some(source_id.into()),
        certificate: None,
        display_name: None,
        now: rig.now,
        branch_vault_ref: account.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(
            &rig.participant_b.account_id,
        ),
        primary_vault_ref: Some(account.primary_vault_ref().into()),
    };
    let db = rig
        .participant_b
        .db
        .lock()
        .map_err(|_| crate::SdkError::PairingCode("Busy"))?
        .take()
        .ok_or(crate::SdkError::AccountDbNotUnlocked)?;
    let db = std::sync::Mutex::new(db);
    let result = publish_head(
        &db,
        &rig.participant_b.root,
        rig.participant_b.vault.as_ref(),
        &write,
        rig.node.as_ref(),
    );
    *rig.participant_b.db.lock().map_err(|_| crate::SdkError::PairingCode("Busy"))? =
        Some(db.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner));
    Ok(result?.record_hash)
}
