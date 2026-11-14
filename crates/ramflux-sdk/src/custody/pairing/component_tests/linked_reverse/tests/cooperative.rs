// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! After attended transfer, A is still a live branch and B alone can publish management heads.
use super::*;
use crate::custody::pairing::{HeadKind, HeadWrite, PublishedHead, publish_head};
use std::sync::Mutex;
#[tokio::test(start_paused = true)]
async fn cooperative_transfer_demotes_primary_without_device_revocation() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let fixture = Box::pin(open_devices(true)).await?;
    let fixture = Box::pin(run_data_in(fixture, false)).await?;
    let mut fixture = Box::pin(install_in(fixture, 0)).await?;
    Box::pin(races::merge(&mut fixture)).await?;
    let original = fixture.rig.source.client.account_db()?.path.clone();
    let b = crate::custody::load_account(
        &fixture.rig.participant_b.root,
        &fixture.rig.participant_b.account_id,
        crate::custody::network_now()?,
    )?;
    let before = b.record().body.devices.clone();
    assert_eq!(before.len(), 3, "test: cooperative transfer removed an enrolled branch");
    assert!(
        before.iter().all(|device| device.status == ramflux_protocol::DeviceSetStatus::Active),
        "test: cooperative transfer silently revoked another branch"
    );
    let a = publish_profile(
        &fixture.rig.participant_a,
        &mut fixture.rig.source.client,
        fixture.rig.node.as_ref(),
    );
    assert!(
        matches!(a, Err(SdkError::PairingCode("PrimaryRequired"))),
        "test: former A primary could still publish a management head"
    );
    assert!(
        fixture.rig.source.client.account_db()?.pairing_head()?.is_none(),
        "test: refused former-primary write left an authority intent"
    );
    let published = publish_profile(
        &fixture.rig.participant_b,
        &mut fixture.target,
        fixture.rig.node.as_ref(),
    )?;
    assert_eq!(
        published.record.body.devices, before,
        "test: new primary profile publication changed surviving branch policy"
    );
    let current = fixture.rig.node.current_authority(&published.record.body.account_anchor)?;
    refresh_authority(
        &fixture.rig.participant_a.root,
        fixture.rig.source.client.account_db()?,
        fixture.rig.participant_a.vault.as_ref(),
        &fixture.rig.participant_a.account_id,
        &current,
        crate::custody::network_now()?,
    )?;
    assert_eq!(
        fixture.rig.source.client.account_db()?.path,
        original,
        "test: later B management replaced A's ordinary data generation"
    );
    third::verify(
        &fixture.rig,
        &fixture.target,
        fixture.third.as_mut().ok_or("test: C owner missing")?,
    )
    .await?;
    assert!(
        fixture.target.account_db()?.next_pairing_own_sync()?.is_none(),
        "test: full handoff scheduled an enrollment-only history export"
    );
    fixture.rig.primary.lock().await?;
    fixture.rig.secondary.lock().await?;
    Ok(())
}
fn publish_profile(
    participant: &LocalPairingParticipant,
    client: &mut crate::RamfluxClient,
    node: &Node,
) -> Result<PublishedHead, SdkError> {
    let now = crate::custody::network_now()?;
    let account = crate::custody::load_account(&participant.root, &participant.account_id, now)?;
    let id = account.local_device_id()?;
    let device = account
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == id)
        .ok_or(SdkError::PairingCode("WrongContext"))?;
    let reference = DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: id.into(),
        device_epoch: device.device_epoch,
    };
    let request = HeadWrite {
        account_id: participant.account_id.clone(),
        operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
        invitation_id: None,
        generation: 1,
        issuer_seq: 0,
        local_seq: 0,
        kind: HeadKind::Profile,
        publisher_ref: reference.clone(),
        local_ref: reference,
        recipient_ref: None,
        revoked_id: None,
        certificate: None,
        display_name: Some("Phone after attended handoff".into()),
        now,
        branch_vault_ref: account.branch_vault_ref().into(),
        data_vault_ref: ramflux_storage::FileVaultSecretSource::owner_ref(&participant.account_id),
        primary_vault_ref: (!account.primary_vault_ref().is_empty())
            .then(|| account.primary_vault_ref().into()),
    };
    let db = Mutex::new(client.active_account_db.take().ok_or(SdkError::AccountDbNotUnlocked)?);
    let result = publish_head(&db, &participant.root, participant.vault.as_ref(), &request, node);
    client.active_account_db = Some(db.into_inner().map_err(|_| SdkError::PairingCode("Busy"))?);
    result
}
