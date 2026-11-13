// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A third independent enrolled branch stays live across B's full generation installation.
use super::*;
use crate::custody::pairing::component_tests::branch_traffic;
use std::sync::{Arc, Mutex};
pub(super) struct Third {
    client: crate::RamfluxClient,
    participant: Arc<LocalPairingParticipant>,
    reference: DeviceRef,
    branch_key: String,
    root: tempfile::TempDir,
}
pub(super) async fn enroll(rig: &mut Rig) -> Result<Third, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let participant = Arc::new(LocalPairingParticipant {
        root: root.path().into(),
        account_id: "component-third".into(),
        vault: Arc::new(crate::custody::pairing::recipient::tests::DiskVault::open(
            root.path().join("third-vault"),
        )?),
        provider: crate::custody::pairing::component_tests::generation::phrase_provider(
            rig.source.phrase.as_deref().map(String::as_str),
        ),
        db: Mutex::new(None),
        persist: rig.node.clone(),
        query: rig.node.clone(),
    });
    let mut relay = None;
    rig.secondary.wrap_transport_for_test(|inner| {
        relay = Some(inner.clone());
        inner
    });
    let mut actor = PairingActor::new(
        PairingIdentity {
            account_id: participant.account_id.clone(),
            local_ref: DeviceRef {
                account_anchor: String::new(),
                device_id: "unreserved-third".into(),
                device_epoch: 1,
            },
            master_public_key: None,
            base_record_hash: ramflux_protocol::encode_base64url([0; 32]),
            base_epoch: 1,
            is_primary: false,
        },
        None,
        relay.ok_or("test: third relay owner missing")?,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    actor.set_participant(participant.clone());
    std::mem::swap(&mut rig.secondary, &mut actor);
    let result = Box::pin(super::enroll(rig)).await;
    std::mem::swap(&mut rig.secondary, &mut actor);
    result?;
    actor.lock().await?;
    let mut client = crate::RamfluxClient::new();
    participant.return_client(&mut client)?;
    let native = crate::custody::load_account(root.path(), &participant.account_id, rig.now)?;
    let id = native.local_device_id()?;
    let device = native
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == id)
        .ok_or("test: third branch absent")?;
    let reference = DeviceRef {
        account_anchor: native.record().body.account_anchor.clone(),
        device_id: id.into(),
        device_epoch: device.device_epoch,
    };
    let branch_key = device
        .branch_certificate
        .as_ref()
        .ok_or("test: third certificate absent")?
        .body
        .branch_signing_public_key
        .clone();
    client.initialize_born_v3_branch(id, participant.vault.clone()).await?;
    branch_traffic::participants(rig, &[participant.as_ref()])?;
    Ok(Third { client, participant, reference, branch_key, root })
}

pub(super) async fn verify(
    rig: &Rig,
    target: &crate::RamfluxClient,
    third: &mut Third,
) -> TestResult {
    let current = rig.node.current_authority(&third.reference.account_anchor)?;
    let devices = &current.publication.record.body.devices;
    assert_eq!(devices.len(), 3, "test: full transfer removed a different enrolled device");
    let device = devices
        .iter()
        .find(|device| device.device_id == third.reference.device_id)
        .ok_or("test: C removed by A-to-B handoff")?;
    assert_eq!(
        device.device_epoch, third.reference.device_epoch,
        "test: handoff replaced C's reference"
    );
    assert_eq!(device.status, ramflux_protocol::DeviceSetStatus::Active, "test: handoff revoked C");
    let certificate = device.branch_certificate.as_ref().ok_or("test: C certificate missing")?;
    assert_eq!(
        certificate.body.branch_signing_public_key, third.branch_key,
        "test: handoff replaced C's signing key"
    );
    let b = crate::custody::load_account(
        &rig.participant_b.root,
        &rig.participant_b.account_id,
        crate::custody::network_now()?,
    )?;
    assert_eq!(
        current.publication.record.body.master_certificate.body.primary_device_ref.device_id,
        b.local_device_id()?,
        "test: existing B did not become primary"
    );
    let own = b
        .record()
        .body
        .devices
        .iter()
        .find(|device| Some(device.device_id.as_str()) == b.local_device_id().ok())
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or("test: B branch certificate missing")?;
    assert_ne!(
        own.body.branch_signing_public_key, third.branch_key,
        "test: B reused C's signing key"
    );
    assert!(
        ordinary_session_admitted(target, &rig.participant_b.account_id)?,
        "test: concurrent B writer was not admitted"
    );
    // C was disconnected during the full copy. Refresh its own durable floor before reconnect.
    refresh_authority(
        third.root.path(),
        third.client.account_db()?,
        third.participant.vault.as_ref(),
        &third.participant.account_id,
        &current,
        crate::custody::network_now()?,
    )?;
    third
        .client
        .initialize_born_v3_branch(&third.reference.device_id, third.participant.vault.clone())
        .await?;
    assert!(
        ordinary_session_admitted(&third.client, &third.participant.account_id)?,
        "test: C lost ordinary session admission after reconnect"
    );
    branch_traffic::participants(
        rig,
        &[rig.participant_a.as_ref(), rig.participant_b.as_ref(), third.participant.as_ref()],
    )?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pairing_receiver_concurrency_and_transfer_acceptance() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let fixture = Box::pin(super::open_devices(true)).await?;
        let fixture = Box::pin(super::run_data_in(fixture, false)).await?;
        Box::pin(super::finish_install(fixture, 3)).await
    }))
    .await;
    hold.finish().await?;
    result
}
