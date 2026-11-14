// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual native tail admission forwards opaque bytes; endpoint AEAD gates data application.
use super::*;
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_relay_admission_is_data_only_endpoints_enforce() -> TestResult {
    let hold = ClockHold::new();
    crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await?;
    for fault in [
        super::hostile_context::Fault::Parent,
        super::hostile_context::Fault::Transfer,
        super::hostile_context::Fault::DeltaAfterJ6,
    ] {
        crate::bus::credentials::contract_tests::deadline(Box::pin(super::hostile_context::run(
            fault,
        )))
        .await?;
    }
    hold.finish().await?;
    Ok(())
}
async fn run() -> TestResult {
    let (mut rig, mut source, mut client, mut target, request) = Box::pin(setup()).await?;
    client.account_db()?.check_object_identity("driver-tail", "driver-manifest")?;
    rig.wire_evidence.corrupt_next_packet();
    let mut refused = false;
    for _ in 0..64 {
        rig.clock.advance_ms(1001);
        let a = drive(Box::pin(rig.primary.sync_relay()), &mut source, &rig.source.client).await;
        rig.clock.advance_ms(1001);
        let b = drive(Box::pin(rig.secondary.sync_relay()), &mut target, &client).await;
        a?;
        b?;
        let a = rig.primary.transfer_status(&request).await?;
        let b = rig.secondary.transfer_status(&request).await?;
        let rejected = |reply: LocalResult| matches!(reply.outcome, Outcome::FullStatus { value } if value.tail_status == FullTailStatus::Pending && value.result.is_some());
        if (rejected(a) || rejected(b)) && rig.wire_evidence.admitted_corruption() == 1 {
            refused = true;
            break;
        }
    }
    assert!(refused, "test: admitted corrupted ciphertext did not fail endpoint authentication");
    client.account_db()?.check_object_identity("driver-tail", "driver-manifest")?;
    let result = rig.secondary.transfer_status(&request).await?;
    assert!(!is_merged(&result), "test: relay acceptance became a semantic tail completion");
    assert!(
        crate::custody::pairing::ordinary_session_admitted(&client, &rig.participant_b.account_id)?,
        "test: data-channel corruption revoked installed ordinary B authority"
    );
    source =
        reopen(&mut rig.primary, &rig.participant_a, &mut rig.source.client, b"fresh-source-data")
            .await?;
    target = reopen(
        &mut rig.secondary,
        &rig.participant_b,
        &mut client,
        b"component-recipient-passphrase",
    )
    .await?;
    // Cold owners have discarded the old bearer tokens. The native relay keeps
    // that epoch until its specified ten-second idle expiry.
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    drive(Box::pin(rig.primary.transfer_status(&request)), &mut source, &rig.source.client).await?;
    drive(Box::pin(rig.secondary.transfer_status(&request)), &mut target, &client).await?;
    Box::pin(merge(&mut rig, &mut source, &client, &mut target, &request)).await?;
    assert!(
        matches!(
            client.account_db()?.check_object_identity("driver-tail", "driver-manifest"),
            Err(ramflux_storage::StorageError::ObjectErased)
        ),
        "test: fresh native endpoint recovery never applied the positive tail"
    );
    rig.primary.lock().await?;
    rig.secondary.lock().await?;
    Ok(())
}
async fn reopen(
    actor: &mut PairingActor,
    participant: &Arc<LocalPairingParticipant>,
    client: &mut crate::RamfluxClient,
    password: &[u8],
) -> Result<PairingLocalWriterService, Box<dyn std::error::Error>> {
    let mut relay = None;
    actor.wrap_transport_for_test(|inner| {
        relay = Some(inner.clone());
        inner
    });
    actor.lock().await?;
    *client = crate::RamfluxClient::new();
    client.open_account_index(&participant.root)?;
    client.unlock_account(&participant.account_id, password)?;
    let now = crate::custody::network_now()?;
    let account = crate::custody::load_account(&participant.root, &participant.account_id, now)?;
    let id = account.local_device_id()?;
    let device = account
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == id)
        .ok_or("test: cold tail branch missing")?;
    let reference = ramflux_protocol::custody::DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id: id.into(),
        device_epoch: device.device_epoch,
    };
    let mut fresh = PairingActor::new(
        PairingIdentity {
            account_id: participant.account_id.clone(),
            local_ref: reference.clone(),
            master_public_key: Some(
                account.record().body.master_certificate.body.master_public_key.clone(),
            ),
            base_record_hash: ramflux_protocol::custody::object_hash(account.record())?,
            base_epoch: account.record().body.device_set_epoch,
            is_primary: account.record().body.master_certificate.body.primary_device_ref
                == reference,
        },
        None,
        relay.ok_or("test: cold tail relay missing")?,
        PairingConfig { enabled: true, extra_root_ca_pem: None },
    );
    fresh.set_participant(participant.clone());
    fresh.set_full_node(
        crate::custody::network_tests::node(now, ramflux_protocol::encode_base64url([29; 32]))
            .map_err(|error| error.to_string())?,
    );
    let service = fresh.bind_frontend_writer(client.account_db()?)?;
    *actor = fresh;
    Ok(service)
}
