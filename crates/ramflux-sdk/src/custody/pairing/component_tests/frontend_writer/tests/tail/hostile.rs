// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual native tail admission forwards opaque bytes; endpoint AEAD gates data application.
use super::*;

/// Real wall-clock bound for a scenario that runs on paused tokio time. Tokio timers are
/// virtual here, so a watchdog thread measures real time with `std` and cancels the scenario
/// through a oneshot. The scenario future is dropped, which drops its fixtures and their
/// temporary directories, before the test returns and long before the runner's kill window.
async fn wall_bounded<T>(
    seconds: u64,
    scenario: impl std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let (expired, expiry) = tokio::sync::oneshot::channel::<()>();
    let (finished, watch) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if matches!(
            watch.recv_timeout(std::time::Duration::from_secs(seconds)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = expired.send(());
        }
    });
    let outcome = tokio::select! {
        result = scenario => Some(result),
        _ = expiry => None,
    };
    drop(finished);
    watchdog.join().map_err(|_| "wall-clock watchdog panicked")?;
    outcome.ok_or_else(|| format!("scenario exceeded its {seconds} s wall-clock deadline"))?
}
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_relay_admission_is_data_only_endpoints_enforce() -> TestResult {
    let hold = ClockHold::new();
    let result =
        wall_bounded(150, crate::bus::credentials::contract_tests::deadline(Box::pin(run()))).await;
    hold.finish().await?;
    result?;
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_signed_parent_is_refused() -> TestResult {
    let hold = ClockHold::new();
    let result = wall_bounded(
        50,
        crate::bus::credentials::contract_tests::deadline(Box::pin(super::hostile_context::run(
            super::hostile_context::Fault::Parent,
        ))),
    )
    .await;
    hold.finish().await?;
    result
}
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_signed_transfer_is_refused() -> TestResult {
    let hold = ClockHold::new();
    let result = wall_bounded(
        50,
        crate::bus::credentials::contract_tests::deadline(Box::pin(super::hostile_context::run(
            super::hostile_context::Fault::Transfer,
        ))),
    )
    .await;
    hold.finish().await?;
    result
}
#[tokio::test(start_paused = true)]
async fn pairing_full_tail_signed_delta_after_j6_is_refused() -> TestResult {
    let hold = ClockHold::new();
    let result = wall_bounded(
        50,
        crate::bus::credentials::contract_tests::deadline(Box::pin(super::hostile_context::run(
            super::hostile_context::Fault::DeltaAfterJ6,
        ))),
    )
    .await;
    hold.finish().await?;
    result
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
    eprintln!("test: hostile tail rejected; cold reopening source");
    source =
        reopen(&mut rig.primary, &rig.participant_a, &mut rig.source.client, b"fresh-source-data")
            .await?;
    eprintln!("test: hostile tail source reopened; cold reopening target");
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
    eprintln!("test: hostile tail cold owners opened; restoring fresh epochs");
    drive(Box::pin(rig.primary.transfer_status(&request)), &mut source, &rig.source.client).await?;
    drive(Box::pin(rig.secondary.transfer_status(&request)), &mut target, &client).await?;
    eprintln!("test: hostile tail epochs started; merging cold data");
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
#[tokio::test(start_paused = true)]
async fn the_wall_clock_bound_cancels_a_scenario_that_never_finishes_on_paused_time() {
    let started = std::time::Instant::now();
    let outcome = wall_bounded::<()>(1, std::future::pending()).await;
    assert!(
        outcome.is_err_and(|error| error.to_string().contains("wall-clock deadline")),
        "a stuck scenario is cancelled with the deadline error"
    );
    assert!(started.elapsed() >= std::time::Duration::from_secs(1), "real time elapsed");
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "cancelled promptly");
}
