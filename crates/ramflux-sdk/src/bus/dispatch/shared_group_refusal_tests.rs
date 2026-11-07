// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `sender_refusal_policy_group_sync`: typed gateway refusals on the two durable group-sync
//! sites (S1 state delivery, S2 control courier), through the real writer, courier and a real
//! account DB reopen. Every expectation is an exact literal.
use super::*;
use crate::bus::runtime_tests;
use std::sync::{Arc, Mutex, atomic::AtomicBool};
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Sent = Arc<Mutex<Vec<ramflux_protocol::Envelope>>>;

/// The four outcomes of the policy table: a certain Conflict, the two deferrals, and a
/// failure the gateway did not classify (uncertain).
#[derive(Clone, Copy)]
enum Case {
    Conflict,
    Capacity,
    RetrySafe,
    Uncertain,
}

impl Case {
    const ALL: [Self; 4] = [Self::Conflict, Self::Capacity, Self::RetrySafe, Self::Uncertain];

    /// The exact nack reason the scripted gateway sends.
    const fn nack(self) -> &'static str {
        match self {
            Self::Conflict => "idempotency_conflict",
            Self::Capacity => "capacity_retry_after",
            Self::RetrySafe => "aborted_retry_safe",
            Self::Uncertain => "injected target failure",
        }
    }
}

fn recording(nack: Option<&str>) -> (super::fixture::RecordingGateway, Sent) {
    let mut gateway = super::fixture::RecordingGateway::new(Arc::default());
    gateway.nack_reason = nack.map(str::to_owned);
    let attempted = gateway.attempted.clone();
    (gateway, attempted)
}

/// A real reopen: the account DB handle is dropped and unlocked again from disk.
fn reopen(account: &mut LocalBusAccountState, local_account_id: &str) -> TestResult {
    account.client.active_account_db = None;
    account.client.unlock_account(local_account_id, b"actor-test-secret")?;
    Ok(())
}

fn failures(client: &RamfluxClient, reason: &str) -> Result<usize, SdkError> {
    Ok(client
        .account_db()?
        .journal_after(0, 128)?
        .into_iter()
        .filter(|event| {
            event.topic == "group.state.delivery_failed" && event.body["reason"] == reason
        })
        .count())
}

fn intents(client: &RamfluxClient) -> Result<Vec<Value>, SdkError> {
    Ok(client.account_db()?.list_actor_states::<Value>("group-state/send/")?)
}

/// S1: one recipient device, one scripted nack.
async fn state_delivery(case: Case) -> TestResult {
    let root = runtime_tests::root("group-sync-refusal-s1");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { peers, config, directory, .. } =
        super::dm_tests::peer_fixture_devices(&root, &mut source, &["device-peer-0"]).await?;
    source.gateway_config = config.clone();
    source.target_delivery_id = config.target_delivery_id.clone();
    source.client.shared_group_create("group", "group-thread", None, "sender")?;
    source.client.shared_group_change(
        "group",
        "sender",
        ramflux_protocol::group_state::GroupStateChange::Add {
            member: peers[0].client.owned_group_actor("device-peer-0")?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
    )?;
    let (gateway, attempted) = recording(Some(case.nack()));
    source.install_test_session(GatewaySessionEngine::with_test_transport(
        config.clone(),
        Box::new(gateway),
    ));
    let before = now_unix_timestamp();
    assert!(
        crate::bus::couriers::test_pass::drive(
            &mut source,
            crate::bus::shared_group_sync::deliver_pass
        )
        .await?
    );
    let after = now_unix_timestamp();
    assert_eq!(attempted.lock().map_err(|_| "attempted")?.len(), 1, "one submit was written");

    match case {
        Case::Conflict => {
            // (a) the intent took its terminal branch in the same step: removed, journalled
            // with the exact reason, and no per-device failure was recorded.
            assert_eq!(intents(&source.client)?.len(), 0);
            assert_eq!(failures(&source.client, "submit_conflict")?, 1);
            assert_eq!(failures(&source.client, "submit_failed")?, 0);
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            // (b)-(d) the existing deferral: the intent stays, one round failed, the next
            // attempt is 2 s out (attempt 1 backoff, above the 1000 ms floor), the floor is
            // consumed, and one per-device failure is journalled.
            let kept = intents(&source.client)?;
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0]["attempt"], 1);
            assert_eq!(kept[0]["round_active"], false);
            assert_eq!(kept[0]["min_defer_secs"], 0);
            let next = kept[0]["next_at"].as_i64().ok_or("next_at")?;
            assert!(
                (before + 2..=after + 2).contains(&next),
                "next_at {next} outside [{}, {}]",
                before + 2,
                after + 2
            );
            assert_eq!(failures(&source.client, "submit_failed")?, 1);
            assert_eq!(failures(&source.client, "submit_conflict")?, 0);
        }
    }

    // Reopen from disk, then run again against a gateway that would accept everything: no
    // submit is written (the terminal intent is gone, the deferral has not elapsed).
    reopen(&mut source, "sender")?;
    let (gateway, resent) = recording(None);
    source
        .install_test_session(GatewaySessionEngine::with_test_transport(config, Box::new(gateway)));
    assert!(
        !crate::bus::couriers::test_pass::drive(
            &mut source,
            crate::bus::shared_group_sync::deliver_pass
        )
        .await?
    );
    assert_eq!(resent.lock().map_err(|_| "resent")?.len(), 0, "no resend after reopen");
    assert_eq!(intents(&source.client)?.len(), usize::from(!matches!(case, Case::Conflict)));
    directory.abort();
    drop((source, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

/// S2: an admin's signed request to the group owner, one scripted nack.
async fn control_courier(case: Case) -> TestResult {
    let root = runtime_tests::root("group-sync-refusal-s2");
    let mut owner = runtime_tests::account(
        &root.join("owner"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { mut peers, config, directory, .. } =
        super::dm_tests::peer_fixture(&root, &mut owner).await?;
    let mut admin = peers.remove(0);
    owner.gateway_config = config.clone();
    owner.target_delivery_id = config.target_delivery_id.clone();
    let mut admin_config = config.clone();
    admin_config.principal_id = "peer".into();
    admin_config.device_id = "device-peer-one".into();
    admin_config.target_delivery_id = "device-peer-one".into();
    admin_config = admin_config.with_account_identity(&admin.client)?;
    admin.gateway_config = admin_config.clone();
    admin.target_delivery_id = admin_config.target_delivery_id.clone();
    owner.client.shared_group_create("group", "group-thread", None, "sender")?;
    let base = owner.client.shared_group_change(
        "group",
        "sender",
        ramflux_protocol::GroupStateChange::Add {
            member: admin.client.owned_group_actor("device-peer-one")?.identity,
            role: ramflux_protocol::SharedGroupRole::Admin,
        },
    )?;
    admin.client.accept_shared_group_state(&base, "device-peer-one")?;
    let request = admin.client.stage_group_change_request(
        "group",
        "device-peer-one",
        ramflux_protocol::GroupStateChange::SetName { name: "Requested name".into() },
        Some("refusal-request"),
    )?;
    let (gateway, attempted) = recording(Some(case.nack()));
    admin.install_test_session(GatewaySessionEngine::with_test_transport(
        admin_config.clone(),
        Box::new(gateway),
    ));
    let before = now_unix_timestamp();
    let first = crate::bus::couriers::test_pass::drive(
        &mut admin,
        crate::bus::shared_group_sync::request_pass,
    )
    .await;
    let after = now_unix_timestamp();
    let sent = attempted.lock().map_err(|_| "attempted")?.clone();
    assert_eq!(sent.len(), 1, "one submit was written");
    let conflicted = sent[0].envelope_id.clone();
    let sealed = || -> Result<usize, SdkError> {
        Ok(admin.client.account_db()?.list_actor_states::<Value>("group-courier/sealed/")?.len())
    };
    let record = admin.client.group_change_record(&request, false)?.ok_or("record")?;
    assert!(record.delivered.is_empty(), "mark_sent is never called on a refusal");
    assert!(
        (before + 30..=after + 30).contains(&record.next_at),
        "next_at {} outside [{}, {}]",
        record.next_at,
        before + 30,
        after + 30
    );
    match case {
        Case::Conflict => {
            // (a) the staged attempt took the expiry branch: no sealed record, no error.
            assert!(first?);
            assert_eq!(sealed()?, 0);
        }
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            // (b)-(d) the existing deferral: the attempt stays staged and the error is the
            // gateway's exact reason.
            assert!(
                matches!(&first, Err(SdkError::GatewaySessionRejected(reason)) if reason == case.nack()),
                "{first:?}"
            );
            assert_eq!(sealed()?, 1);
        }
    }

    // Reopen from disk; the deferral is persisted, so nothing is written until it elapses.
    reopen(&mut admin, "peer")?;
    let (gateway, resent) = recording(None);
    admin.install_test_session(GatewaySessionEngine::with_test_transport(
        admin_config.clone(),
        Box::new(gateway),
    ));
    assert!(
        !crate::bus::couriers::test_pass::drive(
            &mut admin,
            crate::bus::shared_group_sync::request_pass
        )
        .await?
    );
    assert_eq!(resent.lock().map_err(|_| "resent")?.len(), 0, "deferral survives reopen");

    // Once it elapses: a Conflict never resends the conflicted envelope id (a fresh envelope
    // is sealed), the deferrals resend the byte-identical staged envelope.
    let mut due = admin.client.group_change_record(&request, false)?.ok_or("record")?;
    due.next_at = 0;
    admin.client.persist_group_request(&due)?;
    let (gateway, retried) = recording(None);
    admin.install_test_session(GatewaySessionEngine::with_test_transport(
        admin_config,
        Box::new(gateway),
    ));
    assert!(
        crate::bus::couriers::test_pass::drive(
            &mut admin,
            crate::bus::shared_group_sync::request_pass
        )
        .await?
    );
    let again = retried.lock().map_err(|_| "retried")?.clone();
    assert_eq!(again.len(), 1);
    match case {
        Case::Conflict => assert_ne!(again[0].envelope_id, conflicted),
        Case::Capacity | Case::RetrySafe | Case::Uncertain => {
            assert_eq!(again[0], sent[0], "the staged envelope is resubmitted byte for byte");
        }
    }
    assert_eq!(
        admin.client.group_change_record(&request, false)?.ok_or("record")?.delivered.len(),
        1
    );
    directory.abort();
    drop((owner, admin, peers));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn sender_refusal_policy_group_sync() -> TestResult {
    for case in Case::ALL {
        Box::pin(state_delivery(case)).await?;
    }
    for case in Case::ALL {
        Box::pin(control_courier(case)).await?;
    }
    Ok(())
}
